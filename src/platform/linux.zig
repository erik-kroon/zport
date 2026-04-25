const std = @import("std");
const model = @import("../model.zig");
const procnet = @import("linux_procnet.zig");

const Candidate = procnet.SocketCandidate;

pub fn scan(allocator: std.mem.Allocator, io: std.Io, filter: model.ScanFilter) !model.ScanResult {
    var state = ScanState.init(allocator, io, filter);
    defer state.deinit();

    try state.run();
    return state.toResult();
}

const ScanState = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    filter: model.ScanFilter,
    candidates: std.ArrayList(Candidate) = .empty,
    inode_to_index: std.AutoHashMap(u64, usize),
    matched: []bool = &.{},
    entries: std.ArrayList(model.PortEntry) = .empty,
    seen: std.AutoHashMap(u128, void),
    diagnostics: model.ScanDiagnostics = .{},
    parse_diagnostics: procnet.ParseDiagnostics = .{},
    entries_transferred: bool = false,

    const MatchedSocket = struct {
        candidate_index: usize,
        pid: u32,
    };

    fn init(allocator: std.mem.Allocator, io: std.Io, filter: model.ScanFilter) ScanState {
        return .{
            .allocator = allocator,
            .io = io,
            .filter = filter,
            .inode_to_index = std.AutoHashMap(u64, usize).init(allocator),
            .seen = std.AutoHashMap(u128, void).init(allocator),
        };
    }

    fn deinit(self: *ScanState) void {
        self.candidates.deinit(self.allocator);
        self.inode_to_index.deinit();
        if (self.matched.len != 0) self.allocator.free(self.matched);
        if (!self.entries_transferred) {
            for (self.entries.items) |entry| {
                if (entry.process_name) |name| self.allocator.free(name);
            }
            self.entries.deinit(self.allocator);
        }
        self.seen.deinit();
    }

    fn run(self: *ScanState) !void {
        try self.readTables();
        try self.indexCandidates();
        try self.allocateMatchedSet();
        self.scanProc() catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        try self.appendUnmatchedCandidates();
    }

    fn toResult(self: *ScanState) !model.ScanResult {
        const owned = try self.entries.toOwnedSlice(self.allocator);
        self.entries_transferred = true;
        return .{
            .allocator = self.allocator,
            .entries = owned,
            .diagnostics = self.diagnostics,
        };
    }

    fn readTables(self: *ScanState) !void {
        try self.readTable("/proc/net/tcp", .tcp, .ipv4);
        try self.readTable("/proc/net/tcp6", .tcp, .ipv6);
        try self.readTable("/proc/net/udp", .udp, .ipv4);
        try self.readTable("/proc/net/udp6", .udp, .ipv6);
        self.diagnostics.noteMalformedSocketRows(self.parse_diagnostics.malformed_rows);
    }

    fn readTable(
        self: *ScanState,
        path: []const u8,
        protocol: model.Protocol,
        family: model.AddressFamily,
    ) !void {
        const content = self.readProcFileAlloc(path, .limited(16 * 1024 * 1024)) catch |err| switch (err) {
            error.FileNotFound => return,
            error.AccessDenied, error.PermissionDenied => return,
            else => return err,
        };
        defer self.allocator.free(content);
        try procnet.parseTable(self.allocator, &self.candidates, content, protocol, family, &self.parse_diagnostics);
    }

    fn indexCandidates(self: *ScanState) !void {
        for (self.candidates.items, 0..) |candidate, i| {
            try self.inode_to_index.put(candidate.inode, i);
        }
    }

    fn allocateMatchedSet(self: *ScanState) !void {
        self.matched = try self.allocator.alloc(bool, self.candidates.items.len);
        @memset(self.matched, false);
    }

    fn scanProc(self: *ScanState) !void {
        var proc_dir = try std.Io.Dir.openDirAbsolute(self.io, "/proc", .{ .iterate = true });
        defer proc_dir.close(self.io);

        var it = proc_dir.iterate();
        while (try it.next(self.io)) |entry| {
            if (!isNumeric(entry.name)) continue;
            const pid = std.fmt.parseInt(u32, entry.name, 10) catch continue;
            try self.scanPid(entry.name, pid);
        }
    }

    fn scanPid(self: *ScanState, pid_name: []const u8, pid: u32) !void {
        const fd_path = try std.fmt.allocPrint(self.allocator, "/proc/{s}/fd", .{pid_name});
        defer self.allocator.free(fd_path);

        var fd_dir = std.Io.Dir.openDirAbsolute(self.io, fd_path, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => return,
            error.AccessDenied, error.PermissionDenied => {
                self.diagnostics.noteProcessPermissionDenied();
                return;
            },
            else => return err,
        };
        defer fd_dir.close(self.io);

        var process_name: ?[]const u8 = null;
        defer if (process_name) |name| self.allocator.free(name);

        var it = fd_dir.iterate();
        while (try it.next(self.io)) |fd_entry| {
            var link_buf: [512]u8 = undefined;
            const link_len = fd_dir.readLink(self.io, fd_entry.name, &link_buf) catch |err| switch (err) {
                error.FileNotFound => continue,
                error.AccessDenied, error.PermissionDenied => {
                    self.diagnostics.noteFdPermissionDenied();
                    continue;
                },
                else => continue,
            };
            const inode = parseSocketInode(link_buf[0..link_len]) orelse continue;
            const matched_socket = try self.matchInode(pid, inode) orelse continue;

            if (process_name == null) process_name = try self.readProcessName(pid_name);
            try self.appendMatchedSocket(matched_socket, process_name);
        }
    }

    fn matchInode(self: *ScanState, pid: u32, inode: u64) !?MatchedSocket {
        const candidate_index = self.inode_to_index.get(inode) orelse return null;
        const candidate = self.candidates.items[candidate_index];
        const base_entry = entryFromCandidate(candidate, pid, null);
        if (!self.filter.matches(base_entry)) return null;

        const key = socketProcessKey(inode, pid);
        const put = try self.seen.getOrPut(key);
        if (put.found_existing) return null;

        return .{ .candidate_index = candidate_index, .pid = pid };
    }

    fn appendMatchedSocket(self: *ScanState, matched_socket: MatchedSocket, process_name: ?[]const u8) !void {
        const candidate = self.candidates.items[matched_socket.candidate_index];
        const owned_process_name = if (process_name) |name| try self.allocator.dupe(u8, name) else null;
        errdefer if (owned_process_name) |name| self.allocator.free(name);

        self.matched[matched_socket.candidate_index] = true;
        try self.entries.append(self.allocator, entryFromCandidate(
            candidate,
            matched_socket.pid,
            owned_process_name,
        ));
    }

    fn appendUnmatchedCandidates(self: *ScanState) !void {
        for (self.candidates.items, 0..) |candidate, i| {
            if (!self.matched[i] and self.filter.matches(entryFromCandidate(candidate, null, null))) {
                try self.entries.append(self.allocator, entryFromCandidate(candidate, null, null));
            }
        }
    }

    fn readProcessName(self: *ScanState, pid_name: []const u8) !?[]const u8 {
        const path = try std.fmt.allocPrint(self.allocator, "/proc/{s}/comm", .{pid_name});
        defer self.allocator.free(path);
        const raw = self.readProcFileAlloc(path, .limited(4096)) catch return null;
        defer self.allocator.free(raw);
        const trimmed = std.mem.trim(u8, raw, "\n\r");
        return try self.allocator.dupe(u8, trimmed);
    }

    fn readProcFileAlloc(self: *ScanState, path: []const u8, limit: std.Io.Limit) ![]u8 {
        var file = try std.Io.Dir.openFileAbsolute(self.io, path, .{ .allow_directory = false });
        defer file.close(self.io);

        var buffer: [4096]u8 = undefined;
        var reader = file.readerStreaming(self.io, &buffer);
        return reader.interface.allocRemaining(self.allocator, limit) catch |err| switch (err) {
            error.ReadFailed => return reader.err.?,
            else => |e| return e,
        };
    }
};

fn entryFromCandidate(candidate: Candidate, pid: ?u32, process_name: ?[]const u8) model.PortEntry {
    return .{
        .protocol = candidate.protocol,
        .local_address = candidate.address,
        .local_port = candidate.port,
        .pid = pid,
        .process_name = process_name,
        .source = .{
            .backend = .linux_procfs,
            .inode = candidate.inode,
            .raw_state = candidate.raw_state,
        },
    };
}

fn parseSocketInode(link: []const u8) ?u64 {
    if (!std.mem.startsWith(u8, link, "socket:[") or !std.mem.endsWith(u8, link, "]")) return null;
    return std.fmt.parseInt(u64, link["socket:[".len .. link.len - 1], 10) catch null;
}

fn socketProcessKey(inode: u64, pid: u32) u128 {
    return (@as(u128, inode) << 32) | @as(u128, pid);
}

fn isNumeric(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        if (byte < '0' or byte > '9') return false;
    }
    return true;
}

test "parses socket inode symlink" {
    try std.testing.expectEqual(@as(?u64, 12345), parseSocketInode("socket:[12345]"));
    try std.testing.expectEqual(@as(?u64, null), parseSocketInode("anon_inode:[eventpoll]"));
}

test "scan state matches socket inode once per pid" {
    var state = ScanState.init(std.testing.allocator, std.testing.io, .{ .port = 3000, .protocol = .tcp });
    defer state.deinit();

    try state.candidates.append(std.testing.allocator, .{
        .protocol = .tcp,
        .address = .{ .ipv4 = .{ 127, 0, 0, 1 } },
        .port = 3000,
        .inode = 123456,
        .raw_state = 0x0a,
    });
    try state.indexCandidates();
    try state.allocateMatchedSet();

    const matched_socket = (try state.matchInode(42, 123456)).?;
    try state.appendMatchedSocket(matched_socket, "zport-test");

    try std.testing.expectEqual(@as(?ScanState.MatchedSocket, null), try state.matchInode(42, 123456));
    try std.testing.expect(state.matched[0]);
    try std.testing.expectEqual(@as(usize, 1), state.entries.items.len);
    try std.testing.expectEqual(@as(u32, 42), state.entries.items[0].pid.?);
    try std.testing.expectEqualSlices(u8, "zport-test", state.entries.items[0].process_name.?);
}
