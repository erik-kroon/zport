const std = @import("std");
const model = @import("../model.zig");
const procnet = @import("linux_procnet.zig");

const Candidate = procnet.SocketCandidate;

pub fn scan(allocator: std.mem.Allocator, io: std.Io, filter: model.ScanFilter) !model.ScanResult {
    var candidates: std.ArrayList(Candidate) = .empty;
    defer candidates.deinit(allocator);
    var stats: model.ScanStats = .{};
    var parse_stats: procnet.ParseStats = .{};

    try readTable(allocator, io, &candidates, "/proc/net/tcp", .tcp, .ipv4, &parse_stats);
    try readTable(allocator, io, &candidates, "/proc/net/tcp6", .tcp, .ipv6, &parse_stats);
    try readTable(allocator, io, &candidates, "/proc/net/udp", .udp, .ipv4, &parse_stats);
    try readTable(allocator, io, &candidates, "/proc/net/udp6", .udp, .ipv6, &parse_stats);
    stats.parse_errors = parse_stats.parse_errors;

    var inode_to_index = std.AutoHashMap(u64, usize).init(allocator);
    defer inode_to_index.deinit();
    for (candidates.items, 0..) |candidate, i| {
        try inode_to_index.put(candidate.inode, i);
    }

    const matched = try allocator.alloc(bool, candidates.items.len);
    defer allocator.free(matched);
    @memset(matched, false);

    var entries: std.ArrayList(model.PortEntry) = .empty;
    errdefer {
        for (entries.items) |entry| {
            if (entry.process_name) |name| allocator.free(name);
        }
        entries.deinit(allocator);
    }

    var seen = std.AutoHashMap(u128, void).init(allocator);
    defer seen.deinit();

    scanProc(allocator, io, filter, &inode_to_index, candidates.items, matched, &entries, &seen, &stats) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };

    for (candidates.items, 0..) |candidate, i| {
        if (!matched[i] and filter.matches(entryFromCandidate(candidate, null, null))) {
            try entries.append(allocator, entryFromCandidate(candidate, null, null));
        }
    }

    const owned = try entries.toOwnedSlice(allocator);
    model.sortEntries(owned);
    return .{ .allocator = allocator, .entries = owned, .stats = stats };
}

fn readTable(
    allocator: std.mem.Allocator,
    io: std.Io,
    candidates: *std.ArrayList(Candidate),
    path: []const u8,
    protocol: model.Protocol,
    family: model.AddressFamily,
    stats: *procnet.ParseStats,
) !void {
    const content = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(16 * 1024 * 1024)) catch |err| switch (err) {
        error.FileNotFound => return,
        error.AccessDenied, error.PermissionDenied => return,
        else => return err,
    };
    defer allocator.free(content);
    try procnet.parseTable(allocator, candidates, content, protocol, family, stats);
}

fn scanProc(
    allocator: std.mem.Allocator,
    io: std.Io,
    filter: model.ScanFilter,
    inode_to_index: *std.AutoHashMap(u64, usize),
    candidates: []const Candidate,
    matched: []bool,
    entries: *std.ArrayList(model.PortEntry),
    seen: *std.AutoHashMap(u128, void),
    stats: *model.ScanStats,
) !void {
    var proc_dir = try std.Io.Dir.openDirAbsolute(io, "/proc", .{ .iterate = true });
    defer proc_dir.close(io);

    var it = proc_dir.iterate();
    while (try it.next(io)) |entry| {
        if (!isNumeric(entry.name)) continue;
        const pid = std.fmt.parseInt(u32, entry.name, 10) catch continue;
        try scanPid(allocator, io, entry.name, pid, filter, inode_to_index, candidates, matched, entries, seen, stats);
    }
}

fn scanPid(
    allocator: std.mem.Allocator,
    io: std.Io,
    pid_name: []const u8,
    pid: u32,
    filter: model.ScanFilter,
    inode_to_index: *std.AutoHashMap(u64, usize),
    candidates: []const Candidate,
    matched: []bool,
    entries: *std.ArrayList(model.PortEntry),
    seen: *std.AutoHashMap(u128, void),
    stats: *model.ScanStats,
) !void {
    const fd_path = try std.fmt.allocPrint(allocator, "/proc/{s}/fd", .{pid_name});
    defer allocator.free(fd_path);

    var fd_dir = std.Io.Dir.openDirAbsolute(io, fd_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return,
        error.AccessDenied, error.PermissionDenied => {
            stats.skipped_processes += 1;
            stats.permission_errors += 1;
            return;
        },
        else => return err,
    };
    defer fd_dir.close(io);

    var process_name: ?[]const u8 = null;
    defer if (process_name) |name| allocator.free(name);

    var it = fd_dir.iterate();
    while (try it.next(io)) |fd_entry| {
        var link_buf: [512]u8 = undefined;
        const link_len = fd_dir.readLink(io, fd_entry.name, &link_buf) catch |err| switch (err) {
            error.FileNotFound => continue,
            error.AccessDenied, error.PermissionDenied => {
                stats.skipped_fds += 1;
                continue;
            },
            else => continue,
        };
        const link = link_buf[0..link_len];
        const inode = parseSocketInode(link) orelse continue;
        const candidate_index = inode_to_index.get(inode) orelse continue;
        const candidate = candidates[candidate_index];
        const base_entry = entryFromCandidate(candidate, pid, null);
        if (!filter.matches(base_entry)) continue;

        const key = (@as(u128, inode) << 32) | @as(u128, pid);
        const put = try seen.getOrPut(key);
        if (put.found_existing) continue;

        if (process_name == null) process_name = try readProcessName(allocator, io, pid_name);
        matched[candidate_index] = true;
        try entries.append(allocator, entryFromCandidate(candidate, pid, if (process_name) |name| try allocator.dupe(u8, name) else null));
    }
}

fn readProcessName(allocator: std.mem.Allocator, io: std.Io, pid_name: []const u8) !?[]const u8 {
    const path = try std.fmt.allocPrint(allocator, "/proc/{s}/comm", .{pid_name});
    defer allocator.free(path);
    const raw = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(4096)) catch return null;
    defer allocator.free(raw);
    const trimmed = std.mem.trim(u8, raw, "\n\r");
    return try allocator.dupe(u8, trimmed);
}

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
