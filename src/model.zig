const std = @import("std");

pub const Protocol = enum {
    tcp,
    udp,

    pub fn text(self: Protocol) []const u8 {
        return switch (self) {
            .tcp => "tcp",
            .udp => "udp",
        };
    }
};

pub const AddressFamily = enum {
    ipv4,
    ipv6,
};

pub const IpAddress = union(AddressFamily) {
    ipv4: [4]u8,
    ipv6: [16]u8,

    pub fn family(self: IpAddress) AddressFamily {
        return switch (self) {
            .ipv4 => .ipv4,
            .ipv6 => .ipv6,
        };
    }
};

pub const BackendKind = enum {
    macos_libproc,
    linux_procfs,
    test_backend,

    pub fn text(self: BackendKind) []const u8 {
        return switch (self) {
            .macos_libproc => "macos_libproc",
            .linux_procfs => "linux_procfs",
            .test_backend => "test",
        };
    }
};

pub const BackendMeta = struct {
    backend: BackendKind,
    fd: ?i32 = null,
    inode: ?u64 = null,
    raw_state: ?u8 = null,
};

pub const PortEntry = struct {
    protocol: Protocol,
    local_address: IpAddress,
    local_port: u16,
    pid: ?u32,
    process_name: ?[]const u8,
    source: BackendMeta,
};

pub const ScanDiagnostics = struct {
    permission_denied_processes: usize = 0,
    permission_denied_fds: usize = 0,
    malformed_socket_rows: usize = 0,

    pub fn noteProcessPermissionDenied(self: *ScanDiagnostics) void {
        self.permission_denied_processes += 1;
    }

    pub fn noteFdPermissionDenied(self: *ScanDiagnostics) void {
        self.permission_denied_fds += 1;
    }

    pub fn noteMalformedSocketRows(self: *ScanDiagnostics, count: usize) void {
        self.malformed_socket_rows += count;
    }

    pub fn hasPermissionGaps(self: ScanDiagnostics) bool {
        return self.permission_denied_processes != 0 or self.permission_denied_fds != 0;
    }
};

pub const ScanResult = struct {
    allocator: std.mem.Allocator,
    entries: []PortEntry,
    diagnostics: ScanDiagnostics = .{},

    pub fn deinit(self: *ScanResult) void {
        for (self.entries) |entry| {
            if (entry.process_name) |name| self.allocator.free(name);
        }
        self.allocator.free(self.entries);
        self.* = undefined;
    }
};

pub const ScanFilter = struct {
    port: ?u16 = null,
    protocol: ?Protocol = null,

    pub fn matches(self: ScanFilter, entry: PortEntry) bool {
        return self.matchesLocal(entry.protocol, entry.local_port);
    }

    pub fn matchesLocal(self: ScanFilter, protocol: Protocol, port: u16) bool {
        if (self.port) |wanted_port| {
            if (port != wanted_port) return false;
        }
        if (self.protocol) |wanted_protocol| {
            if (protocol != wanted_protocol) return false;
        }
        return true;
    }
};

pub fn sortEntries(entries: []PortEntry) void {
    std.mem.sort(PortEntry, entries, {}, lessThan);
}

fn lessThan(_: void, a: PortEntry, b: PortEntry) bool {
    if (a.local_port != b.local_port) return a.local_port < b.local_port;
    if (a.protocol != b.protocol) return @intFromEnum(a.protocol) < @intFromEnum(b.protocol);
    if (a.local_address.family() != b.local_address.family()) {
        return @intFromEnum(a.local_address.family()) < @intFromEnum(b.local_address.family());
    }
    switch (a.local_address) {
        .ipv4 => |aa| {
            const bb = b.local_address.ipv4;
            const order = std.mem.order(u8, &aa, &bb);
            if (order != .eq) return order == .lt;
        },
        .ipv6 => |aa| {
            const bb = b.local_address.ipv6;
            const order = std.mem.order(u8, &aa, &bb);
            if (order != .eq) return order == .lt;
        },
    }
    if (a.pid != b.pid) return (a.pid orelse 0) < (b.pid orelse 0);
    return std.mem.order(u8, a.process_name orelse "", b.process_name orelse "") == .lt;
}

test "scan filter matches port and protocol" {
    const entry: PortEntry = .{
        .protocol = .tcp,
        .local_address = .{ .ipv4 = .{ 127, 0, 0, 1 } },
        .local_port = 3000,
        .pid = 10,
        .process_name = "node",
        .source = .{ .backend = .test_backend },
    };

    try std.testing.expect((ScanFilter{ .port = 3000 }).matches(entry));
    try std.testing.expect(!(ScanFilter{ .port = 4000 }).matches(entry));
    try std.testing.expect((ScanFilter{ .protocol = .tcp }).matches(entry));
    try std.testing.expect(!(ScanFilter{ .protocol = .udp }).matches(entry));
    try std.testing.expect((ScanFilter{ .port = 3000, .protocol = .tcp }).matchesLocal(.tcp, 3000));
    try std.testing.expect(!(ScanFilter{ .port = 3000, .protocol = .tcp }).matchesLocal(.udp, 3000));
}

test "entries sort deterministically" {
    var entries = [_]PortEntry{
        .{
            .protocol = .udp,
            .local_address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
            .local_port = 3000,
            .pid = 2,
            .process_name = "b",
            .source = .{ .backend = .test_backend },
        },
        .{
            .protocol = .tcp,
            .local_address = .{ .ipv4 = .{ 127, 0, 0, 1 } },
            .local_port = 80,
            .pid = 1,
            .process_name = "a",
            .source = .{ .backend = .test_backend },
        },
    };

    sortEntries(&entries);
    try std.testing.expectEqual(@as(u16, 80), entries[0].local_port);
    try std.testing.expectEqual(Protocol.tcp, entries[0].protocol);
}
