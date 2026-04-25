const std = @import("std");
const builtin = @import("builtin");
const model = @import("model.zig");

pub const Snapshot = struct {
    entries: []const model.PortEntry,
    stats: model.ScanStats = .{},
};

pub const SnapshotSource = struct {
    snapshot: Snapshot,

    pub fn scanner(self: *const SnapshotSource) Scanner {
        return .{ .source = .{ .snapshot = self } };
    }
};

pub const ScriptedSource = struct {
    snapshots: []const Snapshot,
    index: usize = 0,

    pub fn scanner(self: *ScriptedSource) Scanner {
        return .{ .source = .{ .scripted = self } };
    }

    fn next(self: *ScriptedSource) Snapshot {
        if (self.snapshots.len == 0) return .{ .entries = &.{} };
        const selected = @min(self.index, self.snapshots.len - 1);
        if (self.index < self.snapshots.len) self.index += 1;
        return self.snapshots[selected];
    }
};

pub const Scanner = struct {
    source: Source,

    const Source = union(enum) {
        platform,
        snapshot: *const SnapshotSource,
        scripted: *ScriptedSource,
    };

    pub fn platform() Scanner {
        return .{ .source = .platform };
    }

    pub fn scan(self: Scanner, allocator: std.mem.Allocator, io: std.Io, filter: model.ScanFilter) !model.ScanResult {
        switch (self.source) {
            .platform => {
                var raw = try scanPlatform(allocator, io, filter);
                defer raw.deinit();
                return normalize(allocator, raw.entries, raw.stats, filter);
            },
            .snapshot => |source| return normalize(allocator, source.snapshot.entries, source.snapshot.stats, filter),
            .scripted => |source| {
                const snapshot = source.next();
                return normalize(allocator, snapshot.entries, snapshot.stats, filter);
            },
        }
    }
};

pub fn scan(allocator: std.mem.Allocator, io: std.Io, filter: model.ScanFilter) anyerror!model.ScanResult {
    return Scanner.platform().scan(allocator, io, filter);
}

fn scanPlatform(allocator: std.mem.Allocator, io: std.Io, filter_hint: model.ScanFilter) anyerror!model.ScanResult {
    return switch (builtin.os.tag) {
        .macos => @import("platform/macos.zig").scan(allocator, io, filter_hint),
        .linux => @import("platform/linux.zig").scan(allocator, io, filter_hint),
        else => error.UnsupportedPlatform,
    };
}

fn normalize(
    allocator: std.mem.Allocator,
    entries: []const model.PortEntry,
    stats: model.ScanStats,
    filter: model.ScanFilter,
) !model.ScanResult {
    var normalized: std.ArrayList(model.PortEntry) = .empty;
    errdefer {
        for (normalized.items) |entry| {
            if (entry.process_name) |name| allocator.free(name);
        }
        normalized.deinit(allocator);
    }

    for (entries) |entry| {
        if (!filter.matches(entry)) continue;
        const cloned = try cloneEntry(allocator, entry);
        errdefer if (cloned.process_name) |name| allocator.free(name);
        try normalized.append(allocator, cloned);
    }

    const owned = try normalized.toOwnedSlice(allocator);
    model.sortEntries(owned);
    return .{ .allocator = allocator, .entries = owned, .stats = stats };
}

fn cloneEntry(allocator: std.mem.Allocator, entry: model.PortEntry) !model.PortEntry {
    var cloned = entry;
    cloned.process_name = if (entry.process_name) |name| try allocator.dupe(u8, name) else null;
    return cloned;
}

test "scanner normalizes filtered sorted owned results" {
    const entries = [_]model.PortEntry{
        .{
            .protocol = .udp,
            .local_address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
            .local_port = 5353,
            .pid = 2,
            .process_name = "mdns",
            .source = .{ .backend = .test_backend },
        },
        .{
            .protocol = .tcp,
            .local_address = .{ .ipv4 = .{ 127, 0, 0, 1 } },
            .local_port = 3000,
            .pid = 10,
            .process_name = "node",
            .source = .{ .backend = .test_backend },
        },
        .{
            .protocol = .tcp,
            .local_address = .{ .ipv4 = .{ 127, 0, 0, 1 } },
            .local_port = 2000,
            .pid = 11,
            .process_name = "bun",
            .source = .{ .backend = .test_backend },
        },
    };
    const source: SnapshotSource = .{ .snapshot = .{ .entries = &entries, .stats = .{ .parse_errors = 1 } } };

    var result = try source.scanner().scan(std.testing.allocator, std.testing.io, .{ .protocol = .tcp });
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.entries.len);
    try std.testing.expectEqual(@as(u16, 2000), result.entries[0].local_port);
    try std.testing.expectEqual(@as(u16, 3000), result.entries[1].local_port);
    try std.testing.expectEqual(@as(usize, 1), result.stats.parse_errors);
    try std.testing.expect(result.entries[1].process_name.?.ptr != entries[1].process_name.?.ptr);
}
