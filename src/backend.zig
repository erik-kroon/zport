const std = @import("std");
const builtin = @import("builtin");
const model = @import("model.zig");

pub fn scan(allocator: std.mem.Allocator, io: std.Io, filter: model.ScanFilter) anyerror!model.ScanResult {
    return switch (builtin.os.tag) {
        .macos => @import("platform/macos.zig").scan(allocator, io, filter),
        .linux => @import("platform/linux.zig").scan(allocator, io, filter),
        else => error.UnsupportedPlatform,
    };
}
