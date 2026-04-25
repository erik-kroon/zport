const std = @import("std");
const model = @import("model.zig");

pub const Address = struct {
    value: model.IpAddress,

    pub fn write(self: Address, writer: *std.Io.Writer) !void {
        switch (self.value) {
            .ipv4 => |bytes| try writer.print("{d}.{d}.{d}.{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3] }),
            .ipv6 => |bytes| try writeIpv6(writer, bytes),
        }
    }

    pub fn width(self: Address) usize {
        return switch (self.value) {
            .ipv4 => |bytes| decimalWidth(bytes[0]) + 1 + decimalWidth(bytes[1]) + 1 + decimalWidth(bytes[2]) + 1 + decimalWidth(bytes[3]),
            .ipv6 => |bytes| ipv6Width(bytes),
        };
    }
};

pub const Local = struct {
    address: Address,
    port: u16,

    pub fn write(self: Local, writer: *std.Io.Writer) !void {
        switch (self.address.value) {
            .ipv4 => {
                try self.address.write(writer);
                try writer.print(":{d}", .{self.port});
            },
            .ipv6 => {
                try writer.writeAll("[");
                try self.address.write(writer);
                try writer.print("]:{d}", .{self.port});
            },
        }
    }

    pub fn width(self: Local) usize {
        return switch (self.address.value) {
            .ipv4 => self.address.width() + 1 + decimalWidth(self.port),
            .ipv6 => self.address.width() + 3 + decimalWidth(self.port),
        };
    }
};

pub fn address(value: model.IpAddress) Address {
    return .{ .value = value };
}

pub fn local(entry: model.PortEntry) Local {
    return .{
        .address = address(entry.local_address),
        .port = entry.local_port,
    };
}

fn decimalWidth(value: anytype) usize {
    var n: u64 = @intCast(value);
    var width: usize = 1;
    while (n >= 10) : (n /= 10) width += 1;
    return width;
}

fn writeIpv6(writer: *std.Io.Writer, bytes: [16]u8) !void {
    var parts: [8]u16 = undefined;
    for (&parts, 0..) |*part, i| {
        part.* = std.mem.readInt(u16, bytes[i * 2 ..][0..2], .big);
    }

    var best_start: usize = 8;
    var best_len: usize = 0;
    var run_start: usize = 0;
    var run_len: usize = 0;
    for (parts, 0..) |part, i| {
        if (part == 0) {
            if (run_len == 0) run_start = i;
            run_len += 1;
            if (run_len > best_len) {
                best_start = run_start;
                best_len = run_len;
            }
        } else {
            run_len = 0;
        }
    }
    if (best_len < 2) {
        best_start = 8;
        best_len = 0;
    }

    var i: usize = 0;
    while (i < parts.len) : (i += 1) {
        if (i == best_start) {
            try writer.writeAll(if (i == 0) "::" else ":");
            i += best_len - 1;
            continue;
        }
        try writer.print("{x}", .{parts[i]});
        if (i != parts.len - 1) try writer.writeByte(':');
    }
}

fn ipv6Width(bytes: [16]u8) usize {
    var buf: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    writeIpv6(&writer, bytes) catch return 39;
    return writer.end;
}

fn expectAddressText(address_value: model.IpAddress, expected: []const u8) !void {
    var aw = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer aw.deinit();

    try address(address_value).write(&aw.writer);
    try std.testing.expectEqualStrings(expected, aw.written());
    try std.testing.expectEqual(expected.len, address(address_value).width());
}

fn expectLocalText(entry: model.PortEntry, expected: []const u8) !void {
    var aw = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer aw.deinit();

    const display = local(entry);
    try display.write(&aw.writer);
    try std.testing.expectEqualStrings(expected, aw.written());
    try std.testing.expectEqual(expected.len, display.width());
}

test "formats ipv4 addresses" {
    try expectAddressText(.{ .ipv4 = .{ 127, 0, 0, 1 } }, "127.0.0.1");
    try expectAddressText(.{ .ipv4 = .{ 255, 255, 255, 255 } }, "255.255.255.255");
}

test "formats ipv6 addresses with canonical zero compression" {
    try expectAddressText(.{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } }, "::");
    try expectAddressText(.{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } }, "::1");
    try expectAddressText(.{ .ipv6 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } }, "2001:db8::1");
    try expectAddressText(.{ .ipv6 = .{ 0x20, 0x01, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1 } }, "2001:0:0:1::1");
    try expectAddressText(.{ .ipv6 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6 } }, "2001:db8:1:2:3:4:5:6");
}

test "formats local endpoints and reports display width" {
    try expectLocalText(.{
        .protocol = .tcp,
        .local_address = .{ .ipv4 = .{ 127, 0, 0, 1 } },
        .local_port = 3000,
        .pid = null,
        .process_name = null,
        .source = .{ .backend = .test_backend },
    }, "127.0.0.1:3000");
    try expectLocalText(.{
        .protocol = .tcp,
        .local_address = .{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },
        .local_port = 3000,
        .pid = null,
        .process_name = null,
        .source = .{ .backend = .test_backend },
    }, "[::1]:3000");
}
