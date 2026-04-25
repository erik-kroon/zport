const std = @import("std");
const model = @import("model.zig");

pub const TableOptions = struct {
    header: bool = true,
};

pub fn writeTable(writer: *std.Io.Writer, entries: []const model.PortEntry, opts: TableOptions) !void {
    var local_width: usize = "LOCAL".len;
    for (entries) |entry| {
        const width = localWidth(entry);
        if (width > local_width) local_width = width;
    }

    if (opts.header) {
        try writer.writeAll("PROTO  LOCAL");
        if (local_width > "LOCAL".len) {
            for (0..(local_width - "LOCAL".len)) |_| try writer.writeByte(' ');
        }
        try writer.writeAll("  PID    PROCESS\n");
    }
    for (entries) |entry| {
        try writer.print("{s:<5}  ", .{entry.protocol.text()});
        try writeLocalPadded(writer, entry, local_width);
        try writer.writeAll("  ");
        if (entry.pid) |pid| {
            try writer.print("{d:<5}", .{pid});
        } else {
            try writer.writeAll("-    ");
        }
        try writer.print("  {s}\n", .{entry.process_name orelse "?"});
    }
}

pub fn writeJson(writer: *std.Io.Writer, result: model.ScanResult) !void {
    try writer.writeAll("{\"entries\":[");
    for (result.entries, 0..) |entry, i| {
        if (i != 0) try writer.writeAll(",");
        try writer.writeAll("{");
        try writer.print("\"protocol\":\"{s}\",", .{entry.protocol.text()});
        try writer.writeAll("\"local_address\":\"");
        try writeAddress(writer, entry.local_address);
        try writer.print("\",\"local_port\":{d},", .{entry.local_port});
        if (entry.pid) |pid| {
            try writer.print("\"pid\":{d},", .{pid});
        } else {
            try writer.writeAll("\"pid\":null,");
        }
        try writer.writeAll("\"process_name\":");
        if (entry.process_name) |name| {
            try writeJsonString(writer, name);
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll("}");
    }
    try writer.writeAll("],\"diagnostics\":{");
    try writer.print("\"permission_denied_processes\":{d},\"permission_denied_fds\":{d},\"malformed_socket_rows\":{d}", .{
        result.diagnostics.permission_denied_processes,
        result.diagnostics.permission_denied_fds,
        result.diagnostics.malformed_socket_rows,
    });
    try writer.writeAll("}}\n");
}

pub fn writeLocal(writer: *std.Io.Writer, entry: model.PortEntry) !void {
    switch (entry.local_address) {
        .ipv4 => {
            try writeAddress(writer, entry.local_address);
            try writer.print(":{d}", .{entry.local_port});
        },
        .ipv6 => {
            try writer.writeAll("[");
            try writeAddress(writer, entry.local_address);
            try writer.print("]:{d}", .{entry.local_port});
        },
    }
}

pub fn writeAddress(writer: *std.Io.Writer, address: model.IpAddress) !void {
    switch (address) {
        .ipv4 => |bytes| try writer.print("{d}.{d}.{d}.{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3] }),
        .ipv6 => |bytes| try writeIpv6(writer, bytes),
    }
}

fn writeLocalPadded(writer: *std.Io.Writer, entry: model.PortEntry, width: usize) !void {
    try writeLocal(writer, entry);
    const written = localWidth(entry);
    if (written < width) {
        for (0..(width - written)) |_| try writer.writeByte(' ');
    }
}

fn localWidth(entry: model.PortEntry) usize {
    const port_width = decimalWidth(entry.local_port);
    return switch (entry.local_address) {
        .ipv4 => |bytes| decimalWidth(bytes[0]) + 1 + decimalWidth(bytes[1]) + 1 + decimalWidth(bytes[2]) + 1 + decimalWidth(bytes[3]) + 1 + port_width,
        .ipv6 => |bytes| ipv6Width(bytes) + 3 + port_width,
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

fn writeJsonString(writer: *std.Io.Writer, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |byte| {
        switch (byte) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (byte < 0x20) {
                    try writer.print("\\u{x:0>4}", .{byte});
                } else {
                    try writer.writeByte(byte);
                }
            },
        }
    }
    try writer.writeByte('"');
}

test "writes table with ipv4 and ipv6" {
    var aw = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer aw.deinit();
    const entries = [_]model.PortEntry{
        .{
            .protocol = .tcp,
            .local_address = .{ .ipv4 = .{ 127, 0, 0, 1 } },
            .local_port = 3000,
            .pid = 1842,
            .process_name = "node",
            .source = .{ .backend = .test_backend },
        },
        .{
            .protocol = .tcp,
            .local_address = .{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },
            .local_port = 3000,
            .pid = null,
            .process_name = null,
            .source = .{ .backend = .test_backend },
        },
    };

    try writeTable(&aw.writer, &entries, .{});
    try std.testing.expect(std.mem.indexOf(u8, aw.written(), "127.0.0.1:3000") != null);
    try std.testing.expect(std.mem.indexOf(u8, aw.written(), "[::1]:3000") != null);
}

test "writes json" {
    var aw = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer aw.deinit();
    var entries = [_]model.PortEntry{.{
        .protocol = .udp,
        .local_address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
        .local_port = 5353,
        .pid = 12,
        .process_name = "mDNS\"Responder",
        .source = .{ .backend = .test_backend, .inode = 99 },
    }};
    const result: model.ScanResult = .{
        .allocator = std.testing.allocator,
        .entries = &entries,
        .diagnostics = .{ .permission_denied_processes = 1 },
    };

    try writeJson(&aw.writer, result);
    try std.testing.expect(std.mem.indexOf(u8, aw.written(), "\"protocol\":\"udp\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, aw.written(), "mDNS\\\"Responder") != null);
    try std.testing.expect(std.mem.indexOf(u8, aw.written(), "\"diagnostics\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, aw.written(), "\"inode\"") == null);
}
