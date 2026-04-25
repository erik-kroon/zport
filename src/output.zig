const std = @import("std");
const endpoint = @import("endpoint.zig");
const model = @import("model.zig");

pub const TableOptions = struct {
    header: bool = true,
};

pub fn writeTable(writer: *std.Io.Writer, entries: []const model.PortEntry, opts: TableOptions) !void {
    var local_width: usize = "LOCAL".len;
    for (entries) |entry| {
        const width = endpoint.local(entry).width();
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
        try writeLocalPadded(writer, endpoint.local(entry), local_width);
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
        try endpoint.address(entry.local_address).write(writer);
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
        try writer.print(",\"backend\":\"{s}\"", .{entry.source.backend.text()});
        if (entry.source.fd) |fd| try writer.print(",\"fd\":{d}", .{fd});
        if (entry.source.inode) |inode| try writer.print(",\"inode\":{d}", .{inode});
        if (entry.source.raw_state) |state| try writer.print(",\"raw_state\":{d}", .{state});
        try writer.writeAll("}");
    }
    try writer.writeAll("],\"stats\":{");
    try writer.print("\"skipped_processes\":{d},\"skipped_fds\":{d},\"parse_errors\":{d},\"permission_errors\":{d}", .{
        result.stats.skipped_processes,
        result.stats.skipped_fds,
        result.stats.parse_errors,
        result.stats.permission_errors,
    });
    try writer.writeAll("}}\n");
}

fn writeLocalPadded(writer: *std.Io.Writer, local_display: endpoint.Local, width: usize) !void {
    try local_display.write(writer);
    const written = local_display.width();
    if (written < width) {
        for (0..(width - written)) |_| try writer.writeByte(' ');
    }
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
        .stats = .{ .permission_errors = 1 },
    };

    try writeJson(&aw.writer, result);
    try std.testing.expect(std.mem.indexOf(u8, aw.written(), "\"protocol\":\"udp\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, aw.written(), "mDNS\\\"Responder") != null);
}
