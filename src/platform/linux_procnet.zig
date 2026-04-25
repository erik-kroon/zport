const std = @import("std");
const model = @import("../model.zig");

pub const SocketCandidate = struct {
    protocol: model.Protocol,
    address: model.IpAddress,
    port: u16,
    inode: u64,
    raw_state: ?u8,
};

pub const ParseStats = struct {
    parse_errors: usize = 0,
};

pub fn parseTable(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(SocketCandidate),
    content: []const u8,
    protocol: model.Protocol,
    family: model.AddressFamily,
    stats: *ParseStats,
) !void {
    var lines = std.mem.splitScalar(u8, content, '\n');
    _ = lines.next();
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0) continue;
        if (parseLine(line, protocol, family)) |candidate| {
            try out.append(allocator, candidate);
        } else |err| switch (err) {
            error.Skip => {},
            error.Malformed => stats.parse_errors += 1,
        }
    }
}

const LineError = error{ Skip, Malformed };

fn parseLine(line: []const u8, protocol: model.Protocol, family: model.AddressFamily) LineError!SocketCandidate {
    var fields: [10][]const u8 = undefined;
    var count: usize = 0;
    var tokens = std.mem.tokenizeAny(u8, line, " \t");
    while (tokens.next()) |token| {
        if (count < fields.len) fields[count] = token;
        count += 1;
    }
    if (count < 10) return error.Malformed;

    const local = fields[1];
    const state_text = fields[3];
    const inode_text = fields[9];
    const colon = std.mem.indexOfScalar(u8, local, ':') orelse return error.Malformed;
    const address_text = local[0..colon];
    const port_text = local[colon + 1 ..];

    const state = std.fmt.parseInt(u8, state_text, 16) catch return error.Malformed;
    if (protocol == .tcp and state != 0x0a) return error.Skip;

    const port = std.fmt.parseInt(u16, port_text, 16) catch return error.Malformed;
    if (port == 0) return error.Skip;

    const address = switch (family) {
        .ipv4 => model.IpAddress{ .ipv4 = parseIpv4(address_text) catch return error.Malformed },
        .ipv6 => model.IpAddress{ .ipv6 = parseIpv6(address_text) catch return error.Malformed },
    };
    const inode = std.fmt.parseInt(u64, inode_text, 10) catch return error.Malformed;

    return .{
        .protocol = protocol,
        .address = address,
        .port = port,
        .inode = inode,
        .raw_state = state,
    };
}

pub fn parseIpv4(text: []const u8) ![4]u8 {
    if (text.len != 8) return error.Malformed;
    var raw: [4]u8 = undefined;
    for (&raw, 0..) |*byte, i| {
        byte.* = try std.fmt.parseInt(u8, text[i * 2 ..][0..2], 16);
    }
    return .{ raw[3], raw[2], raw[1], raw[0] };
}

pub fn parseIpv6(text: []const u8) ![16]u8 {
    if (text.len != 32) return error.Malformed;
    var raw: [16]u8 = undefined;
    for (&raw, 0..) |*byte, i| {
        byte.* = try std.fmt.parseInt(u8, text[i * 2 ..][0..2], 16);
    }
    var out: [16]u8 = undefined;
    var word: usize = 0;
    while (word < 4) : (word += 1) {
        const base = word * 4;
        out[base + 0] = raw[base + 3];
        out[base + 1] = raw[base + 2];
        out[base + 2] = raw[base + 1];
        out[base + 3] = raw[base + 0];
    }
    return out;
}

test "parses linux proc net rows" {
    const fixture =
        \\  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
        \\   0: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000  501        0 123456 1 0000000000000000 100 0 0 10 0
        \\   1: 0100007F:0BB9 0100007F:1770 01 00000000:00000000 00:00000000 00000000  501        0 999999 1 0000000000000000 100 0 0 10 0
    ;
    var list: std.ArrayList(SocketCandidate) = .empty;
    defer list.deinit(std.testing.allocator);
    var stats: ParseStats = .{};
    try parseTable(std.testing.allocator, &list, fixture, .tcp, .ipv4, &stats);

    try std.testing.expectEqual(@as(usize, 1), list.items.len);
    try std.testing.expectEqual(@as(u16, 3000), list.items[0].port);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, &list.items[0].address.ipv4);
    try std.testing.expectEqual(@as(u64, 123456), list.items[0].inode);
    try std.testing.expectEqual(@as(usize, 0), stats.parse_errors);
}

test "parses linux ipv6 proc address" {
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, &(try parseIpv6("00000000000000000000000000000000")));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, &(try parseIpv6("00000000000000000000000001000000")));
}
