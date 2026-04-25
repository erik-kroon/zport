const std = @import("std");
const model = @import("model.zig");

pub const ExitCode = enum(u8) {
    ok = 0,
    no_match = 1,
    usage = 2,
    permission = 3,
    unsupported = 4,
    runtime = 5,
};

pub const KillSignal = enum {
    term,
    kill,
    int,
    hup,

    pub fn text(self: KillSignal) []const u8 {
        return switch (self) {
            .term => "SIGTERM",
            .kill => "SIGKILL",
            .int => "SIGINT",
            .hup => "SIGHUP",
        };
    }
};

pub const Action = union(enum) {
    list: ListOptions,
    kill: KillOptions,
    help,
    version,
};

pub const ListOptions = struct {
    port: ?u16 = null,
    protocol: ?model.Protocol = null,
    json: bool = false,
    no_header: bool = false,
};

pub const KillOptions = struct {
    port: u16,
    protocol: ?model.Protocol = null,
    signal: KillSignal = .term,
    dry_run: bool = false,
    wait_ms: u32 = 1000,
};

pub const Config = struct {
    action: Action,
};

pub const ParseError = error{Usage};

pub const usage =
    \\Usage:
    \\  zport [OPTIONS] [PORT]
    \\  zport list [OPTIONS] [PORT]
    \\  zport kill [OPTIONS] PORT
    \\
    \\Options:
    \\  --tcp                 Show TCP only
    \\  --udp                 Show UDP only
    \\  --protocol <proto>    tcp | udp
    \\  --json                Emit JSON for list output
    \\  --no-header           Omit table header
    \\  -h, --help            Show help
    \\  -V, --version         Show version
    \\
    \\Kill options:
    \\  --force, -9           Send SIGKILL
    \\  --signal <signal>     TERM | KILL | INT | HUP
    \\  --dry-run             Show matching PIDs without signaling
    \\  --wait <ms>           Wait up to N milliseconds for exit
    \\
;

pub fn parse(args: []const []const u8) ParseError!Config {
    if (args.len == 0) return .{ .action = .{ .list = .{} } };

    if (std.mem.eql(u8, args[0], "-h") or std.mem.eql(u8, args[0], "--help")) {
        if (args.len != 1) return error.Usage;
        return .{ .action = .help };
    }
    if (std.mem.eql(u8, args[0], "-V") or std.mem.eql(u8, args[0], "--version")) {
        if (args.len != 1) return error.Usage;
        return .{ .action = .version };
    }

    if (std.mem.eql(u8, args[0], "kill")) {
        return .{ .action = .{ .kill = try parseKill(args[1..]) } };
    }

    const list_args = if (std.mem.eql(u8, args[0], "list")) args[1..] else args;
    return .{ .action = .{ .list = try parseList(list_args) } };
}

fn parseList(args: []const []const u8) ParseError!ListOptions {
    var opts: ListOptions = .{};
    var port_seen = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--tcp")) {
            try setProtocol(&opts.protocol, .tcp);
        } else if (std.mem.eql(u8, arg, "--udp")) {
            try setProtocol(&opts.protocol, .udp);
        } else if (std.mem.eql(u8, arg, "--protocol")) {
            i += 1;
            if (i >= args.len) return error.Usage;
            try setProtocol(&opts.protocol, try parseProtocol(args[i]));
        } else if (std.mem.eql(u8, arg, "--json")) {
            opts.json = true;
        } else if (std.mem.eql(u8, arg, "--no-header")) {
            opts.no_header = true;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            return error.Usage;
        } else {
            if (port_seen) return error.Usage;
            opts.port = try parsePort(arg);
            port_seen = true;
        }
    }
    return opts;
}

fn parseKill(args: []const []const u8) ParseError!KillOptions {
    var port: ?u16 = null;
    var protocol: ?model.Protocol = null;
    var signal: KillSignal = .term;
    var signal_set = false;
    var force_set = false;
    var dry_run = false;
    var wait_ms: u32 = 1000;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--tcp")) {
            try setProtocol(&protocol, .tcp);
        } else if (std.mem.eql(u8, arg, "--udp")) {
            try setProtocol(&protocol, .udp);
        } else if (std.mem.eql(u8, arg, "--protocol")) {
            i += 1;
            if (i >= args.len) return error.Usage;
            try setProtocol(&protocol, try parseProtocol(args[i]));
        } else if (std.mem.eql(u8, arg, "--force") or std.mem.eql(u8, arg, "-9")) {
            if (signal_set) return error.Usage;
            signal = .kill;
            force_set = true;
        } else if (std.mem.eql(u8, arg, "--signal")) {
            if (force_set or signal_set) return error.Usage;
            i += 1;
            if (i >= args.len) return error.Usage;
            signal = try parseSignal(args[i]);
            signal_set = true;
        } else if (std.mem.eql(u8, arg, "--dry-run")) {
            dry_run = true;
        } else if (std.mem.eql(u8, arg, "--wait")) {
            i += 1;
            if (i >= args.len) return error.Usage;
            wait_ms = std.fmt.parseInt(u32, args[i], 10) catch return error.Usage;
        } else if (std.mem.eql(u8, arg, "--json") or std.mem.eql(u8, arg, "--no-header")) {
            return error.Usage;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            return error.Usage;
        } else {
            if (port != null) return error.Usage;
            port = try parsePort(arg);
        }
    }

    return .{
        .port = port orelse return error.Usage,
        .protocol = protocol,
        .signal = signal,
        .dry_run = dry_run,
        .wait_ms = wait_ms,
    };
}

fn setProtocol(slot: *?model.Protocol, value: model.Protocol) ParseError!void {
    if (slot.*) |existing| {
        if (existing != value) return error.Usage;
    }
    slot.* = value;
}

fn parseProtocol(value: []const u8) ParseError!model.Protocol {
    if (std.mem.eql(u8, value, "tcp")) return .tcp;
    if (std.mem.eql(u8, value, "udp")) return .udp;
    return error.Usage;
}

fn parseSignal(value: []const u8) ParseError!KillSignal {
    if (std.ascii.eqlIgnoreCase(value, "TERM") or std.ascii.eqlIgnoreCase(value, "SIGTERM")) return .term;
    if (std.ascii.eqlIgnoreCase(value, "KILL") or std.ascii.eqlIgnoreCase(value, "SIGKILL")) return .kill;
    if (std.ascii.eqlIgnoreCase(value, "INT") or std.ascii.eqlIgnoreCase(value, "SIGINT")) return .int;
    if (std.ascii.eqlIgnoreCase(value, "HUP") or std.ascii.eqlIgnoreCase(value, "SIGHUP")) return .hup;
    return error.Usage;
}

pub fn parsePort(value: []const u8) ParseError!u16 {
    if (value.len == 0 or value[0] == ':') return error.Usage;
    const parsed = std.fmt.parseInt(u32, value, 10) catch return error.Usage;
    if (parsed == 0 or parsed > 65535) return error.Usage;
    return @intCast(parsed);
}

test "parses list defaults and filters" {
    try std.testing.expectEqual(Action{ .list = .{} }, (try parse(&.{})).action);
    try std.testing.expectEqual(@as(?u16, 3000), (try parse(&.{"3000"})).action.list.port);
    try std.testing.expectEqual(model.Protocol.tcp, (try parse(&.{"--tcp"})).action.list.protocol.?);
    try std.testing.expectEqual(model.Protocol.udp, (try parse(&.{ "--protocol", "udp" })).action.list.protocol.?);
    try std.testing.expect((try parse(&.{"--json"})).action.list.json);
}

test "parses kill options" {
    const cfg = try parse(&.{ "kill", "3000", "--force", "--dry-run", "--wait", "50" });
    try std.testing.expectEqual(@as(u16, 3000), cfg.action.kill.port);
    try std.testing.expectEqual(KillSignal.kill, cfg.action.kill.signal);
    try std.testing.expect(cfg.action.kill.dry_run);
    try std.testing.expectEqual(@as(u32, 50), cfg.action.kill.wait_ms);
}

test "rejects invalid arguments" {
    try std.testing.expectError(error.Usage, parse(&.{"abc"}));
    try std.testing.expectError(error.Usage, parse(&.{"0"}));
    try std.testing.expectError(error.Usage, parse(&.{"65536"}));
    try std.testing.expectError(error.Usage, parse(&.{"-1"}));
    try std.testing.expectError(error.Usage, parse(&.{"kill"}));
    try std.testing.expectError(error.Usage, parse(&.{ "--tcp", "--udp" }));
    try std.testing.expectError(error.Usage, parse(&.{ "--protocol", "sctp" }));
    try std.testing.expectError(error.Usage, parse(&.{ "kill", "3000", "--json" }));
    try std.testing.expectError(error.Usage, parse(&.{ "kill", "3000", "--force", "--signal", "TERM" }));
}
