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
    ports: model.PortSet = .{},
    protocol: ?model.Protocol = null,
    json: bool = false,
    no_header: bool = false,

    pub fn requestedPorts(self: ListOptions) model.PortSet {
        var ports = self.ports;
        if (ports.isEmpty()) {
            if (self.port) |port| ports.add(port);
        }
        return ports;
    }

    pub fn scanFilter(self: ListOptions) model.ScanFilter {
        return model.ScanFilter.fromPorts(self.requestedPorts(), self.protocol);
    }
};

pub const KillOptions = struct {
    port: u16,
    ports: model.PortSet = .{},
    protocol: ?model.Protocol = null,
    signal: KillSignal = .term,
    dry_run: bool = false,
    wait_ms: u32 = 1000,

    pub fn requestedPorts(self: KillOptions) model.PortSet {
        var ports = self.ports;
        if (ports.isEmpty()) ports.add(self.port);
        return ports;
    }

    pub fn scanFilter(self: KillOptions) model.ScanFilter {
        return model.ScanFilter.fromPorts(self.requestedPorts(), self.protocol);
    }
};

pub const Config = struct {
    action: Action,
};

pub const ParseError = error{Usage};

pub const usage =
    \\Usage:
    \\  zport [OPTIONS] [PORT ...]
    \\  zport list [OPTIONS] [PORT ...]
    \\  zport kill [OPTIONS] PORT ...
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
    var parser = ArgParser.init(args);
    var shared: SharedOptions = .{};
    var json = false;
    var no_header = false;

    while (parser.next()) |arg| {
        if (try parseProtocolOption(&parser, &shared.protocol, arg)) {
            continue;
        } else if (std.mem.eql(u8, arg, "--json")) {
            json = true;
        } else if (std.mem.eql(u8, arg, "--no-header")) {
            no_header = true;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            return error.Usage;
        } else {
            try shared.setPort(arg);
        }
    }

    return .{
        .port = shared.port,
        .ports = shared.ports,
        .protocol = shared.protocol,
        .json = json,
        .no_header = no_header,
    };
}

fn parseKill(args: []const []const u8) ParseError!KillOptions {
    var parser = ArgParser.init(args);
    var shared: SharedOptions = .{};
    var signal: KillSignal = .term;
    var signal_set = false;
    var force_set = false;
    var dry_run = false;
    var wait_ms: u32 = 1000;

    while (parser.next()) |arg| {
        if (try parseProtocolOption(&parser, &shared.protocol, arg)) {
            continue;
        } else if (std.mem.eql(u8, arg, "--force") or std.mem.eql(u8, arg, "-9")) {
            if (signal_set) return error.Usage;
            signal = .kill;
            force_set = true;
        } else if (std.mem.eql(u8, arg, "--signal")) {
            if (force_set or signal_set) return error.Usage;
            signal = try parseSignal(try parser.takeValue());
            signal_set = true;
        } else if (std.mem.eql(u8, arg, "--dry-run")) {
            dry_run = true;
        } else if (std.mem.eql(u8, arg, "--wait")) {
            wait_ms = std.fmt.parseInt(u32, try parser.takeValue(), 10) catch return error.Usage;
        } else if (isListOutputOption(arg)) {
            return error.Usage;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            return error.Usage;
        } else {
            try shared.setPort(arg);
        }
    }

    return .{
        .port = try shared.requirePort(),
        .ports = shared.ports,
        .protocol = shared.protocol,
        .signal = signal,
        .dry_run = dry_run,
        .wait_ms = wait_ms,
    };
}

const ArgParser = struct {
    args: []const []const u8,
    index: usize = 0,

    fn init(args: []const []const u8) ArgParser {
        return .{ .args = args };
    }

    fn next(self: *ArgParser) ?[]const u8 {
        if (self.index >= self.args.len) return null;
        const arg = self.args[self.index];
        self.index += 1;
        return arg;
    }

    fn takeValue(self: *ArgParser) ParseError![]const u8 {
        return self.next() orelse error.Usage;
    }
};

const SharedOptions = struct {
    port: ?u16 = null,
    ports: model.PortSet = .{},
    protocol: ?model.Protocol = null,

    fn setPort(self: *SharedOptions, value: []const u8) ParseError!void {
        const parsed = try parsePort(value);
        if (self.port == null) self.port = parsed;
        self.ports.add(parsed);
    }

    fn requirePort(self: SharedOptions) ParseError!u16 {
        return self.port orelse error.Usage;
    }
};

fn parseProtocolOption(parser: *ArgParser, protocol: *?model.Protocol, arg: []const u8) ParseError!bool {
    if (std.mem.eql(u8, arg, "--tcp")) {
        try setProtocol(protocol, .tcp);
        return true;
    }
    if (std.mem.eql(u8, arg, "--udp")) {
        try setProtocol(protocol, .udp);
        return true;
    }
    if (std.mem.eql(u8, arg, "--protocol")) {
        try setProtocol(protocol, try parseProtocol(try parser.takeValue()));
        return true;
    }
    return false;
}

fn isListOutputOption(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "--json") or std.mem.eql(u8, arg, "--no-header");
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

test "parses multiple list ports" {
    const cfg = try parse(&.{ "3000", "4000" });
    try std.testing.expect(cfg.action.list.ports.contains(3000));
    try std.testing.expect(cfg.action.list.ports.contains(4000));
    try std.testing.expectEqual(@as(usize, 2), cfg.action.list.ports.count);
}

test "parses kill options" {
    const cfg = try parse(&.{ "kill", "3000", "--force", "--dry-run", "--wait", "50" });
    try std.testing.expectEqual(@as(u16, 3000), cfg.action.kill.port);
    try std.testing.expectEqual(KillSignal.kill, cfg.action.kill.signal);
    try std.testing.expect(cfg.action.kill.dry_run);
    try std.testing.expectEqual(@as(u32, 50), cfg.action.kill.wait_ms);
}

test "parses multiple kill ports" {
    const cfg = try parse(&.{ "kill", "3000", "4000", "--dry-run" });
    try std.testing.expect(cfg.action.kill.ports.contains(3000));
    try std.testing.expect(cfg.action.kill.ports.contains(4000));
    try std.testing.expectEqual(@as(usize, 2), cfg.action.kill.ports.count);
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
