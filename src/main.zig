const std = @import("std");
const build_options = @import("build_options");
const backend = @import("backend.zig");
const cli = @import("cli.zig");
const kill = @import("kill.zig");
const model = @import("model.zig");
const output = @import("output.zig");

pub fn main(init: std.process.Init) !void {
    const code = run(init) catch |err| switch (err) {
        error.UnsupportedPlatform => cli.ExitCode.unsupported,
        else => blk: {
            var stderr_buf: [4096]u8 = undefined;
            var stderr_file = std.Io.File.stderr().writer(init.io, &stderr_buf);
            const stderr = &stderr_file.interface;
            try stderr.print("zport: {s}\n", .{@errorName(err)});
            try stderr.flush();
            break :blk cli.ExitCode.runtime;
        },
    };
    if (code != .ok) std.process.exit(@intFromEnum(code));
}

fn run(init: std.process.Init) !cli.ExitCode {
    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_file = std.Io.File.stdout().writer(init.io, &stdout_buf);
    var stderr_file = std.Io.File.stderr().writer(init.io, &stderr_buf);
    const stdout = &stdout_file.interface;
    const stderr = &stderr_file.interface;
    defer stdout.flush() catch {};
    defer stderr.flush() catch {};

    var args_list: std.ArrayList([]const u8) = .empty;
    defer args_list.deinit(init.gpa);

    var args_it = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.gpa);
    defer args_it.deinit();
    _ = args_it.next();
    while (args_it.next()) |arg| try args_list.append(init.gpa, arg);

    const config = cli.parse(args_list.items) catch {
        try stderr.writeAll("zport: invalid arguments\n\n");
        try stderr.writeAll(cli.usage);
        return .usage;
    };

    switch (config.action) {
        .help => {
            try stdout.writeAll(cli.usage);
            return .ok;
        },
        .version => {
            try stdout.print("zport {s}\n", .{build_options.version});
            return .ok;
        },
        .list => |opts| return runList(backend.Scanner.platform(), init.gpa, init.io, stdout, stderr, opts),
        .kill => |opts| return (try kill.run(init.gpa, init.io, stdout, stderr, opts)).code,
    }
}

fn runList(
    scanner: backend.Scanner,
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
    opts: cli.ListOptions,
) !cli.ExitCode {
    var result = try scanner.scan(allocator, io, .{ .port = opts.port, .protocol = opts.protocol });
    defer result.deinit();

    if (opts.json) {
        try output.writeJson(stdout, result);
    } else {
        try output.writeTable(stdout, result.entries, .{ .header = !opts.no_header });
        if (result.stats.hasPermissionGaps()) {
            try stderr.print("zport: skipped {d} processes due to permissions; run with sudo for complete results\n", .{result.stats.skipped_processes});
        }
    }

    if (opts.port != null and result.entries.len == 0) {
        try stderr.print("zport: no process found using port {d}\n", .{opts.port.?});
        return .no_match;
    }
    return .ok;
}

test {
    _ = model;
}

test "list command uses scanner seam and reports filtered misses" {
    const entries = [_]model.PortEntry{.{
        .protocol = .tcp,
        .local_address = .{ .ipv4 = .{ 127, 0, 0, 1 } },
        .local_port = 3000,
        .pid = 42,
        .process_name = "node",
        .source = .{ .backend = .test_backend },
    }};
    const source: backend.SnapshotSource = .{ .snapshot = .{ .entries = &entries } };

    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();
    var err = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer err.deinit();

    const code = try runList(source.scanner(), std.testing.allocator, std.testing.io, &out.writer, &err.writer, .{ .port = 4000 });

    try std.testing.expectEqual(cli.ExitCode.no_match, code);
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "no process found using port 4000") != null);
}
