const std = @import("std");
const backend = @import("backend.zig");
const cli = @import("cli.zig");
const model = @import("model.zig");
const output = @import("output.zig");

pub const KillResult = struct {
    code: cli.ExitCode,
};

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
    opts: cli.KillOptions,
) !KillResult {
    var result = try backend.scan(allocator, io, .{ .port = opts.port, .protocol = opts.protocol });
    defer result.deinit();

    var killable: std.ArrayList(model.PortEntry) = .empty;
    defer killable.deinit(allocator);
    var pids = std.AutoHashMap(u32, void).init(allocator);
    defer pids.deinit();

    for (result.entries) |entry| {
        if (entry.pid) |pid| {
            if (pid == 0) continue;
            try killable.append(allocator, entry);
            try pids.put(pid, {});
        }
    }

    if (pids.count() == 0) {
        try stderr.print("zport: no process found using port {d}\n", .{opts.port});
        return .{ .code = .no_match };
    }

    if (opts.dry_run) {
        try output.writeTable(stdout, killable.items, .{});
        return .{ .code = .ok };
    }

    try stdout.print("Killing processes using port {d}:\n\n", .{opts.port});
    try output.writeTable(stdout, killable.items, .{});
    try stdout.writeByte('\n');

    var permission_failures: usize = 0;
    var signal_failures: usize = 0;
    var sent: usize = 0;
    var it = pids.keyIterator();
    while (it.next()) |pid_ptr| {
        const pid = pid_ptr.*;
        std.posix.kill(@intCast(pid), toPosixSignal(opts.signal)) catch |err| switch (err) {
            error.PermissionDenied => {
                permission_failures += 1;
                try stderr.print("failed to signal {d}: permission denied\n", .{pid});
                continue;
            },
            error.ProcessNotFound => {
                try stdout.print("process {d} already exited\n", .{pid});
                continue;
            },
            else => {
                signal_failures += 1;
                try stderr.print("failed to signal {d}: {s}\n", .{ pid, @errorName(err) });
                continue;
            },
        };
        sent += 1;
        try stdout.print("sent {s} to {d}\n", .{ opts.signal.text(), pid });
    }

    if (permission_failures != 0) return .{ .code = .permission };
    if (signal_failures != 0) return .{ .code = .runtime };
    if (sent == 0) return .{ .code = .no_match };

    const survivors = try waitForPortRelease(io, allocator, &pids, opts.port, opts.protocol, opts.wait_ms);
    defer allocator.free(survivors);
    if (survivors.len != 0) {
        for (survivors) |pid| {
            try stderr.print("process {d} still alive after {d}ms\n", .{ pid, opts.wait_ms });
        }
        return .{ .code = .runtime };
    }

    return .{ .code = .ok };
}

fn waitForPortRelease(
    io: std.Io,
    allocator: std.mem.Allocator,
    pids: *std.AutoHashMap(u32, void),
    port: u16,
    protocol: ?model.Protocol,
    wait_ms: u32,
) ![]u32 {
    var remaining: std.ArrayList(u32) = .empty;
    errdefer remaining.deinit(allocator);

    var elapsed: u32 = 0;
    while (elapsed < wait_ms) : (elapsed += 50) {
        if (!try anyTargetStillHoldsPort(allocator, io, pids, port, protocol, null)) {
            return try remaining.toOwnedSlice(allocator);
        }
        const sleep_ms = @min(@as(u32, 50), wait_ms - elapsed);
        try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(sleep_ms), .awake);
    }

    _ = try anyTargetStillHoldsPort(allocator, io, pids, port, protocol, &remaining);
    return try remaining.toOwnedSlice(allocator);
}

fn anyTargetStillHoldsPort(
    allocator: std.mem.Allocator,
    io: std.Io,
    pids: *std.AutoHashMap(u32, void),
    port: u16,
    protocol: ?model.Protocol,
    remaining: ?*std.ArrayList(u32),
) !bool {
    var result = try backend.scan(allocator, io, .{ .port = port, .protocol = protocol });
    defer result.deinit();
    var seen = std.AutoHashMap(u32, void).init(allocator);
    defer seen.deinit();

    var found = false;
    for (result.entries) |entry| {
        const pid = entry.pid orelse continue;
        if (!pids.contains(pid)) continue;
        found = true;
        if (remaining) |out| {
            const put = try seen.getOrPut(pid);
            if (!put.found_existing) try out.append(allocator, pid);
        } else {
            return true;
        }
    }
    return found;
}

fn toPosixSignal(signal: cli.KillSignal) std.posix.SIG {
    return switch (signal) {
        .term => .TERM,
        .kill => .KILL,
        .int => .INT,
        .hup => .HUP,
    };
}

test "deduplicates pids through hashmap key path" {
    var pids = std.AutoHashMap(u32, void).init(std.testing.allocator);
    defer pids.deinit();
    try pids.put(100, {});
    try pids.put(100, {});
    try pids.put(101, {});
    try std.testing.expectEqual(@as(u32, 2), pids.count());
}
