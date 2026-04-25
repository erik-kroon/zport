const std = @import("std");
const builtin = @import("builtin");

test {
    _ = @import("model.zig");
    _ = @import("endpoint.zig");
    _ = @import("cli.zig");
    _ = @import("output.zig");
    _ = @import("platform/linux_procnet.zig");
    _ = @import("platform/linux.zig");
    _ = @import("kill.zig");
}

test "backend finds current tcp listener" {
    if (builtin.os.tag != .macos and builtin.os.tag != .linux) return error.SkipZigTest;

    const backend = @import("backend.zig");
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(std.testing.io, .{ .reuse_address = true });
    defer server.deinit(std.testing.io);

    const port = server.socket.address.getPort();
    var result = try backend.scan(std.testing.allocator, std.testing.io, .{ .port = port, .protocol = .tcp });
    defer result.deinit();

    const pid: u32 = @intCast(std.c.getpid());
    for (result.entries) |entry| {
        if (entry.pid == pid and entry.local_port == port and entry.protocol == .tcp) return;
    }
    return error.TestExpectedCurrentPidListener;
}

test "kill command terminates forked listener" {
    if (builtin.os.tag != .macos and builtin.os.tag != .linux) return error.SkipZigTest;

    const cli = @import("cli.zig");
    const kill = @import("kill.zig");

    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(std.testing.io, .{ .reuse_address = true });
    const port = server.socket.address.getPort();

    const pid = std.c.fork();
    if (pid < 0) return error.ForkFailed;
    if (pid == 0) {
        while (true) {
            const ts: std.c.timespec = .{ .sec = 1, .nsec = 0 };
            _ = std.c.nanosleep(&ts, null);
        }
    }

    server.deinit(std.testing.io);
    defer {
        std.posix.kill(@intCast(pid), .KILL) catch {};
        _ = std.c.waitpid(pid, null, 0);
    }

    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();
    var err = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer err.deinit();

    const result = try kill.run(std.testing.allocator, std.testing.io, &out.writer, &err.writer, .{
        .port = port,
        .signal = .term,
        .wait_ms = 2000,
    });

    try std.testing.expectEqual(cli.ExitCode.ok, result.code);
}
