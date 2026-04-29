const std = @import("std");
const backend = @import("backend.zig");
const cli = @import("cli.zig");
const model = @import("model.zig");
const output = @import("output.zig");

pub const KillResult = struct {
    code: cli.ExitCode,
};

const TargetPlan = struct {
    entries: []model.PortEntry,
    pids: []u32,

    fn deinit(self: *TargetPlan, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
        allocator.free(self.pids);
        self.* = undefined;
    }
};

const KillRuntime = struct {
    context: *anyopaque,
    signal: *const fn (*anyopaque, u32, std.posix.SIG) anyerror!void,
    wait_for_release: *const fn (
        *anyopaque,
        std.Io,
        std.mem.Allocator,
        []const u32,
        model.ScanFilter,
        u32,
    ) anyerror![]u32,
};

const DeliverySummary = struct {
    permission_failures: usize = 0,
    signal_failures: usize = 0,
    sent: usize = 0,
};

const RuntimeContext = struct {
    scanner: backend.Scanner,
};

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
    opts: cli.KillOptions,
) !KillResult {
    return runWithScanner(backend.Scanner.platform(), allocator, io, stdout, stderr, opts);
}

pub fn runWithScanner(
    scanner: backend.Scanner,
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
    opts: cli.KillOptions,
) !KillResult {
    const filter = opts.scanFilter();
    var result = try scanner.scan(allocator, io, filter);
    defer result.deinit();

    var plan = try planTargets(allocator, result.entries);
    defer plan.deinit(allocator);

    if (plan.pids.len == 0) {
        try writeNoTargetMessage(stderr, opts.requestedPorts());
        return .{ .code = .no_match };
    }

    if (opts.dry_run) {
        try output.writeTable(stdout, plan.entries, .{});
        return .{ .code = .ok };
    }

    var runtime_context: RuntimeContext = .{ .scanner = scanner };
    const runtime: KillRuntime = .{
        .context = &runtime_context,
        .signal = posixSignal,
        .wait_for_release = waitForPortRelease,
    };
    return .{ .code = try executeAttempt(allocator, io, stdout, stderr, opts, plan, runtime) };
}

fn planTargets(allocator: std.mem.Allocator, entries: []const model.PortEntry) !TargetPlan {
    var killable: std.ArrayList(model.PortEntry) = .empty;
    errdefer killable.deinit(allocator);

    var seen_pids = std.AutoHashMap(u32, void).init(allocator);
    defer seen_pids.deinit();

    for (entries) |entry| {
        const pid = entry.pid orelse continue;
        if (pid == 0) continue;
        try killable.append(allocator, entry);
        try seen_pids.put(pid, {});
    }

    var pids: std.ArrayList(u32) = .empty;
    errdefer pids.deinit(allocator);
    var it = seen_pids.keyIterator();
    while (it.next()) |pid| try pids.append(allocator, pid.*);
    std.mem.sort(u32, pids.items, {}, std.sort.asc(u32));

    const planned_entries = try killable.toOwnedSlice(allocator);
    errdefer allocator.free(planned_entries);
    const planned_pids = try pids.toOwnedSlice(allocator);

    return .{
        .entries = planned_entries,
        .pids = planned_pids,
    };
}

fn executeAttempt(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
    opts: cli.KillOptions,
    plan: TargetPlan,
    runtime: KillRuntime,
) !cli.ExitCode {
    try stdout.writeAll("Killing processes using ");
    try writePortRequest(stdout, opts.requestedPorts());
    try stdout.writeAll(":\n\n");
    try output.writeTable(stdout, plan.entries, .{});
    try stdout.writeByte('\n');

    const delivery = try deliverSignals(stdout, stderr, opts.signal, plan.pids, runtime);
    const delivery_code = codeForDelivery(delivery);
    if (delivery_code != .ok) return delivery_code;

    const survivors = try runtime.wait_for_release(
        runtime.context,
        io,
        allocator,
        plan.pids,
        opts.scanFilter(),
        opts.wait_ms,
    );
    defer allocator.free(survivors);
    return try codeForSurvivors(stderr, survivors, opts.wait_ms);
}

fn deliverSignals(
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
    signal: cli.KillSignal,
    pids: []const u32,
    runtime: KillRuntime,
) !DeliverySummary {
    var summary: DeliverySummary = .{};
    for (pids) |pid| {
        runtime.signal(runtime.context, pid, toPosixSignal(signal)) catch |err| switch (err) {
            error.PermissionDenied => {
                summary.permission_failures += 1;
                try stderr.print("failed to signal {d}: permission denied\n", .{pid});
                continue;
            },
            error.ProcessNotFound => {
                try stdout.print("process {d} already exited\n", .{pid});
                continue;
            },
            else => {
                summary.signal_failures += 1;
                try stderr.print("failed to signal {d}: {s}\n", .{ pid, @errorName(err) });
                continue;
            },
        };
        summary.sent += 1;
        try stdout.print("sent {s} to {d}\n", .{ signal.text(), pid });
    }

    return summary;
}

fn codeForDelivery(summary: DeliverySummary) cli.ExitCode {
    if (summary.permission_failures != 0) return .permission;
    if (summary.signal_failures != 0) return .runtime;
    if (summary.sent == 0) return .no_match;
    return .ok;
}

fn codeForSurvivors(stderr: *std.Io.Writer, survivors: []const u32, wait_ms: u32) !cli.ExitCode {
    if (survivors.len != 0) {
        for (survivors) |pid| {
            try stderr.print("process {d} still alive after {d}ms\n", .{ pid, wait_ms });
        }
        return .runtime;
    }

    return .ok;
}

fn posixSignal(_: *anyopaque, pid: u32, signal: std.posix.SIG) !void {
    try std.posix.kill(@intCast(pid), signal);
}

fn waitForPortRelease(
    context: *anyopaque,
    io: std.Io,
    allocator: std.mem.Allocator,
    pids: []const u32,
    filter: model.ScanFilter,
    wait_ms: u32,
) ![]u32 {
    const runtime_context: *RuntimeContext = @ptrCast(@alignCast(context));
    var remaining: std.ArrayList(u32) = .empty;
    errdefer remaining.deinit(allocator);

    var elapsed: u32 = 0;
    while (elapsed < wait_ms) : (elapsed += 50) {
        if (!try anyTargetStillHoldsPort(runtime_context.scanner, allocator, io, pids, filter, null)) {
            return try remaining.toOwnedSlice(allocator);
        }
        const sleep_ms = @min(@as(u32, 50), wait_ms - elapsed);
        try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(sleep_ms), .awake);
    }

    _ = try anyTargetStillHoldsPort(runtime_context.scanner, allocator, io, pids, filter, &remaining);
    return try remaining.toOwnedSlice(allocator);
}

fn anyTargetStillHoldsPort(
    scanner: backend.Scanner,
    allocator: std.mem.Allocator,
    io: std.Io,
    pids: []const u32,
    filter: model.ScanFilter,
    remaining: ?*std.ArrayList(u32),
) !bool {
    var result = try scanner.scan(allocator, io, filter);
    defer result.deinit();
    var seen = std.AutoHashMap(u32, void).init(allocator);
    defer seen.deinit();

    var found = false;
    for (result.entries) |entry| {
        const pid = entry.pid orelse continue;
        if (!pidInPlan(pids, pid)) continue;
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

fn pidInPlan(pids: []const u32, pid: u32) bool {
    return std.mem.indexOfScalar(u32, pids, pid) != null;
}

fn toPosixSignal(signal: cli.KillSignal) std.posix.SIG {
    return switch (signal) {
        .term => .TERM,
        .kill => .KILL,
        .int => .INT,
        .hup => .HUP,
    };
}

fn writeNoTargetMessage(writer: *std.Io.Writer, ports: model.PortSet) !void {
    if (ports.count == 1) {
        try writer.print("zport: no process found using port {d}\n", .{ports.first().?});
    } else {
        try writer.writeAll("zport: no process found using requested ports\n");
    }
}

fn writePortRequest(writer: *std.Io.Writer, ports: model.PortSet) !void {
    if (ports.count == 1) {
        try writer.print("port {d}", .{ports.first().?});
        return;
    }

    try writer.writeAll("ports ");
    var first = true;
    var it = ports.bits.iterator(.{});
    while (it.next()) |index| {
        if (!first) try writer.writeAll(", ");
        first = false;
        try writer.print("{d}", .{index});
    }
}

test "target planning keeps display rows and deduplicates signal pids" {
    const entries = [_]model.PortEntry{
        testEntry(100, "node"),
        testEntry(100, "node-helper"),
        testEntry(0, "kernel"),
        testEntry(null, "unknown"),
        testEntry(101, "vite"),
    };

    var plan = try planTargets(std.testing.allocator, &entries);
    defer plan.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 3), plan.entries.len);
    try std.testing.expectEqual(@as(usize, 2), plan.pids.len);
    try std.testing.expectEqual(@as(u32, 100), plan.pids[0]);
    try std.testing.expectEqual(@as(u32, 101), plan.pids[1]);
}

test "permission failures map to permission exit without polling" {
    const entries = [_]model.PortEntry{testEntry(100, "node")};
    var plan = try planTargets(std.testing.allocator, &entries);
    defer plan.deinit(std.testing.allocator);

    var fake: FakeRuntime = .{ .signal_result = error.PermissionDenied };
    const code = try runAttemptForTest(&plan, &fake);

    try std.testing.expectEqual(cli.ExitCode.permission, code);
    try std.testing.expectEqual(@as(usize, 1), fake.signal_calls);
    try std.testing.expectEqual(@as(usize, 0), fake.wait_calls);
}

test "already exited targets map to no match without polling" {
    const entries = [_]model.PortEntry{testEntry(100, "node")};
    var plan = try planTargets(std.testing.allocator, &entries);
    defer plan.deinit(std.testing.allocator);

    var fake: FakeRuntime = .{ .signal_result = error.ProcessNotFound };
    const code = try runAttemptForTest(&plan, &fake);

    try std.testing.expectEqual(cli.ExitCode.no_match, code);
    try std.testing.expectEqual(@as(usize, 1), fake.signal_calls);
    try std.testing.expectEqual(@as(usize, 0), fake.wait_calls);
}

test "survivors map to runtime failure after successful signal delivery" {
    const entries = [_]model.PortEntry{testEntry(100, "node")};
    var plan = try planTargets(std.testing.allocator, &entries);
    defer plan.deinit(std.testing.allocator);

    var fake: FakeRuntime = .{ .survivor = 100 };
    const code = try runAttemptForTest(&plan, &fake);

    try std.testing.expectEqual(cli.ExitCode.runtime, code);
    try std.testing.expectEqual(@as(usize, 1), fake.signal_calls);
    try std.testing.expectEqual(@as(usize, 1), fake.wait_calls);
}

test "kill dry-run uses scanner-owned filtering" {
    const entries = [_]model.PortEntry{
        .{
            .protocol = .tcp,
            .local_address = .{ .ipv4 = .{ 127, 0, 0, 1 } },
            .local_port = 3000,
            .pid = 42,
            .process_name = "node",
            .source = .{ .backend = .test_backend },
        },
        .{
            .protocol = .tcp,
            .local_address = .{ .ipv4 = .{ 127, 0, 0, 1 } },
            .local_port = 4000,
            .pid = 99,
            .process_name = "other",
            .source = .{ .backend = .test_backend },
        },
    };
    const source: backend.SnapshotSource = .{ .snapshot = .{ .entries = &entries } };

    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();
    var err = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer err.deinit();

    const result = try runWithScanner(source.scanner(), std.testing.allocator, std.testing.io, &out.writer, &err.writer, .{
        .port = 3000,
        .dry_run = true,
    });

    try std.testing.expectEqual(cli.ExitCode.ok, result.code);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "127.0.0.1:3000") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "127.0.0.1:4000") == null);
    try std.testing.expectEqual(@as(usize, 0), err.written().len);
}

test "kill dry-run accepts multiple requested ports" {
    const entries = [_]model.PortEntry{
        .{
            .protocol = .tcp,
            .local_address = .{ .ipv4 = .{ 127, 0, 0, 1 } },
            .local_port = 3000,
            .pid = 42,
            .process_name = "node",
            .source = .{ .backend = .test_backend },
        },
        .{
            .protocol = .tcp,
            .local_address = .{ .ipv4 = .{ 127, 0, 0, 1 } },
            .local_port = 4000,
            .pid = 99,
            .process_name = "vite",
            .source = .{ .backend = .test_backend },
        },
        .{
            .protocol = .tcp,
            .local_address = .{ .ipv4 = .{ 127, 0, 0, 1 } },
            .local_port = 5000,
            .pid = 100,
            .process_name = "other",
            .source = .{ .backend = .test_backend },
        },
    };
    const source: backend.SnapshotSource = .{ .snapshot = .{ .entries = &entries } };

    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();
    var err = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer err.deinit();

    var ports: model.PortSet = .{};
    ports.add(3000);
    ports.add(4000);

    const result = try runWithScanner(source.scanner(), std.testing.allocator, std.testing.io, &out.writer, &err.writer, .{
        .port = 3000,
        .ports = ports,
        .dry_run = true,
    });

    try std.testing.expectEqual(cli.ExitCode.ok, result.code);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "127.0.0.1:3000") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "127.0.0.1:4000") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "127.0.0.1:5000") == null);
    try std.testing.expectEqual(@as(usize, 0), err.written().len);
}

test "wait for port release uses scripted scanner snapshots" {
    const pids = [_]u32{42};

    const held = [_]model.PortEntry{.{
        .protocol = .tcp,
        .local_address = .{ .ipv4 = .{ 127, 0, 0, 1 } },
        .local_port = 3000,
        .pid = 42,
        .process_name = "node",
        .source = .{ .backend = .test_backend },
    }};
    const snapshots = [_]backend.Snapshot{
        .{ .entries = &held },
        .{ .entries = &.{} },
    };
    var source: backend.ScriptedSource = .{ .snapshots = &snapshots };
    var runtime_context: RuntimeContext = .{ .scanner = source.scanner() };

    const survivors = try waitForPortRelease(&runtime_context, std.testing.io, std.testing.allocator, &pids, .{ .port = 3000, .protocol = .tcp }, 100);
    defer std.testing.allocator.free(survivors);

    try std.testing.expectEqual(@as(usize, 0), survivors.len);
    try std.testing.expectEqual(@as(usize, 2), source.index);
}

fn testEntry(pid: ?u32, name: []const u8) model.PortEntry {
    return .{
        .protocol = .tcp,
        .local_address = .{ .ipv4 = .{ 127, 0, 0, 1 } },
        .local_port = 3000,
        .pid = pid,
        .process_name = name,
        .source = .{ .backend = .test_backend },
    };
}

const FakeRuntime = struct {
    signal_result: ?anyerror = null,
    survivor: ?u32 = null,
    signal_calls: usize = 0,
    wait_calls: usize = 0,

    fn runtime(self: *FakeRuntime) KillRuntime {
        return .{
            .context = self,
            .signal = signal,
            .wait_for_release = waitForRelease,
        };
    }

    fn signal(context: *anyopaque, _: u32, _: std.posix.SIG) !void {
        const self: *FakeRuntime = @ptrCast(@alignCast(context));
        self.signal_calls += 1;
        if (self.signal_result) |err| return err;
    }

    fn waitForRelease(
        context: *anyopaque,
        _: std.Io,
        allocator: std.mem.Allocator,
        _: []const u32,
        _: model.ScanFilter,
        _: u32,
    ) ![]u32 {
        const self: *FakeRuntime = @ptrCast(@alignCast(context));
        self.wait_calls += 1;
        if (self.survivor) |pid| {
            const survivors = try allocator.alloc(u32, 1);
            survivors[0] = pid;
            return survivors;
        }
        return try allocator.alloc(u32, 0);
    }
};

fn runAttemptForTest(plan: *const TargetPlan, fake: *FakeRuntime) !cli.ExitCode {
    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();
    var err = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer err.deinit();

    return try executeAttempt(
        std.testing.allocator,
        std.testing.io,
        &out.writer,
        &err.writer,
        .{ .port = 3000, .wait_ms = 100 },
        plan.*,
        fake.runtime(),
    );
}
