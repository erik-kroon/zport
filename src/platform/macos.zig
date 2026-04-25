const std = @import("std");
const model = @import("../model.zig");
const c = @import("macos_c");

pub fn scan(allocator: std.mem.Allocator, _: std.Io, filter_hint: model.ScanFilter) !model.ScanResult {
    var entries: std.ArrayList(model.PortEntry) = .empty;
    var stats: model.ScanStats = .{};
    errdefer {
        for (entries.items) |entry| {
            if (entry.process_name) |name| allocator.free(name);
        }
        entries.deinit(allocator);
    }

    const needed = c.proc_listpids(c.PROC_ALL_PIDS, 0, null, 0);
    if (needed <= 0) return error.RuntimeFailure;
    const pid_cap: usize = @intCast(@divTrunc(needed, @sizeOf(c_int)) + 128);
    const pids = try allocator.alloc(c_int, pid_cap);
    defer allocator.free(pids);

    const returned = c.proc_listpids(c.PROC_ALL_PIDS, 0, pids.ptr, @intCast(pids.len * @sizeOf(c_int)));
    if (returned <= 0) return error.RuntimeFailure;
    const pid_count: usize = @intCast(@divTrunc(returned, @sizeOf(c_int)));

    for (pids[0..@min(pid_count, pids.len)]) |pid| {
        if (pid <= 0) continue;
        try scanPid(allocator, pid, filter_hint, &entries, &stats);
    }

    const owned = try entries.toOwnedSlice(allocator);
    return .{ .allocator = allocator, .entries = owned, .stats = stats };
}

fn scanPid(
    allocator: std.mem.Allocator,
    pid: c_int,
    filter_hint: model.ScanFilter,
    entries: *std.ArrayList(model.PortEntry),
    stats: *model.ScanStats,
) !void {
    const fd_bytes = c.proc_pidinfo(pid, c.PROC_PIDLISTFDS, 0, null, 0);
    if (fd_bytes < 0) {
        stats.skipped_processes += 1;
        stats.permission_errors += 1;
        return;
    }
    if (fd_bytes == 0) {
        return;
    }

    const fd_count: usize = @intCast(@divTrunc(fd_bytes, @sizeOf(c.struct_proc_fdinfo)));
    if (fd_count == 0) return;
    const fds = try allocator.alloc(c.struct_proc_fdinfo, fd_count);
    defer allocator.free(fds);

    const actual_bytes = c.proc_pidinfo(pid, c.PROC_PIDLISTFDS, 0, fds.ptr, fd_bytes);
    if (actual_bytes < 0) {
        stats.skipped_processes += 1;
        stats.permission_errors += 1;
        return;
    }
    if (actual_bytes == 0) {
        return;
    }
    const actual_count: usize = @intCast(@divTrunc(actual_bytes, @sizeOf(c.struct_proc_fdinfo)));

    var process_name: ?[]const u8 = null;
    defer if (process_name) |name| allocator.free(name);

    for (fds[0..@min(actual_count, fds.len)]) |fd| {
        if (fd.proc_fdtype != c.PROX_FDTYPE_SOCKET) continue;
        var socket_info: c.struct_socket_fdinfo = undefined;
        const info_bytes = c.proc_pidfdinfo(pid, fd.proc_fd, c.PROC_PIDFDSOCKETINFO, &socket_info, @sizeOf(c.struct_socket_fdinfo));
        if (info_bytes < @sizeOf(c.struct_socket_fdinfo)) {
            stats.skipped_fds += 1;
            continue;
        }
        const entry = socketEntryFromInfo(socket_info, pid, fd.proc_fd) orelse continue;
        if (!filter_hint.matches(entry)) continue;

        if (process_name == null) process_name = try readProcessName(allocator, pid);
        var owned = entry;
        owned.process_name = if (process_name) |name| try allocator.dupe(u8, name) else null;
        try entries.append(allocator, owned);
    }
}

fn socketEntryFromInfo(info: c.struct_socket_fdinfo, pid: c_int, fd: c_int) ?model.PortEntry {
    const socket = info.psi;
    if (socket.soi_kind == c.SOCKINFO_TCP) {
        const tcp = socket.soi_proto.pri_tcp;
        if (tcp.tcpsi_state != c.TSI_S_LISTEN) return null;
        return entryFromInSock(.tcp, tcp.tcpsi_ini, pid, fd, tcp.tcpsi_state);
    }

    if (socket.soi_kind == c.SOCKINFO_IN and socket.soi_protocol == c.IPPROTO_UDP) {
        return entryFromInSock(.udp, socket.soi_proto.pri_in, pid, fd, null);
    }
    return null;
}

fn entryFromInSock(protocol: model.Protocol, info: c.struct_in_sockinfo, pid: c_int, fd: c_int, raw_state: ?c_int) ?model.PortEntry {
    const port = networkPortToHost(info.insi_lport);
    if (port == 0) return null;
    const address = decodeAddress(info) orelse return null;
    return .{
        .protocol = protocol,
        .local_address = address,
        .local_port = port,
        .pid = @intCast(pid),
        .process_name = null,
        .source = .{
            .backend = .macos_libproc,
            .fd = @intCast(fd),
            .raw_state = if (raw_state) |state| @intCast(state) else null,
        },
    };
}

fn networkPortToHost(port: c_int) u16 {
    return std.mem.bigToNative(u16, @as(u16, @intCast(port & 0xffff)));
}

fn decodeAddress(info: c.struct_in_sockinfo) ?model.IpAddress {
    if ((info.insi_vflag & c.INI_IPV4) != 0) {
        var bytes: [4]u8 = undefined;
        const source = std.mem.asBytes(&info.insi_laddr.ina_46.i46a_addr4.s_addr);
        @memcpy(&bytes, source[0..4]);
        return .{ .ipv4 = bytes };
    }
    if ((info.insi_vflag & c.INI_IPV6) != 0) {
        var bytes: [16]u8 = undefined;
        const source = std.mem.asBytes(&info.insi_laddr.ina_6);
        @memcpy(&bytes, source[0..16]);
        return .{ .ipv6 = bytes };
    }
    return null;
}

fn readProcessName(allocator: std.mem.Allocator, pid: c_int) !?[]const u8 {
    var buf: [1024]u8 = undefined;
    const len = c.proc_name(pid, &buf, buf.len);
    if (len <= 0) return null;
    return try allocator.dupe(u8, buf[0..@intCast(len)]);
}
