#!/usr/bin/env python3
import json
import os
import socket
import subprocess
import sys
import tempfile
import textwrap
import time


class SmokeFailure(Exception):
    pass


def fail(message, result=None):
    details = [message]
    if result is not None:
        details.append(f"exit={result.returncode}")
        if result.stdout:
            details.append(f"stdout:\n{result.stdout}")
        if result.stderr:
            details.append(f"stderr:\n{result.stderr}")
    raise SmokeFailure("\n".join(details))


def require(condition, message):
    if not condition:
        fail(message)


def run_zport(zport, *args, check=True, timeout=5):
    result = subprocess.run(
        [zport, *args],
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        fail(f"zport {' '.join(args)} failed", result)
    return result


def json_entries(result):
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as err:
        fail(f"invalid JSON output: {err}", result)
    return payload.get("entries", [])


def has_entry(entries, *, protocol, port, pid=None):
    for entry in entries:
        if entry.get("protocol") != protocol:
            continue
        if entry.get("local_port") != port:
            continue
        if entry.get("local_address") != "127.0.0.1":
            continue
        if pid is not None and entry.get("pid") != pid:
            continue
        return True
    return False


def wait_for_entry(zport, *, protocol, port, pid=None, timeout=5):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = run_zport(zport, str(port), "--json", check=False)
        if last.returncode == 0 and has_entry(json_entries(last), protocol=protocol, port=port, pid=pid):
            return
        time.sleep(0.1)
    fail(f"timed out waiting for {protocol} entry on port {port}", last)


def with_tcp_listener(callback):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        callback(sock.getsockname()[1])
    finally:
        sock.close()


def with_udp_socket(callback):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        callback(sock.getsockname()[1])
    finally:
        sock.close()


CHILD_LISTENER = textwrap.dedent(
    r"""
    import os
    import socket
    import sys
    import time

    protocol = sys.argv[1]
    port_file = sys.argv[2]

    if protocol == "tcp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
    elif protocol == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
    else:
        raise SystemExit(f"unknown protocol: {protocol}")

    with open(port_file, "w", encoding="utf-8") as handle:
        handle.write(str(sock.getsockname()[1]))
        handle.flush()

    while True:
        time.sleep(1)
    """
)


def start_child_listener(protocol):
    temp = tempfile.TemporaryDirectory()
    port_file = os.path.join(temp.name, "port")
    process = subprocess.Popen(
        [sys.executable, "-c", CHILD_LISTENER, protocol, port_file],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stderr = process.stderr.read() if process.stderr is not None else ""
            temp.cleanup()
            fail(f"child listener exited early with {process.returncode}\nstderr:\n{stderr}")
        if os.path.exists(port_file):
            with open(port_file, "r", encoding="utf-8") as handle:
                content = handle.read().strip()
            if content:
                return process, int(content), temp
        time.sleep(0.05)
    cleanup_child(process)
    temp.cleanup()
    fail(f"timed out waiting for child {protocol} listener")


def cleanup_child(process):
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def test_table_and_json(zport):
    def check_tcp(port):
        table = run_zport(zport, str(port))
        require(f"127.0.0.1:{port}" in table.stdout, "table output did not include TCP listener")
        require("tcp" in table.stdout, "table output did not mark TCP listener")

        tcp = run_zport(zport, str(port), "--tcp", "--json")
        tcp_entries = json_entries(tcp)
        require(has_entry(tcp_entries, protocol="tcp", port=port, pid=os.getpid()), "--tcp JSON did not include TCP listener")
        require(all(entry.get("protocol") == "tcp" for entry in tcp_entries), "--tcp JSON included non-TCP entries")

        udp_miss = run_zport(zport, str(port), "--udp", "--json", check=False)
        require(udp_miss.returncode == 1, "--udp should not match a TCP-only port")

    def check_udp(port):
        udp = run_zport(zport, str(port), "--udp", "--json")
        udp_entries = json_entries(udp)
        require(has_entry(udp_entries, protocol="udp", port=port, pid=os.getpid()), "--udp JSON did not include UDP socket")
        require(all(entry.get("protocol") == "udp" for entry in udp_entries), "--udp JSON included non-UDP entries")

        tcp_miss = run_zport(zport, str(port), "--tcp", "--json", check=False)
        require(tcp_miss.returncode == 1, "--tcp should not match a UDP-only port")

    with_tcp_listener(check_tcp)
    with_udp_socket(check_udp)


def test_kill(zport):
    process, port, temp = start_child_listener("tcp")
    try:
        wait_for_entry(zport, protocol="tcp", port=port, pid=process.pid)

        dry_run = run_zport(zport, "kill", str(port), "--dry-run")
        require(str(process.pid) in dry_run.stdout, "dry-run output did not include child PID")
        require(process.poll() is None, "dry-run terminated the child process")

        killed = run_zport(zport, "kill", str(port), "--wait", "3000", timeout=8)
        require(killed.returncode == 0, "kill command failed")
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            fail("child process was still running after zport kill", killed)
        require(process.returncode is not None, "child process did not exit after zport kill")
    finally:
        cleanup_child(process)
        temp.cleanup()


def main():
    if len(sys.argv) != 2:
        print("usage: smoke.py /path/to/zport", file=sys.stderr)
        return 2

    zport = os.path.abspath(sys.argv[1])
    if not os.path.exists(zport):
        print(f"zport binary not found: {zport}", file=sys.stderr)
        return 2

    try:
        test_table_and_json(zport)
        test_kill(zport)
    except SmokeFailure as err:
        print(err, file=sys.stderr)
        return 1

    print("smoke tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
