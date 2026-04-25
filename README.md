# zport

Find and kill processes using local ports.

```bash
zport 3000
zport kill 3000
```

`zport` is a tiny native alternative to reaching for `lsof`, `netstat`, `ss`,
or `kill-port` during local development.

## Build

```bash
zig build -Doptimize=ReleaseFast
cp zig-out/bin/zport ~/.local/bin/
```

Use a custom release version with:

```bash
zig build -Dversion=1.0.0 -Doptimize=ReleaseFast
```

## Usage

```bash
zport
zport 3000
zport list 3000
zport --tcp
zport --udp
zport --protocol tcp
zport --json
zport --no-header
zport kill 3000
zport kill 3000 --force
zport kill 3000 --signal INT
zport kill 3000 --dry-run
zport kill 3000 --wait 2000
```

`zport` lists listening TCP sockets and bound UDP sockets. `zport <port>` filters
to a single local port.

## Kill Behavior

`zport kill <port>` sends `SIGTERM` to each unique PID holding the requested
port, waits up to 1000ms, and exits nonzero if a targeted process is still
alive. Use `--force` or `--signal KILL` to send `SIGKILL` explicitly.

If multiple sockets or file descriptors map to the same process, `zport`
signals that PID once.

## JSON

`--json` applies to list-style commands only:

```bash
zport --json
zport 3000 --json
```

Kill commands are intentionally human-readable because they have side effects.

## Platform Notes

macOS:

```text
zport uses libproc to inspect process file descriptors and socket metadata.
Some processes may be hidden unless run with sufficient permissions.
```

Linux:

```text
zport parses /proc/net/{tcp,tcp6,udp,udp6}, then maps socket inodes
to processes by scanning /proc/<pid>/fd.
Some systems mount /proc with restrictions such as hidepid.
```

## Exit Codes

| Code | Meaning |
| ---: | --- |
| 0 | Success |
| 1 | No matching port/process found |
| 2 | CLI usage error |
| 3 | Permission failure for requested kill |
| 4 | Unsupported platform |
| 5 | Backend/runtime/still-alive failure |
