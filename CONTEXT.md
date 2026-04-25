# zport Context

zport is a local development command for finding and terminating processes that
hold local ports.

## Domain Terms

**Local port** - A TCP or UDP port bound on the local machine. Users can list all
local ports or filter to one local port.

**Protocol** - The transport protocol for a local port. zport currently supports
TCP listeners and bound UDP sockets.

**Socket candidate** - A platform-discovered socket that may become a port
entry. On Linux, socket candidates come from `/proc/net/{tcp,tcp6,udp,udp6}` and
may not yet be mapped to a process.

**Port entry** - A normalized local port record returned by a scan. It includes
protocol, local address, local port, optional PID, optional process name, and
internal backend metadata.

**Scan filter** - The requested local port and protocol constraints applied while
building port entries.

**Scan result** - The complete output of a scan: sorted port entries plus scan
diagnostics.

**Scan diagnostics** - Non-fatal gaps discovered while scanning, such as
permission-denied processes, permission-denied file descriptors, or malformed
platform socket rows.

**Kill target** - A unique PID selected from matching port entries for a kill
command. Multiple socket entries can map to one kill target.

**Kill attempt** - The signal delivery and post-signal verification for kill
targets on a requested local port.

**Backend metadata** - Platform-specific scan facts such as Linux socket inode,
macOS file descriptor, or raw socket state. This metadata is for internal
diagnostics and should not be treated as user-facing JSON output.
