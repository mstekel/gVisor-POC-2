# gVisor Sandbox Demo

Three self-contained demos showing what gVisor can restrict.

## Setup

```bash
# Compile all sources
javac *.java

# Create the data folder used by Demo 1
mkdir -p data
```

## Running

```bash
java Main filesystem        # Demo 1: restrict writes to one folder / file
java Main syscall           # Demo 2: an unimplemented syscall + a seccomp-denied one
java Main network           # Demo 3: no network + one Unix-domain socket channel
```

**All three demos run rootless, as an ordinary user — no `sudo` or root needed.** `runsc` is
invoked as a bare command, so it must be on `PATH` (it's usually installed in `/usr/local/bin`,
which is normally already on an ordinary user's `PATH`).

## What each demo shows

### Demo 1 — Filesystem
- **Unsandboxed**: writes to `data/` and `/tmp` both succeed
- **Sandboxed**: only `/sandbox-data` (mapped to `data/`) is writable; writes to `/tmp` and `/usr` are blocked
- **Read-only vs hidden**: `/sandbox-data/readonly.txt` is exposed via a per-file read-only bind mount — it can be *read* but not *written* (`BLOCKED` on write) even though its parent directory `/sandbox-data` is writable, while `/etc/passwd` is hidden entirely (`FileNotFoundError`) — three distinct kinds of access: writable, read-only, and hidden

### Demo 2 — Syscall (perf_event_open)
- **Unsandboxed**: `perf_event_open` reaches the kernel (returns ENOENT — no hw counters in container, but the syscall was reachable)
- **Sandboxed**: seccomp filter returns EPERM immediately — the syscall never touches the host kernel

`perf_event_open` has been the entry point for multiple local privilege escalation CVEs (CVE-2013-2094, CVE-2016-6786, and others).

### Demo 3 — Network (no network + one Unix socket)
- **Unsandboxed**: connects to the parent's **Unix-domain echo socket** (OK) *and* an external TCP connection (`8.8.8.8:53`) succeeds — the host has full network.
- **Sandboxed** (`--network=none`): connects to the **one bind-mounted Unix socket** (OK, via `--host-uds=open`), but every IP operation is blocked by gVisor (`ENETUNREACH`).

The sandbox has *no* network stack. Its only channel out is a single Unix-domain socket — the parent's echo server — exposed by bind-mounting just that socket and allowing host-UDS access. The sandboxed workload's `stdin`/`stdout`/`stderr` stay completely free for its own use (the channel is an explicitly-opened `AF_UNIX` socket, not a hijacked standard stream). There is no veth, netns, or iptables: the isolation is enforced by gVisor itself, the demo runs **rootless**, needs no `sudo`/`CAP_SYS_ADMIN`, and touches nothing on the host *network* (the socket is a filesystem path, not a network endpoint).

## Requirements

- Linux host with gVisor (`runsc`) installed
- Python 3 (3.12 recommended)
- JDK 17+
- All three demos run **rootless** (ordinary user) — no root, `sudo`, `iproute2`/`iptables`, or network setup

### Sandbox platform

The demos launch `runsc` with `--platform=systrap` (gVisor's modern default), which nests
reliably inside containers. See Troubleshooting below if you switch platforms.

### Running inside Docker

The demos run on bare metal as-is. Inside a Docker container they need one extra capability for
`runsc` to fork its sandbox processes. This command runs **all three** demos without `--privileged`:

```bash
docker run --name gvisor-demo \
  --cap-add=SYS_ADMIN \
  --security-opt seccomp=unconfined \
  -it <image>
```

- `SYS_ADMIN` lets `runsc` fork its sandbox processes — without it the sandboxed runs fail with
  `fork/exec /proc/self/exe: operation not permitted`.
- `seccomp=unconfined` lets the sandbox make the syscalls it needs.
- `SYS_PTRACE` and `NET_ADMIN` are **not** required — Demo 3 no longer uses a network namespace,
  so no `iproute2`/`iptables` packages or `NET_ADMIN` are needed either.

`--privileged` also works but grants more than necessary. On a Kubernetes node, also ensure
unprivileged user namespaces are allowed (e.g. on Ubuntu 24.04:
`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`).

### Troubleshooting

**`cannot read client sync file: waiting for sandbox to start: EOF`** — the sandbox boot
process died. Two common causes:

- A **bind-mount source that doesn't exist** on the host. gVisor aborts the whole sandbox if
  any bind source is missing (e.g. binding `/etc/localtime` on a minimal image that ships
  without it). Make sure every bind-mount source in the OCI config exists on the host. To
  diagnose, add `--debug --debug-log=/tmp/rd/` to the `runsc` invocation and read
  `/tmp/rd/*boot*`.
- The deprecated **`--platform=ptrace`** failing to nest inside a container. The demos use
  `--platform=systrap` for this reason; if you change it, update both `SandboxRunner.java` and
  `NetworkDemo.java`.
