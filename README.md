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
java Main filesystem        # Demo 1: restrict writes to one folder
java Main syscall           # Demo 2: block perf_event_open (vulnerable kernel API)
sudo java Main network      # Demo 3: block all network access (needs root)
```

Demo 3 requires `sudo` because it creates a network namespace, a veth pair, and iptables rules.
Demos 1 and 2 run as an ordinary user.

## What each demo shows

### Demo 1 — Filesystem
- **Unsandboxed**: writes to `data/` and `/tmp` both succeed
- **Sandboxed**: only `/sandbox-data` (mapped to `data/`) is writable; writes to `/tmp` and `/usr` are blocked

### Demo 2 — Syscall (perf_event_open)
- **Unsandboxed**: `perf_event_open` reaches the kernel (returns ENOENT — no hw counters in container, but the syscall was reachable)
- **Sandboxed**: seccomp filter returns EPERM immediately — the syscall never touches the host kernel

`perf_event_open` has been the entry point for multiple local privilege escalation CVEs (CVE-2013-2094, CVE-2016-6786, and others).

### Demo 3 — Network
- **Unsandboxed**: connects to localhost echo server and attempts external IP
- **Sandboxed**: `--network=none` blocks all socket operations with ENETDOWN

## Requirements

- Linux host with gVisor (`runsc`) installed
- Python 3.12
- JDK 17+
- Root (via `sudo`) for Demo 3 only — needed to create the netns, veth pair, and iptables rules

### Sandbox platform

The demos launch `runsc` with `--platform=systrap` (gVisor's modern default), which nests
reliably inside containers. See Troubleshooting below if you switch platforms.

### Running inside Docker

The demos run on bare metal as-is. Inside a Docker container they need extra capabilities and,
for Demo 3, extra packages. This command runs all three demos without `--privileged`:

```bash
docker run --name ubuntu \
  --cap-add=SYS_ADMIN --cap-add=NET_ADMIN \
  --security-opt seccomp=unconfined \
  -it <image>
```

- `SYS_ADMIN` lets `runsc` fork its sandbox processes — without it Demos 1 & 2 fail with
  `fork/exec /proc/self/exe: operation not permitted`.
- `NET_ADMIN` lets Demo 3 create the netns, veth pair, and iptables rules and write
  `/proc/sys/net/ipv4/ip_forward`. Demos 1 & 2 don't need it.
- `seccomp=unconfined` lets the sandbox make the syscalls it needs.
- `SYS_PTRACE` is **not** required with the `systrap` platform.

`--privileged` also works but grants more than necessary.

**Demo 3** additionally needs `ip` and `iptables` installed. On Debian/Ubuntu images:

```bash
apt-get update && apt-get install -y iproute2 iptables
```

(RHEL/UBI: `dnf install -y iproute iptables`.) Bake these into your Dockerfile so they survive
container removal. Without them `setup-netns.sh` fails with `command not found`, the netns is
never created, and the sandboxed run reports everything BLOCKED — a false pass.

### Troubleshooting

**`cannot read client sync file: waiting for sandbox to start: EOF`** — the sandbox boot
process died. Two common causes:

- A **bind-mount source that doesn't exist** on the host. gVisor aborts the whole sandbox if
  any bind source is missing (e.g. minimal images with no `/etc/localtime`). Demo 1 now skips
  the `/etc/localtime` mount automatically when the host lacks it. To diagnose other cases, add
  `--debug --debug-log=/tmp/rd/` to the `runsc` invocation and read `/tmp/rd/*boot*`.
- The deprecated **`--platform=ptrace`** failing to nest inside a container. The demos use
  `--platform=systrap` for this reason; if you change it, update both `SandboxRunner.java` and
  `NetworkDemo.java`.
