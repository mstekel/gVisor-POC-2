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
