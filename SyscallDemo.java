import java.util.List;

/**
 * Demo 2 - Syscall Restriction
 *
 * Shows two independent blocking layers:
 *
 * Case A - perf_event_open (syscall #298):
 *   NOT implemented by gVisor. The Sentry rejects it with ENODEV before
 *   the host kernel is ever involved. Demonstrates gVisor's reduced attack
 *   surface: an unimplemented syscall simply cannot be exploited.
 *
 * Case B - sethostname (syscall #170):
 *   IS implemented by gVisor (it maintains its own UTS namespace).
 *   Blocked explicitly via a seccomp DENY rule in config.json.
 *   Security relevance: an attacker calling sethostname could spoof
 *   hostname-based identity checks or poison service discovery.
 *   Demonstrates that seccomp fires BEFORE gVisor even sees the syscall.
 *
 * Blocking layers (in order):
 *   1. seccomp filter  -> EPERM  (fires first, before gVisor)
 *   2. gVisor Sentry   -> ENODEV (fires if no seccomp rule, syscall unimplemented)
 *   3. Host kernel     -> never reached for blocked syscalls
 */
public class SyscallDemo {

    public void run() {
        System.out.println("+------------------------------------------+");
        System.out.println("|  Demo 2: Syscall Restriction             |");
        System.out.println("|  Case A: perf_event_open (not in gVisor) |");
        System.out.println("|  Case B: sethostname     (blocked by     |");
        System.out.println("|          seccomp despite gVisor support) |");
        System.out.println("+------------------------------------------+");

        runCaseA();
        runCaseB();
    }

    // -- Case A: perf_event_open - not implemented by gVisor -----------------

    private void runCaseA() {
        System.out.println("\n  -- Case A: perf_event_open (syscall 298) --");
        System.out.println("  Historically vulnerable kernel perf API.");
        System.out.println("  gVisor does not implement it -> ENODEV.");

        String script = """
                import ctypes, os
                libc = ctypes.CDLL(None, use_errno=True)

                # Minimal perf_event_attr struct (128 bytes)
                attr = ctypes.create_string_buffer(128)
                ctypes.c_uint32.from_buffer(attr, 0).value = 0    # PERF_TYPE_HARDWARE
                ctypes.c_uint32.from_buffer(attr, 4).value = 128  # struct size
                ctypes.c_uint64.from_buffer(attr, 8).value = 0    # CPU_CYCLES

                fd  = libc.syscall(298, attr, 0, -1, -1, 0)
                err = ctypes.get_errno()

                if fd >= 0:
                    print(f'  perf_event_open -> fd={fd}   REACHED host kernel')
                    os.close(fd)
                elif err == 19:
                    print(f'  perf_event_open -> ENODEV   BLOCKED by gVisor (not implemented)')
                elif err == 1:
                    print(f'  perf_event_open -> EPERM    BLOCKED by seccomp')
                elif err == 2:
                    print(f'  perf_event_open -> ENOENT   REACHED host kernel (no hw counters)')
                else:
                    print(f'  perf_event_open -> errno={err} ({os.strerror(err)})')
                """;

        SandboxRunner.runPythonUnsandboxed("perf_event_open unsandboxed", script);
        SandboxRunner.runPythonSandboxed(  "perf_event_open sandboxed",
                script, List.of(), null, "none");
    }

    // -- Case B: sethostname - implemented by gVisor, blocked by seccomp -----

    private void runCaseB() {
        System.out.println("\n  -- Case B: sethostname (syscall 170) --");
        System.out.println("  gVisor implements it, but seccomp blocks it first.");
        System.out.println("  Attack scenario: spoof hostname-based identity checks.");

        String script = """
                import ctypes, os

                def get_hostname():
                    try:
                        return open('/proc/sys/kernel/hostname').read().strip()
                    except:
                        return '(unknown)'

                libc = ctypes.CDLL(None, use_errno=True)

                original = get_hostname()
                print(f'  hostname before: {original}')

                name = b'pwned-host'
                ret  = libc.syscall(170, name, len(name))
                err  = ctypes.get_errno()

                if ret == 0:
                    print(f'  sethostname    -> OK        hostname is now: {get_hostname()}')
                elif err == 1:
                    print(f'  sethostname    -> EPERM     BLOCKED by seccomp (hostname unchanged)')
                elif err == 19:
                    print(f'  sethostname    -> ENODEV    BLOCKED by gVisor (not implemented)')
                else:
                    print(f'  sethostname    -> errno={err} ({os.strerror(err)})')
                """;

        // Seccomp rule: block sethostname -> EPERM
        String seccomp = """
                {
                  "defaultAction": "SCMP_ACT_ALLOW",
                  "architectures": ["SCMP_ARCH_X86_64"],
                  "syscalls": [
                    {
                      "names": ["sethostname"],
                      "action": "SCMP_ACT_ERRNO",
                      "errnoRet": 1
                    }
                  ]
                }
                """;

        SandboxRunner.runPythonUnsandboxed("sethostname unsandboxed", script);
        SandboxRunner.runPythonSandboxed(  "sethostname sandboxed (seccomp blocks it)",
                script, List.of(), seccomp, "none");
    }
}