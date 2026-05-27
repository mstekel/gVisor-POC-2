import java.util.List;

/**
 * Demo 2 - Syscall Restriction (perf_event_open)
 *
 * perf_event_open (syscall #298 on x86_64) opens a file descriptor for
 * performance monitoring. It has a long history of kernel vulnerabilities
 * (CVE-2011-2517, CVE-2013-2094 "perf_swevent", CVE-2016-6786, and others)
 * and is a common first step in local privilege escalation exploits.
 *
 * Unsandboxed: perf_event_open returns a valid fd (or ENOENT in a container
 *              without hardware counters) - the syscall is reachable.
 * Sandboxed:   gVisor's seccomp filter returns EPERM - the syscall is blocked
 *              before it ever touches the host kernel.
 */
public class SyscallDemo {

    public void run() {
        System.out.println("+------------------------------------------+");
        System.out.println("|  Demo 2: Syscall Restriction             |");
        System.out.println("|  Blocking: perf_event_open (syscall 298) |");
        System.out.println("+------------------------------------------+");
        System.out.println("perf_event_open is a historically vulnerable kernel API.");
        System.out.println("Sandboxed process will be blocked from calling it.");

        String script = """
                import ctypes, ctypes.util, os

                libc = ctypes.CDLL(None, use_errno=True)

                # Build a minimal perf_event_attr struct (128 bytes):
                #   offset 0: type   (uint32) = 0  PERF_TYPE_HARDWARE
                #   offset 4: size   (uint32) = 128
                #   offset 8: config (uint64) = 0  PERF_COUNT_HW_CPU_CYCLES
                attr = ctypes.create_string_buffer(128)
                ctypes.c_uint32.from_buffer(attr, 0).value = 0    # PERF_TYPE_HARDWARE
                ctypes.c_uint32.from_buffer(attr, 4).value = 128  # struct size
                ctypes.c_uint64.from_buffer(attr, 8).value = 0    # CPU_CYCLES

                SYS_perf_event_open = 298
                fd = libc.syscall(SYS_perf_event_open, attr, 0, -1, -1, 0)
                err = ctypes.get_errno()

                REACHED = 'syscall REACHED the host kernel'
                BLOCKED = 'syscall BLOCKED - never reached host kernel'

                if fd >= 0:
                    # Got a real file descriptor - kernel accepted the call
                    print(f'  perf_event_open -> fd={fd}  ({REACHED})')
                    os.close(fd)
                elif err == 1:    # EPERM  - seccomp denied it
                    print(f'  perf_event_open -> EPERM   ({BLOCKED} - seccomp filter)')
                elif err == 19:   # ENODEV - gVisor intercepted, not implemented in gVisor
                    print(f'  perf_event_open -> ENODEV  ({BLOCKED} - gVisor does not implement this syscall)')
                elif err == 38:   # ENOSYS - syscall not known at all
                    print(f'  perf_event_open -> ENOSYS  ({BLOCKED} - syscall not available)')
                elif err == 2:    # ENOENT - reached kernel, no hw counters in container
                    print(f'  perf_event_open -> ENOENT  ({REACHED}, but no hardware counters here)')
                elif err == 22:   # EINVAL - reached kernel, invalid args
                    print(f'  perf_event_open -> EINVAL  ({REACHED})')
                else:
                    print(f'  perf_event_open -> errno={err} ({os.strerror(err)})')
                """;

        // - Unsandboxed -
        SandboxRunner.runPythonUnsandboxed(
                "Call perf_event_open directly", script);

        // - Sandboxed - seccomp blocks perf_event_open -
        // OCI seccomp profile: default action = SCMP_ACT_ALLOW,
        // but perf_event_open (298) -> SCMP_ACT_ERRNO(EPERM)
        String seccomp = """
                {
                  "defaultAction": "SCMP_ACT_ALLOW",
                  "architectures": ["SCMP_ARCH_X86_64"],
                  "syscalls": [
                    {
                      "names": ["perf_event_open"],
                      "action": "SCMP_ACT_ERRNO",
                      "errnoRet": 1
                    }
                  ]
                }
                """;

        SandboxRunner.runPythonSandboxed(
                "Call perf_event_open (blocked by seccomp)",
                script,
                List.of(),  // no extra mounts needed
                seccomp,
                "none"
        );
    }
}