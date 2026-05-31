import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * Shared utilities for building and running gVisor OCI sandboxes.
 */
public class SandboxRunner {

    // - Public API -

    /**
     * Run a command unsandboxed (plain OS process).
     */
    public static void runUnsandboxed(String label, String... cmd) {
        System.out.println("\n\n\n[UNSANDBOXED] " + label);
        exec(cmd);
    }

    /**
     * Run a Python script unsandboxed.
     */
    public static void runPythonUnsandboxed(String label, String script) {
        runUnsandboxed(label, "python3", "-c", script);
    }

    /**
     * Run a Python script inside a gVisor OCI sandbox.
     *
     * @param label       display label
     * @param script      Python source to execute
     * @param extraMounts additional OCI mounts (raw JSON array elements)
     * @param seccomp     seccomp JSON block, or null for no syscall filtering
     * @param networkMode "none" | "sandbox" | "host"
     */
    public static void runPythonSandboxed(
            String label,
            String script,
            List<String> extraMounts,
            String seccomp,
            String networkMode
    ) {
        System.out.println("\n\n\n[SANDBOXED]   " + label);
        try {
            long pid       = ProcessHandle.current().pid();
            String tmpRoot = "/tmp/runsc-root-" + pid;
            String bundle  = "/tmp/bundle-" + pid + "-" + System.nanoTime();
            String rootfs  = bundle + "/rootfs";

            // Create rootfs stub directories
            for (String d : new String[]{
                    "usr", "lib", "lib64", "bin", "etc",
                    "proc", "sys", "dev", "tmp"}) {
                new File(rootfs + "/" + d).mkdirs();
            }
            new File(tmpRoot).mkdirs();

            String config = buildConfig(script, extraMounts, seccomp, networkMode);
            Files.writeString(Path.of(bundle + "/config.json"), config);

            // DEBUG: capture the sandbox boot log to diagnose startup failures.
            String debugLog = "/tmp/runsc-debug-" + pid + "/";
            new File(debugLog).mkdirs();
            System.out.println("  [debug log dir: " + debugLog + "]");

            String containerId = "sandbox-" + pid + "-" + System.nanoTime();
            exec("runsc",
                    "--root",           tmpRoot,
                    "--rootless",
                    "--ignore-cgroups",
                    "--platform=systrap",
                    "--network=none",   // overridden per-demo via config namespaces
                    "--debug",
                    "--debug-log",      debugLog,
                    "--strace",
                    "run",
                    "--bundle", bundle,
                    containerId);

        } catch (Exception e) {
            System.out.println("  Setup error: " + e.getMessage());
        }
    }

    // - OCI config.json builder -

    private static String buildConfig(
            String script,
            List<String> extraMounts,
            String seccomp,
            String networkMode
    ) {
        String escapedScript = escapeJson(script);

        // Standard read-only system mounts every sandbox needs to run Python.
        // /etc is intentionally NOT mounted by default — demos that need host
        // config (e.g. NetworkDemo for /etc/resolv.conf) bind it via extraMounts.
        List<String> mounts = new ArrayList<>(List.of(
                mount("/usr",  "/usr",  "bind", "rbind,ro"),
                mount("/lib",  "/lib",  "bind", "rbind,ro"),
                mount("/lib64","/lib64","bind", "rbind,ro"),
                mount("/bin",  "/bin",  "bind", "rbind,ro"),
                """
                {"destination":"/proc","type":"proc","source":"proc","options":[]},
                {"destination":"/dev","type":"tmpfs","source":"tmpfs","options":["mode=755"]},
                {"destination":"/tmp","type":"tmpfs","source":"tmpfs","options":["mode=555","ro"]},
                {"destination":"/sys","type":"sysfs","source":"sysfs","options":["ro"]}
                """
        ));
        mounts.addAll(extraMounts);

        // Network namespace: include "network" type only when sandbox networking needed
        String netNs = networkMode.equals("none") ? "" :
                """
                ,{ "type": "network" }
                """;

        String seccompBlock = (seccomp != null) ?
                "\"seccomp\": " + seccomp + "," : "";

        return """
                {
                  "ociVersion": "1.0.0",
                  "hostname": "sandbox",
                  "process": {
                    "terminal": false,
                    "user": { "uid": 0, "gid": 0 },
                    "args": ["python3", "-c", "%s"],
                    "env": [
                      "PATH=/usr/bin:/usr/local/bin:/bin",
                      "HOME=/tmp",
                      "PYTHONPATH=/usr/lib/python3.12:/usr/lib/python3"
                    ],
                    "cwd": "/tmp"
                  },
                  "root": { "path": "rootfs", "readonly": true },
                  "mounts": [%s],
                  "linux": {
                    %s
                    "namespaces": [
                      { "type": "pid"   },
                      { "type": "mount" },
                      { "type": "ipc"   },
                      { "type": "uts"   }
                      %s
                    ]
                  }
                }
                """.formatted(
                escapedScript,
                String.join(",", mounts),
                seccompBlock,
                netNs);
    }

    // - Helpers -

    static String mount(String dest, String src, String type, String options) {
        String[] opts = options.split(",");
        StringBuilder arr = new StringBuilder("[");
        for (int i = 0; i < opts.length; i++) {
            arr.append("\"").append(opts[i].trim()).append("\"");
            if (i < opts.length - 1) arr.append(",");
        }
        arr.append("]");
        return "{\"destination\":\"%s\",\"type\":\"%s\",\"source\":\"%s\",\"options\":%s}"
                .formatted(dest, type, src, arr);
    }

    static String escapeJson(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    static void exec(String... cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(p.getInputStream()))) {
                r.lines().map(line -> "  " + line).forEach(System.out::println);
            }
            int exit = p.waitFor();
            if (exit != 0)
                System.out.println("  [exit code " + exit + "]");
        } catch (Exception e) {
            System.out.println("  exec error: " + e.getMessage());
        }
    }
}