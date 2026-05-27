import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.List;
import java.util.concurrent.*;

/**
 * Demo 3 - Network Restriction (veth + iptables)
 *
 * Architecture:
 *
 *   Host side                        Sandbox side (netns: gvisor-demo-ns)
 *   ---------                        ------------
 *   veth-host @ 10.0.0.1  <------>  veth-sb @ 10.0.0.2
 *
 *   Java echo server @ 0.0.0.0:19876
 *
 *   iptables:
 *     ALLOW  sandbox -> 10.0.0.1:19876  (echo server)
 *     DROP   sandbox -> everything else (blocks external internet)
 *
 * Unsandboxed: uses 127.0.0.1 (veth not yet set up) + 8.8.8.8 - both succeed.
 * Sandboxed:   uses 10.0.0.1 (host veth) - succeeds.
 *              uses 8.8.8.8  (external)  - blocked by iptables DROP.
 */
public class NetworkDemo {

    private static final String LOOPBACK_IP   = "127.0.0.1";
    private static final String HOST_IP       = "10.0.0.1";
    private static final String EXTERNAL_IP   = "8.8.8.8";
    private static final int    ECHO_PORT     = 19876;
    private static final int    EXTERNAL_PORT = 53;
    private static final int    TIMEOUT_MS    = 3000;
    private static final String NETNS_NAME    = "gvisor-demo-ns";
    private static final String SETUP_SCRIPT  = "./setup-netns.sh";

    public void run() throws Exception {
        System.out.println("+------------------------------------------+");
        System.out.println("|  Demo 3: Network Restriction             |");
        System.out.println("|  Sandbox: veth only, external blocked    |");
        System.out.println("+------------------------------------------+");
        System.out.println("Sandbox may only reach 10.0.0.1 (host veth).");
        System.out.println("External traffic is dropped by iptables.");

        ExecutorService serverPool = Executors.newSingleThreadExecutor();
        ServerSocket serverSocket  = startEchoServer(serverPool);

        try {
            // -- Unsandboxed --------------------------------------------------
            // Veth not set up yet, so reach echo server via 127.0.0.1.
            // Also test external to show full unrestricted access.
            SandboxRunner.runPythonUnsandboxed(
                    "Connect to echo server (127.0.0.1) and external IP",
                    buildUnsandboxedScript());

            // -- Sandboxed ----------------------------------------------------
            // Set up veth + iptables, then run sandbox pinned to that netns.
            setupNetns();
            try {
                runSandboxed(buildSandboxedScript());
            } finally {
                destroyNetns();
            }

        } finally {
            serverSocket.close();
            serverPool.shutdownNow();
        }
    }

    // -- Network namespace setup ----------------------------------------------

    private void setupNetns() {
        System.out.println("\n[netns] Setting up veth pair and iptables rules...");
        SandboxRunner.exec("bash", SETUP_SCRIPT, NETNS_NAME, "create");
    }

    private void destroyNetns() {
        System.out.println("\n[netns] Tearing down...");
        SandboxRunner.exec("bash", SETUP_SCRIPT, NETNS_NAME, "destroy");
    }

    // -- Sandboxed run --------------------------------------------------------

    private void runSandboxed(String script) throws Exception {
        long   pid     = ProcessHandle.current().pid();
        String tmpRoot = "/tmp/runsc-root-" + pid;
        String bundle  = "/tmp/bundle-net-" + pid;
        String rootfs  = bundle + "/rootfs";

        for (String d : new String[]{
                "usr","lib","lib64","bin","etc","proc","sys","dev","tmp"}) {
            new File(rootfs + "/" + d).mkdirs();
        }
        new File(tmpRoot).mkdirs();

        String netnsPath = "/var/run/netns/" + NETNS_NAME;
        String config    = buildNetworkConfig(script, netnsPath);
        Files.writeString(Path.of(bundle + "/config.json"), config);

        System.out.println("\n[SANDBOXED]   Connect via veth (allowed) and external (blocked)");
        SandboxRunner.exec(
                "runsc",
                "--root",           tmpRoot,
                "--ignore-cgroups",
                "--platform=ptrace",
                "run",
                "--bundle", bundle,
                "sandbox-net-" + pid);
    }

    // -- OCI config with pinned network namespace -----------------------------

    private String buildNetworkConfig(String script, String netnsPath) {
        String escaped = SandboxRunner.escapeJson(script);
        return """
                {
                  "ociVersion": "1.0.0",
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
                  "mounts": [
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    {"destination":"/proc","type":"proc","source":"proc","options":[]},
                    {"destination":"/dev","type":"tmpfs","source":"tmpfs","options":["mode=755"]},
                    {"destination":"/tmp","type":"tmpfs","source":"tmpfs","options":["mode=555","ro"]},
                    {"destination":"/sys","type":"sysfs","source":"sysfs","options":["ro"]}
                  ],
                  "linux": {
                    "namespaces": [
                      { "type": "pid"   },
                      { "type": "mount" },
                      { "type": "ipc"   },
                      { "type": "uts"   },
                      { "type": "network", "path": "%s" }
                    ]
                  }
                }
                """.formatted(
                escaped,
                SandboxRunner.mount("/usr",   "/usr",   "bind", "rbind,ro"),
                SandboxRunner.mount("/lib",   "/lib",   "bind", "rbind,ro"),
                SandboxRunner.mount("/lib64", "/lib64", "bind", "rbind,ro"),
                SandboxRunner.mount("/bin",   "/bin",   "bind", "rbind,ro"),
                SandboxRunner.mount("/etc",   "/etc",   "bind", "rbind,ro"),
                netnsPath);
    }

    // -- Echo server ----------------------------------------------------------

    private ServerSocket startEchoServer(ExecutorService pool) throws IOException {
        ServerSocket ss = new ServerSocket(ECHO_PORT, 10,
                InetAddress.getByName("0.0.0.0"));
        pool.submit(() -> {
            while (!ss.isClosed()) {
                try {
                    Socket client = ss.accept();
                    new Thread(() -> {
                        try (client;
                             var in  = new BufferedReader(
                                     new InputStreamReader(client.getInputStream()));
                             var out = new PrintWriter(
                                     client.getOutputStream(), true)) {
                            String line;
                            while ((line = in.readLine()) != null)
                                out.println("ECHO: " + line);
                        } catch (IOException ignored) {}
                    }).start();
                } catch (IOException ignored) {}
            }
        });
        System.out.println("\n  [Echo server listening on 0.0.0.0:" + ECHO_PORT + "]");
        return ss;
    }

    // -- Python scripts -------------------------------------------------------

    /** Unsandboxed: reach echo server via loopback, then try external. */
    private String buildUnsandboxedScript() {
        return """
                import socket

                targets = [
                    ('%s', %d, 'loopback  %s:%d  (echo server)'),
                    ('%s', %d, 'external  %s:%d  (DNS)        '),
                ]

                for host, port, label in targets:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(%d / 1000)
                    try:
                        s.connect((host, port))
                        s.sendall(b'hello\\n')
                        reply = s.recv(64).decode().strip()
                        print(f'  CONNECT {label} -> OK    reply={reply!r}')
                        s.close()
                    except OSError as e:
                        err_msg = e.strerror or 'timed out after %dms'
                        print(f'  CONNECT {label} -> BLOCKED ({err_msg})')
                """.formatted(
                LOOPBACK_IP, ECHO_PORT,    LOOPBACK_IP, ECHO_PORT,
                EXTERNAL_IP, EXTERNAL_PORT, EXTERNAL_IP, EXTERNAL_PORT,
                TIMEOUT_MS);
    }

    /** Sandboxed: reach echo server via veth (10.0.0.1), external must fail. */
    private String buildSandboxedScript() {
        return """
                import socket

                targets = [
                    ('%s', %d, 'host veth %s:%d  (echo server)'),
                    ('%s', %d, 'external  %s:%d  (DNS)        '),
                ]

                for host, port, label in targets:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(%d / 1000)
                    try:
                        s.connect((host, port))
                        s.sendall(b'hello\\n')
                        reply = s.recv(64).decode().strip()
                        print(f'  CONNECT {label} -> OK    reply={reply!r}')
                        s.close()
                    except OSError as e:
                        err_msg = e.strerror or 'timed out after %dms'
                        print(f'  CONNECT {label} -> BLOCKED ({err_msg})')
                """.formatted(
                HOST_IP,     ECHO_PORT,    HOST_IP,     ECHO_PORT,
                EXTERNAL_IP, EXTERNAL_PORT, EXTERNAL_IP, EXTERNAL_PORT,
                TIMEOUT_MS);
    }
}