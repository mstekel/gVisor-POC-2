import java.io.File;
import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Demo 3 - Network Restriction (no network + one Unix-domain socket)
 *
 * The sandbox is launched with --network=none, so it has NO network stack:
 * any IP socket/connect fails. The ONE channel it is given is a single Unix
 * domain socket - the Java parent's echo server - exposed by bind-mounting
 * just that socket into the sandbox and allowing host UDS access
 * (--host-uds=open). Everything else (all IP networking) is denied by gVisor.
 *
 * Unlike the stdio approach, this leaves the sandboxed process's stdin/stdout/
 * stderr completely free for its own use - the channel is a dedicated fd the
 * workload opens explicitly (socket.AF_UNIX), not a hijacked standard stream.
 *
 *   Unsandboxed: connects to the host UDS (OK) and an external IP (OK).
 *   Sandboxed:   connects to the bind-mounted UDS (OK), external IP BLOCKED.
 *
 * No veth, no netns, no iptables, no root/sudo - same rootless footprint as
 * Demos 1 & 2, and nothing is touched on the host network.
 */
public class NetworkDemo {

    private static final String EXTERNAL_IP   = "8.8.8.8";
    private static final int    EXTERNAL_PORT = 53;
    private static final int    TIMEOUT_MS    = 3000;
    private static final String SOCK_NAME     = "echo.sock";
    private static final String SANDBOX_MNT   = "/echo";                  // mount point in sandbox
    private static final String SANDBOX_SOCK  = "/echo/" + SOCK_NAME;     // socket path inside sandbox

    public void run() throws Exception {
        System.out.println("\n\n\n+------------------------------------------+");
        System.out.println("|  Demo 3: Network Restriction             |");
        System.out.println("|  --network=none + one Unix-domain socket |");
        System.out.println("+------------------------------------------+");
        System.out.println("Sandbox has NO network stack; its only channel out is one");
        System.out.println("bind-mounted Unix socket (the parent's echo server).");

        long pid     = ProcessHandle.current().pid();
        Path sockDir = Path.of("/tmp/echo-" + pid);
        Files.createDirectories(sockDir);
        Path sockPath = sockDir.resolve(SOCK_NAME);
        Files.deleteIfExists(sockPath);   // stale socket from a previous run

        ExecutorService pool  = Executors.newSingleThreadExecutor();
        ServerSocketChannel server = startEchoServer(pool, sockPath);
        try {
            // Baseline: a plain host process reaches the UDS AND the network.
            SandboxRunner.runPythonUnsandboxed(
                    "Connect to echo socket (allowed) and external IP",
                    buildScript(sockPath.toString()));

            // Sandboxed: --network=none. Only the bind-mounted UDS is reachable.
            runSandboxed(buildScript(SANDBOX_SOCK), sockDir.toString());
        } finally {
            server.close();
            pool.shutdownNow();
            Files.deleteIfExists(sockPath);
            Files.deleteIfExists(sockDir);
        }
    }

    // -- Unix-domain echo server (the parent = the one allowed peer) ----------

    private ServerSocketChannel startEchoServer(ExecutorService pool, Path sockPath)
            throws IOException {
        ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        server.bind(UnixDomainSocketAddress.of(sockPath));
        pool.submit(() -> {
            while (server.isOpen()) {
                try {
                    SocketChannel ch = server.accept();
                    new Thread(() -> {
                        try (ch) {
                            ByteBuffer buf = ByteBuffer.allocate(256);
                            int n = ch.read(buf);
                            if (n > 0) {
                                buf.flip();
                                byte[] data = new byte[buf.remaining()];
                                buf.get(data);
                                String msg = new String(data).strip();
                                ch.write(ByteBuffer.wrap(("ECHO: " + msg).getBytes()));
                            }
                        } catch (IOException ignored) {}
                    }).start();
                } catch (IOException e) {
                    break;   // server channel closed
                }
            }
        });
        System.out.println("\n\n\n[Echo server listening on unix:" + sockPath + "]");
        return server;
    }

    // -- Sandboxed run --------------------------------------------------------

    private void runSandboxed(String script, String hostSockDir) throws Exception {
        long   pid     = ProcessHandle.current().pid();
        String tmpRoot = "/tmp/runsc-root-" + pid;
        String bundle  = "/tmp/bundle-net-" + pid + "-" + System.nanoTime();
        String rootfs  = bundle + "/rootfs";

        for (String d : new String[]{
                "usr", "lib", "lib64", "bin", "proc", "sys", "dev", "tmp", "echo"}) {
            new File(rootfs + "/" + d).mkdirs();
        }
        new File(tmpRoot).mkdirs();

        Files.writeString(Path.of(bundle + "/config.json"),
                buildSandboxConfig(script, hostSockDir));

        System.out.println("\n\n\n[SANDBOXED]   Reach echo socket (allowed); external IP (blocked)");
        SandboxRunner.exec(
                "sudo", "/usr/local/bin/runsc",
                "--root",            tmpRoot,
                "--ignore-cgroups",
                "--platform=systrap",
                "--network=none",
                "--host-uds=open",        // allow connecting to the bind-mounted host UDS
                "run",
                "--bundle", bundle,
                "sandbox-net-" + pid);
        System.out.println("\n\n\n");
    }

    // -- OCI config: read-only rootfs, no network ns, one bind-mounted socket -

    private String buildSandboxConfig(String script, String hostSockDir) {
        String escaped = SandboxRunner.escapeJson(script);
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
                      { "type": "uts"   }
                    ]
                  }
                }
                """.formatted(
                escaped,
                SandboxRunner.mount("/usr",   "/usr",   "bind", "rbind,ro"),
                SandboxRunner.mount("/lib",   "/lib",   "bind", "rbind,ro"),
                SandboxRunner.mount("/lib64", "/lib64", "bind", "rbind,ro"),
                SandboxRunner.mount("/bin",   "/bin",   "bind", "rbind,ro"),
                // The ONLY channel out: the directory holding the parent's UDS,
                // bind-mounted in. Combined with --host-uds=open, the sandbox may
                // connect() to this socket and nothing else.
                SandboxRunner.mount(SANDBOX_MNT, hostSockDir, "bind", "rbind,rw"));
    }

    // -- Sandboxed workload ---------------------------------------------------

    /**
     * Python run both unsandboxed and sandboxed. (1) connect to the echo server's
     * Unix socket - the one allowed channel - and (2) try an external TCP
     * connection, which the sandbox denies (--network=none). stdin/stdout/stderr
     * are left entirely free; the channel is the explicitly-opened AF_UNIX socket.
     */
    private String buildScript(String unixPath) {
        return """
                import socket

                # (1) Allowed: connect to the echo server's Unix socket - the only
                #     channel exposed to the sandbox.
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(%d / 1000)
                try:
                    s.connect('%s')
                    s.sendall(b'hello')
                    reply = s.recv(256).decode()
                    print(f'  CONNECT unix echo socket          -> OK    reply={reply!r}')
                except OSError as e:
                    print(f'  CONNECT unix echo socket          -> BLOCKED ({e.strerror or type(e).__name__})')
                finally:
                    s.close()

                # (2) Any IP networking is denied in the sandbox (--network=none).
                t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                t.settimeout(%d / 1000)
                try:
                    t.connect(('%s', %d))
                    print('  CONNECT external %s:%d (TCP/IP) -> OK   <- should NOT happen in sandbox')
                except OSError as e:
                    print(f'  CONNECT external %s:%d (TCP/IP) -> BLOCKED ({e.strerror or "timed out"})')
                finally:
                    t.close()
                """.formatted(
                TIMEOUT_MS, unixPath,
                TIMEOUT_MS, EXTERNAL_IP, EXTERNAL_PORT,
                EXTERNAL_IP, EXTERNAL_PORT,
                EXTERNAL_IP, EXTERNAL_PORT);
    }
}
