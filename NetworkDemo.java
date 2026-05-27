import java.io.*;
import java.net.*;
import java.util.List;
import java.util.concurrent.*;

/**
 * Demo 3 - Network Restriction (localhost only)
 *
 * A Java echo server listens on localhost:19876 for the duration of this demo.
 *
 * Unsandboxed: connects to localhost:19876  -> succeeds.
 *              connects to 8.8.8.8:53       -> succeeds (or times out, proving
 *              the syscall was reachable).
 *
 * Sandboxed:   gVisor runs with --network=none, so ALL network syscalls are
 *              intercepted and return ENETDOWN. Both connections fail, which
 *              demonstrates that even localhost is blocked - the sandbox has
 *              no network stack at all.
 *
 * Note: allowing *only* localhost while blocking external IPs requires
 * combining --network=sandbox with host-level iptables rules (outside the
 * scope of a self-contained demo). Here we show the two extremes:
 *   unsandboxed  = full network access
 *   sandboxed    = zero network access (--network=none)
 */
public class NetworkDemo {

    private static final int    ECHO_PORT    = 19876;
    private static final String EXTERNAL_IP  = "8.8.8.8";
    private static final int    EXTERNAL_PORT = 53;
    private static final int    TIMEOUT_MS   = 3000;

    public void run() throws Exception {
        System.out.println("+------------------------------------------+");
        System.out.println("|  Demo 3: Network Restriction             |");
        System.out.println("+------------------------------------------+");
        System.out.println("Unsandboxed: localhost + external both reachable.");
        System.out.println("Sandboxed:   --network=none blocks all sockets.");

        // Start a local echo server so localhost tests are self-contained
        ExecutorService serverPool = Executors.newSingleThreadExecutor();
        ServerSocket serverSocket  = startEchoServer(serverPool);

        try {
            String script = buildScript();

            // - Unsandboxed -
            SandboxRunner.runPythonUnsandboxed(
                    "Connect to localhost:" + ECHO_PORT + " and " + EXTERNAL_IP + ":" + EXTERNAL_PORT,
                    script);

            // - Sandboxed -
            // --network=none: gVisor provides no network stack at all.
            // Socket syscalls (connect, bind, etc.) return ENETDOWN immediately.
            SandboxRunner.runPythonSandboxed(
                    "Same connections - all blocked by --network=none",
                    script,
                    List.of(),  // no extra mounts
                    null,       // no seccomp (network=none handles it)
                    "none"      // <- this is the key restriction
            );

        } finally {
            serverSocket.close();
            serverPool.shutdownNow();
        }
    }

    // - Echo server -

    private ServerSocket startEchoServer(ExecutorService pool) throws IOException {
        ServerSocket ss = new ServerSocket(ECHO_PORT, 10,
                InetAddress.getByName("127.0.0.1"));
        pool.submit(() -> {
            while (!ss.isClosed()) {
                try {
                    Socket client = ss.accept();
                    new Thread(() -> {
                        try (client;
                             var in  = new BufferedReader(new InputStreamReader(client.getInputStream()));
                             var out = new PrintWriter(client.getOutputStream(), true)) {
                            String line;
                            while ((line = in.readLine()) != null)
                                out.println("ECHO: " + line);
                        } catch (IOException ignored) {}
                    }).start();
                } catch (IOException ignored) {}
            }
        });
        System.out.println("\n  [Echo server listening on localhost:" + ECHO_PORT + "]");
        return ss;
    }

    // - Python script -

    private String buildScript() {
        return """
                import socket

                targets = [
                    ('127.0.0.1', %d, 'localhost:%d (echo server)'),
                    ('%s',        %d, '%s:%d    (external DNS)  '),
                ]

                for host, port, label in targets:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(%d / 1000)
                    try:
                        s.connect((host, port))
                        if host == '127.0.0.1':
                            s.sendall(b'hello\\n')
                            reply = s.recv(64).decode().strip()
                            print(f'  CONNECT {label} -> OK  reply={reply!r}')
                        else:
                            print(f'  CONNECT {label} -> OK  (socket reached external host)')
                        s.close()
                    except OSError as e:
                        print(f'  CONNECT {label} -> BLOCKED ({e.strerror})')
                """.formatted(
                        ECHO_PORT, ECHO_PORT,
                        EXTERNAL_IP, EXTERNAL_PORT, EXTERNAL_IP, EXTERNAL_PORT,
                        TIMEOUT_MS);
    }
}
