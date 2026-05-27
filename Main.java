/**
 * gVisor Sandbox Demo
 *
 * Usage:
 *   java Main filesystem   -- Demo 1: restrict writes to one folder
 *   java Main syscall      -- Demo 2: block perf_event_open (kernel perf API)
 *   java Main network      -- Demo 3: block external network, allow localhost
 */
public class Main {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            printUsage();
            System.exit(1);
        }

        switch (args[0].toLowerCase()) {
            case "filesystem" -> new FilesystemDemo().run();
            case "syscall"    -> new SyscallDemo().run();
            case "network"    -> new NetworkDemo().run();
            default -> {
                System.err.println("Unknown demo: " + args[0]);
                printUsage();
                System.exit(1);
            }
        }
    }

    private static void printUsage() {
        System.out.println("""
                Usage: java Main <demo>

                  filesystem   Restrict sandboxed process to a single folder
                  syscall      Block access to perf_event_open (kernel perf API)
                  network      Block external network; allow only localhost
                """);
    }
}
