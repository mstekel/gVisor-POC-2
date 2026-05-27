import java.io.File;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Demo 1 - Filesystem Restriction
 *
 * The sandboxed process may only read/write the "data/" folder, and
 * only read the system paths needed to run Python (/usr, /lib, /lib64, /bin).
 * Sensitive host paths like /etc are not visible at all.
 *
 * Unsandboxed: writes to data/ and /tmp        -> both succeed.
 *              reads  /etc/passwd              -> succeeds.
 * Sandboxed:   writes to /sandbox-data         -> succeeds (bind-mounted rw).
 *              writes to /tmp                  -> fails    (read-only tmpfs).
 *              writes to /usr                  -> fails    (read-only bind mount).
 *              reads  /sandbox-data            -> succeeds.
 *              reads  /etc/passwd              -> fails    (no /etc in sandbox).
 */
public class FilesystemDemo {

    private static final String DATE_TAG =
            LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss"));

    public void run() {
        System.out.println("\n\n\n+------------------------------------------+");
        System.out.println("|  Demo 1: Filesystem Restriction          |");
        System.out.println("+------------------------------------------+");
        System.out.println("Sandbox may only write to the data/ folder.");

        new File("data").mkdirs();
        String dataAbs = new File("data").getAbsolutePath();

        // - Unsandboxed -
        String unsandboxedScript = """
                import os, datetime
                tag = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

                for path in ['data/unsandboxed_' + tag + '.txt', '/tmp/unsandboxed_' + tag + '.txt']:
                    try:
                        with open(path, 'w') as f:
                            f.write('written by unsandboxed process\\n')
                        print(f'  WRITE {path:50s} -> OK')
                    except Exception as e:
                        print(f'  WRITE {path:50s} -> FAILED: {e}')

                for path in ['/etc/passwd']:
                    try:
                        with open(path) as f:
                            data = f.read()
                        print(f'  READ  {path:50s} -> OK ({len(data)} bytes)')
                    except Exception as e:
                        print(f'  READ  {path:50s} -> FAILED ({type(e).__name__})')
                """;

        SandboxRunner.runPythonUnsandboxed("Read/Write to data/, /tmp, /etc/passwd", unsandboxedScript);

        // - Sandboxed -
        String sandboxedScript = """
                import datetime
                tag = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

                write_paths = [
                    ('/sandbox-data/sandboxed_' + tag + '.txt', 'allowed folder  (/sandbox-data)'),
                    ('/tmp/sandboxed_'           + tag + '.txt', 'temp folder     (/tmp)          '),
                    ('/usr/sandboxed_'           + tag + '.txt', 'system folder   (/usr)          '),
                ]
                for path, desc in write_paths:
                    try:
                        with open(path, 'w') as f:
                            f.write('written by sandboxed process\\n')
                        print(f'  WRITE {desc} -> OK  <- should only happen for /sandbox-data')
                    except Exception as e:
                        print(f'  WRITE {desc} -> BLOCKED ({type(e).__name__})')

                read_paths = [
                    ('/sandbox-data/sandboxed_' + tag + '.txt', 'allowed folder  (/sandbox-data)'),
                    ('/etc/passwd',                              'system file     (/etc/passwd)   '),
                ]
                for path, desc in read_paths:
                    try:
                        with open(path) as f:
                            data = f.read()
                        print(f'  READ  {desc} -> OK ({len(data)} bytes)  <- should only happen for /sandbox-data')
                    except Exception as e:
                        print(f'  READ  {desc} -> BLOCKED ({type(e).__name__})')
                """;

        List<String> extraMounts = List.of(
                // data/ is the ONLY rw mount that reaches the real host filesystem
                SandboxRunner.mount("/sandbox-data", dataAbs, "bind", "rbind,rw")
        );

        SandboxRunner.runPythonSandboxed(
                "Read/Write to allowed folder, /tmp, /usr, /etc/passwd",
                sandboxedScript,
                extraMounts,
                null,    // no seccomp
                "none"   // no network needed
        );

        System.out.println("\n\n\n-- data/ contents after demo --");
        SandboxRunner.exec("ls", "-1", "data/");
        System.out.println("\n\n\n");
    }
}
