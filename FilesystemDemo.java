import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
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
 *              reads  /sandbox-data/readonly.txt -> succeeds, but
 *              writes to that same file        -> fails    (per-file read-only
 *                                                           bind mount, even though
 *                                                           its directory is writable).
 */
public class FilesystemDemo {

    public void run() {
        System.out.println("\n\n\n+------------------------------------------+");
        System.out.println("|  Demo 1: Filesystem Restriction          |");
        System.out.println("+------------------------------------------+");
        System.out.println("Sandbox may only read/write the data/ folder; host /etc is hidden.");

        new File("data").mkdirs();
        String dataAbs = new File("data").getAbsolutePath();

        // Pre-create a file we will expose at single-file read-only granularity.
        // The /sandbox-data directory stays writable; only THIS one file is
        // read-only, via a per-file ro bind mount layered on top of the dir.
        String roFileName = "readonly.txt";
        try {
            Files.writeString(new File("data", roFileName).toPath(),
                    "this single file is mounted read-only\n");
        } catch (IOException e) {
            System.out.println("  Setup error creating " + roFileName + ": " + e.getMessage());
        }

        // - Unsandboxed -
        String unsandboxedScript = """
                import os, datetime
                tag = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d_%H-%M-%S')

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
                tag = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d_%H-%M-%S')

                # A single file exposed read-only via a per-file bind mount, even
                # though its parent directory (/sandbox-data) is writable. Shows
                # read-only at single-file granularity, distinct from /etc/passwd
                # (hidden entirely / not mounted).
                ro_file = '/sandbox-data/readonly.txt'

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

                # Single read-only file inside the writable /sandbox-data dir:
                # READable, but writes are denied by the per-file ro bind mount.
                # The directory itself stays writable (see the /sandbox-data WRITE
                # above), so this is read-only at single-file granularity.
                desc = 'read-only file  (/sandbox-data/readonly.txt)'
                try:
                    with open(ro_file) as f:
                        n = len(f.read())
                    print(f'  READ  {desc} -> OK ({n} bytes)')
                except Exception as e:
                    print(f'  READ  {desc} -> BLOCKED ({type(e).__name__})')
                try:
                    # 'a' requests write access; on the read-only file bind mount
                    # this fails at open() without ever modifying the file.
                    open(ro_file, 'a').close()
                    print(f'  WRITE {desc} -> OK  <- should NOT happen (read-only file)')
                except Exception as e:
                    print(f'  WRITE {desc} -> BLOCKED ({type(e).__name__})')
                """;

        List<String> extraMounts = new ArrayList<>();
        // data/ is the ONLY rw mount that reaches the real host filesystem
        extraMounts.add(SandboxRunner.mount("/sandbox-data", dataAbs, "bind", "rbind,rw"));
        // Single-file read-only bind mount, layered on top of the writable dir
        // above. Order matters: this must come AFTER the /sandbox-data rw mount
        // so it overlays just this one file. Result: the directory is writable,
        // but /sandbox-data/readonly.txt is not.
        extraMounts.add(SandboxRunner.mount(
                "/sandbox-data/" + roFileName, dataAbs + "/" + roFileName, "bind", "rbind,ro"));

        SandboxRunner.runPythonSandboxed(
                "Read/Write to allowed folder, /tmp, /usr, /etc/passwd",
                sandboxedScript,
                extraMounts,
                null,    // no seccomp
                "none",  // no network needed
                0        // rootless maps uid 0 -> host 1001 (the data/ owner), so writes are allowed
        );

        System.out.println("\n\n\n-- data/ contents after demo --");
        SandboxRunner.exec("ls", "-1", "data/");
        System.out.println("\n\n\n");
    }
}
