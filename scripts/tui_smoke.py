#!/usr/bin/env python3
"""Non-interactive smoke test for the `keyhog tui` interactive surface.

The TUI takes over the terminal (crossterm raw mode + alternate screen) and,
after a bounded scan, holds the final frame until the user presses `q`/Esc to
quit. There is no controlling TTY under the dogfood driver or in CI, so this
harness allocates a pseudo-terminal, runs the TUI inside it against a freshly
planted secret, drains the rendered output, sends `q` to quit, and asserts the
process exits cleanly without panicking.

It is the ONLY automated coverage of the interactive surface; the headless scan
path is covered by the CLI payload in dogfood-all-os.sh. The TUI maps "findings
present" to exit 1 and "clean" to exit 0, so either is a healthy exit here (we
plant a secret, so exit 1 is expected, but we accept both to stay robust to
detector changes).

Only meaningful on a build that has the `tui` feature (the default feature set);
portable builds compile it out, so the caller must gate on that.

Usage:
  tui_smoke.py <keyhog-binary> [--timeout SECONDS]

Exit status: 0 = PASS (clean interactive run), 1 = FAIL, 2 = bad invocation.
Prints a single `  PASS tui ...` / `  FAIL tui ...` line so the output slots
into the dogfood matrix alongside the CLI/install phases.
"""
import os
import pty
import select
import shutil
import signal
import sys
import tempfile
import time


def main():
    if len(sys.argv) < 2:
        print("usage: tui_smoke.py <keyhog-binary> [--timeout SECONDS]", file=sys.stderr)
        return 2

    kh = sys.argv[1]
    timeout = 25.0
    if "--timeout" in sys.argv:
        try:
            timeout = float(sys.argv[sys.argv.index("--timeout") + 1])
        except (IndexError, ValueError):
            print("  FAIL tui: --timeout needs a numeric argument")
            return 1

    if not (os.path.isfile(kh) and os.access(kh, os.X_OK)):
        print("  FAIL tui: binary not executable: %s" % kh)
        return 1

    work = tempfile.mkdtemp(prefix="kh-tui-")
    try:
        # Plant one real secret plus filler files so the live feed actually
        # streams findings rather than completing in a single frame.
        with open(os.path.join(work, "leak.env"), "w") as f:
            f.write("aws_access_key_id = AKIAZ4RNVT5QW3MXK7PD\n")
            f.write("github_token = ghp_0123456789abcdefghijklmnopqrstuvwxyz\n")
        for i in range(8):
            with open(os.path.join(work, "f%d.txt" % i), "w") as f:
                f.write("just prose, nothing secret in here\n")

        pid, fd = pty.fork()
        if pid == 0:
            # Child: become the controlling process of the pty and exec the TUI.
            os.environ["TERM"] = "xterm-256color"
            try:
                os.execv(
                    kh,
                    [kh, "tui", work, "--max-files", "16", "--throttle-ms", "20"],
                )
            except OSError as exc:  # pragma: no cover - exec failure path
                os.write(2, ("exec failed: %s\n" % exc).encode())
                os._exit(127)

        # Parent: drain the render stream. Let the bounded scan run to completion
        # FIRST (a short settle) so findings are actually detected and rendered,
        # THEN send `q` to quit. Sending `q` immediately would race the scan and
        # the TUI would exit 0 (clean) before it ever saw the planted secret,
        # making the smoke a hollow pass. The scan here is tiny (9 files,
        # ~20ms/file), so a few seconds is ample. Resend `q` once a second after
        # the settle: mid-scan the key is only polled at the next file boundary;
        # after completion it exits immediately.
        settle = 3.0
        captured = bytearray()
        start = time.time()
        deadline = start + timeout
        last_q = 0.0
        status = None
        while time.time() < deadline:
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                try:
                    data = os.read(fd, 65536)
                except OSError:
                    data = b""  # slave closed (EIO on Linux) -> process exiting
                if data:
                    captured.extend(data)
            now = time.time()
            if now - start > settle and now - last_q > 1.0:
                try:
                    os.write(fd, b"q")
                except OSError:
                    pass
                last_q = now
            wpid, wstatus = os.waitpid(pid, os.WNOHANG)
            if wpid == pid:
                status = wstatus
                break

        if status is None:
            # Hung interactive loop: escalate until it dies, then fail.
            for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    break
                time.sleep(0.5)
                wpid, wstatus = os.waitpid(pid, os.WNOHANG)
                if wpid == pid:
                    status = wstatus
                    break
            print("  FAIL tui: did not exit within %.0fs (hung interactive loop)" % timeout)
            return 1

        text = bytes(captured).decode("utf-8", "replace")
        if "panic" in text.lower():
            print("  FAIL tui: panic in TUI output")
            for line in text.splitlines():
                if "panic" in line.lower():
                    print("    " + line.strip()[:200])
                    break
            return 1
        if os.WIFSIGNALED(status):
            print("  FAIL tui: killed by signal %d" % os.WTERMSIG(status))
            return 1

        code = os.WEXITSTATUS(status)
        if code in (0, 1):
            print("  PASS tui (exit %d, %d bytes rendered)" % (code, len(captured)))
            return 0
        print("  FAIL tui: unexpected exit code %d" % code)
        return 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
