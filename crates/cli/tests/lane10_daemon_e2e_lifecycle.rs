//! Lane-10 (dogfood/robustness) end-to-end: drive the REAL `keyhog` binary
//! through the daemon lifecycle the way a user / IDE / CI hook does, and pin
//! the robustness guarantees:
//!   * start -> status -> stop, with the socket created 0600 and removed on stop;
//!   * the idle-request timeout reclaims a half-frame / slowloris connection so
//!     one stuck client cannot deadlock the daemon (`--request-timeout-secs`);
//!   * a frame body that exceeds MAX_FRAME_BYTES is rejected (recv-buffer bound).

#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Start `keyhog daemon start --socket <sock>` and wait until the socket is a
/// live listener. Returns the child + socket path; the caller stops it.
fn start_daemon(dir: &Path, extra_args: &[&str]) -> (Child, PathBuf) {
    let socket = dir.join("d.sock");
    let mut cmd = Command::new(binary());
    cmd.args(["daemon", "start", "--socket"])
        .arg(&socket)
        .args(extra_args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let child = cmd.spawn().expect("spawn daemon");
    // Wait for a real listener (connect succeeds), not just file existence.
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if socket.exists() && StdUnixStream::connect(&socket).is_ok() {
            return (child, socket);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("daemon did not become ready within 30s");
}

fn stop_daemon(socket: &Path) -> Option<i32> {
    Command::new(binary())
        .args(["daemon", "stop", "--socket"])
        .arg(socket)
        .output()
        .expect("spawn daemon stop")
        .status
        .code()
}

#[test]
fn daemon_start_status_stop_lifecycle_and_socket_hygiene() {
    let dir = TempDir::new().unwrap();
    let (mut child, socket) = start_daemon(dir.path(), &[]);

    // Socket must be 0600 (user-only) — same-uid trust model for plaintext
    // credentials on the wire.
    let mode = std::fs::metadata(&socket)
        .expect("socket metadata")
        .permissions();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        mode.mode() & 0o777,
        0o600,
        "daemon socket must be 0600 (user-only) so a co-tenant cannot read findings"
    );

    // status exits 0 against a live daemon.
    let status = Command::new(binary())
        .args(["daemon", "status", "--socket"])
        .arg(&socket)
        .output()
        .expect("status");
    assert_eq!(
        status.status.code(),
        Some(0),
        "daemon status against a live daemon must exit 0; stderr={}",
        String::from_utf8_lossy(&status.stderr)
    );
    let out = String::from_utf8_lossy(&status.stdout);
    assert!(
        out.contains("detectors") && out.contains("uptime"),
        "status must report uptime + detector count; got {out}"
    );

    // stop exits 0 and removes the socket.
    assert_eq!(stop_daemon(&socket), Some(0), "daemon stop must exit 0");
    let _ = child.wait();
    let deadline = Instant::now() + Duration::from_secs(10);
    while socket.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !socket.exists(),
        "daemon stop must remove the socket file so a later start does not refuse it"
    );
}

#[test]
fn daemon_reclaims_stuck_half_frame_connection() {
    let dir = TempDir::new().unwrap();
    // 1-second request timeout so the test is fast. A real client does one
    // round-trip; a connection idle past this is stuck and must be reclaimed.
    let (mut child, socket) = start_daemon(dir.path(), &["--request-timeout-secs", "1"]);

    // Open a connection, announce a frame length, then send NOTHING — the
    // classic half-frame / slowloris stall that would otherwise hold a
    // connection_limit permit forever.
    let mut stuck = StdUnixStream::connect(&socket).expect("connect stuck client");
    // Announce a 1000-byte body (BE u32) but write zero body bytes.
    stuck
        .write_all(&1000u32.to_be_bytes())
        .expect("write len prefix");
    stuck.flush().ok();

    // The daemon must NOT be wedged: a FRESH client can still get served.
    // Give the stuck connection time to hit the 1s timeout and be reclaimed.
    std::thread::sleep(Duration::from_millis(1500));

    // A well-behaved status request must still succeed — proving the stuck
    // connection did not deadlock the daemon.
    let status = Command::new(binary())
        .args(["daemon", "status", "--socket"])
        .arg(&socket)
        .output()
        .expect("status after stuck client");
    assert_eq!(
        status.status.code(),
        Some(0),
        "a stuck half-frame connection must not wedge the daemon; a fresh status \
         request must still be served. stderr={}",
        String::from_utf8_lossy(&status.stderr)
    );

    // The stuck connection must have been CLOSED by the server-side request
    // timeout: a read returns Ok(0) (true EOF). A read TIMEOUT (WouldBlock /
    // TimedOut) instead would mean the server never closed it — i.e. the
    // timeout fix is absent — so we must distinguish the two and only accept a
    // genuine EOF. (`unwrap_or(0)` would have masked the missing-fix case.)
    stuck
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buf = [0u8; 16];
    match stuck.read(&mut buf) {
        Ok(0) => { /* server closed the stuck connection: the timeout fired */ }
        Ok(n) => panic!(
            "stuck connection returned {n} unexpected bytes instead of EOF; the server \
             must close a half-frame connection, not reply to it"
        ),
        Err(e) => panic!(
            "the server must CLOSE the stuck connection after the request timeout \
             (expected EOF / Ok(0)); instead the read returned {e:?}, meaning the \
             connection is still open — the request-read timeout did not fire"
        ),
    }

    let _ = stop_daemon(&socket);
    let _ = child.wait();
}

#[test]
fn daemon_rejects_oversized_frame_length_prefix() {
    let dir = TempDir::new().unwrap();
    let (mut child, socket) = start_daemon(dir.path(), &[]);

    // MAX_FRAME_BYTES is 64 MiB; announce one byte more. The server must refuse
    // to allocate the recv buffer (it drops the connection) rather than OOM.
    let mut hostile = StdUnixStream::connect(&socket).expect("connect hostile client");
    let oversized = (64u32 * 1024 * 1024 + 1).to_be_bytes();
    hostile
        .write_all(&oversized)
        .expect("write oversized prefix");
    hostile.flush().ok();

    // The connection must be DROPPED (true EOF / Ok(0)) promptly — not hang
    // while the server tries to allocate a 64 MiB+ recv buffer. A read TIMEOUT
    // would mean the server is still waiting on the (never-sent) body, i.e. the
    // length cap did not reject the frame.
    hostile
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buf = [0u8; 16];
    match hostile.read(&mut buf) {
        Ok(0) => { /* server dropped the connection: the length cap fired */ }
        Ok(n) => panic!("oversized-frame client got {n} bytes instead of EOF"),
        Err(e) => panic!(
            "an oversized frame-length prefix must cause the server to DROP the \
             connection (bounded recv buffer); instead the read returned {e:?}, \
             meaning the server did not reject the oversized length"
        ),
    }

    // And the daemon stays healthy for other clients.
    let status = Command::new(binary())
        .args(["daemon", "status", "--socket"])
        .arg(&socket)
        .output()
        .expect("status after hostile client");
    assert_eq!(
        status.status.code(),
        Some(0),
        "an oversized-frame client must not affect other clients; stderr={}",
        String::from_utf8_lossy(&status.stderr)
    );

    let _ = stop_daemon(&socket);
    let _ = child.wait();
}
