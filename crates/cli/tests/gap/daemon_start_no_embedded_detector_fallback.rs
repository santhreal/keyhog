//! KH-GAP-105: `daemon start` requires a `detectors/` directory on disk and
//! does not fall back to the embedded corpus (unlike `scan`, `watch`, `explain`).
//! The test forces SIMD so it isolates corpus discovery from the separate
//! autoroute-readiness contract, which intentionally requires persisted route
//! evidence for the default daemon policy.

use crate::e2e::support::binary;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[test]
fn daemon_start_from_empty_cwd_uses_embedded_detectors_like_scan() {
    let dir = TempDir::new().expect("tempdir");
    let runtime = TempDir::new().expect("runtime dir");
    let mut daemon: Child = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["daemon", "start", "--backend", "simd"])
        .current_dir(dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");

    let socket = runtime.path().join("keyhog.sock");
    let deadline = Instant::now() + Duration::from_secs(120);
    while !socket.exists() {
        if let Some(status) = daemon.try_wait().expect("poll daemon") {
            let stderr = daemon.stderr.take().map(|mut s| {
                use std::io::Read;
                let mut buf = String::new();
                let _ = s.read_to_string(&mut buf);
                buf
            });
            panic!(
                "daemon start outside repo should succeed via embedded corpus (like scan); \
                 exited early with {status:?}; stderr={}",
                stderr.unwrap_or_default()
            );
        }
        assert!(
            Instant::now() < deadline,
            "daemon start outside repo should bind socket via embedded corpus"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let _ = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["daemon", "stop"])
        .output();
    let _ = daemon.kill();
    let _ = daemon.wait();
}
