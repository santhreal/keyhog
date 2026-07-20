//! Spawn parallel `keyhog scan` subprocesses; each must emit independent valid JSON.

use crate::support::binary;
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;
use tempfile::TempDir;

#[test]
fn parallel_scan_subprocesses_emit_valid_json() {
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();

    for worker in 0..4 {
        let b = barrier.clone();
        handles.push(thread::spawn(move || {
            let dir = TempDir::new().expect("tempdir");
            std::fs::write(
                dir.path().join(format!("worker_{worker}.txt")),
                "fn main() {}\n",
            )
            .unwrap();
            b.wait();
            Command::new(binary())
                .args([
                    "scan",
                    "--daemon=off",
                    "--backend",
                    "simd",
                    "--format",
                    "json",
                ])
                .arg(dir.path())
                .env(format!("KEYHOG_CONCURRENT_{worker}"), "1")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("spawn scan")
        }));
    }

    for handle in handles {
        let output = handle.join().expect("thread");
        assert_eq!(output.status.code(), Some(0));
        let parsed: serde_json::Value =
            serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("valid json");
        assert!(parsed.is_array());
    }
}
