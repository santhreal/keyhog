//! R1-D2 stress: four concurrent directory scans must all exit cleanly with valid JSON.

use crate::e2e::support::{binary, workspace_detectors};
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;

#[test]
fn concurrent_scans_no_corrupt_json() {
    let detectors = workspace_detectors();
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();

    for _ in 0..4 {
        let path = detectors.clone();
        let b = barrier.clone();
        handles.push(thread::spawn(move || {
            b.wait();
            let output = Command::new(binary())
                .args(["scan", "--no-daemon", "--format", "json"])
                .arg(&path)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("spawn");
            (output.status.code(), String::from_utf8_lossy(&output.stdout).into_owned())
        }));
    }

    for handle in handles {
        let (code, stdout) = handle.join().expect("thread");
        assert_eq!(code, Some(0), "concurrent scan must exit 0");
        let _: serde_json::Value =
            serde_json::from_str(&stdout).expect("concurrent scan stdout must be valid JSON");
    }
}
