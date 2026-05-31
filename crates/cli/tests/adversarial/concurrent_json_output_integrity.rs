//! Adversarial: four concurrent scans must each emit independent valid JSON arrays.

use crate::support::{binary, workspace_detectors};
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;

#[test]
fn concurrent_json_output_integrity() {
    let detectors = workspace_detectors();
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();

    for id in 0..4 {
        let path = detectors.clone();
        let b = barrier.clone();
        handles.push(thread::spawn(move || {
            b.wait();
            let output = Command::new(binary())
                .args(["scan", "--no-daemon", "--format", "json"])
                .arg(&path)
                .env(format!("KEYHOG_ADVERSARIAL_{id}"), "1")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("spawn");
            (
                output.status.code(),
                String::from_utf8_lossy(&output.stdout).into_owned(),
            )
        }));
    }

    for handle in handles {
        let (code, stdout) = handle.join().expect("thread");
        assert_eq!(code, Some(0));
        let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
        assert!(
            parsed.is_array(),
            "concurrent stdout must stay a JSON array"
        );
    }
}
