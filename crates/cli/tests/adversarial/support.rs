//! Shared helpers for adversarial CLI integration tests.

#[path = "../e2e/support.rs"]
#[allow(dead_code)]
mod e2e_support;

pub use e2e_support::{binary, workspace_detectors, write_temp_file};

use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;
use tempfile::TempDir;

/// Scan a directory containing a unicode filename; must exit 0 with JSON stdout.
pub fn oracle_unicode_path_scan() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("café.txt"), "hello\n").unwrap();
    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--format", "json"])
        .arg(dir.path())
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
}

/// Piped JSON stdout must complete without hanging and parse as JSON.
pub fn oracle_pipe_stdout_json_valid() {
    let (_dir, path) = write_temp_file("clean.txt", "hello\n");
    let child = Command::new(binary())
        .args(["scan", "--no-daemon", "--format", "json"])
        .arg(&path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let output = child.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(0));
    let _: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("valid json array");
}

/// Four concurrent scans from isolated temp dirs must each yield valid JSON.
pub fn oracle_concurrent_four_scans_json() {
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let b = barrier.clone();
        handles.push(thread::spawn(move || {
            let dir = TempDir::new().expect("tempdir");
            std::fs::write(dir.path().join("a.txt"), "hello\n").unwrap();
            b.wait();
            let output = Command::new(binary())
                .args(["scan", "--no-daemon", "--format", "json"])
                .arg(dir.path())
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
    for h in handles {
        let (code, stdout) = h.join().expect("thread");
        assert_eq!(code, Some(0));
        let _: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    }
}

/// Non-UTF-8 path components must fail with an explicit UTF-8 stderr message.
#[cfg(unix)]
pub fn oracle_invalid_utf8_filename_rejected() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let dir = TempDir::new().expect("tempdir");
    let bad = OsStr::from_bytes(b"bad\xffname.txt");
    let path = dir.path().join(bad);
    std::fs::write(&path, b"hello\n").expect("write");

    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--format", "json"])
        .arg(&path)
        .output()
        .expect("spawn");
    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("UTF-8") || stderr.contains("utf-8"),
        "expected UTF-8 path error; got: {stderr}"
    );
}
