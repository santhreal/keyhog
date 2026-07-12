//! Shared helpers for adversarial CLI integration tests.

#[path = "../e2e/support.rs"]
#[allow(dead_code)]
mod e2e_support;

pub use e2e_support::{binary, workspace_detectors, write_temp_file};

use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;
use tempfile::TempDir;

const PLANTED_AWS_KEY: &str = concat!("AKIA", "QYLPMN5HFIQR7XYA");

fn parse_json_array(stdout: &[u8], context: &str) -> Vec<serde_json::Value> {
    let value = serde_json::from_slice::<serde_json::Value>(stdout).unwrap_or_else(|error| {
        panic!(
            "{context}: stdout is not valid UTF-8 JSON: {error}\n{}",
            String::from_utf8_lossy(stdout)
        )
    });
    value
        .as_array()
        .unwrap_or_else(|| panic!("{context}: JSON report must be an array, got {value}"))
        .clone()
}

/// Scan a directory containing a unicode filename; must report the finding path.
pub fn oracle_unicode_path_scan() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join("café.txt"),
        format!("AWS_ACCESS_KEY_ID = \"{PLANTED_AWS_KEY}\"\n"),
    )
    .unwrap();
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "simd",
            "--format",
            "json",
        ])
        .arg(dir.path())
        .output()
        .expect("spawn");
    assert_eq!(
        output.status.code(),
        Some(1),
        "unicode filename scan must find the planted secret; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output
            .stdout
            .windows(PLANTED_AWS_KEY.len())
            .any(|window| window == PLANTED_AWS_KEY.as_bytes()),
        "unicode path JSON report must redact the planted credential; stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    let findings = parse_json_array(&output.stdout, "unicode path scan JSON");
    assert!(
        findings.iter().any(|finding| {
            finding
                .pointer("/location/file_path")
                .and_then(|v| v.as_str())
                .is_some_and(|path| path.ends_with("café.txt") || path.ends_with("cafe\u{301}.txt"))
                && finding
                    .get("detector_id")
                    .and_then(|v| v.as_str())
                    .is_some_and(|detector_id| detector_id == "aws-access-key")
        }),
        "unicode path scan must report the planted finding with the unicode filename; stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// Piped JSON stdout must complete without hanging and parse as JSON.
pub fn oracle_pipe_stdout_json_valid() {
    let (_dir, path) = write_temp_file("clean.txt", "hello\n");
    let child = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "simd",
            "--format",
            "json",
        ])
        .arg(&path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let output = child.wait_with_output().expect("wait");
    assert_eq!(
        output.status.code(),
        Some(0),
        "clean piped scan should exit 0; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings = parse_json_array(&output.stdout, "piped stdout scan JSON");
    assert!(
        findings.is_empty(),
        "clean piped scan should produce an empty JSON array; stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
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
                .args([
                    "scan",
                    "--daemon=off",
                    "--backend",
                    "simd",
                    "--format",
                    "json",
                ])
                .arg(dir.path())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("spawn");
            (output.status.code(), output.stdout, output.stderr)
        }));
    }
    for h in handles {
        let (code, stdout, stderr) = h.join().expect("thread");
        assert_eq!(
            code,
            Some(0),
            "concurrent clean scan should exit 0; stderr={}",
            String::from_utf8_lossy(&stderr)
        );
        let findings = parse_json_array(&stdout, "concurrent scan JSON");
        assert!(
            findings.is_empty(),
            "concurrent clean scan should produce an empty JSON array; stdout={}",
            String::from_utf8_lossy(&stdout)
        );
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
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "simd",
            "--format",
            "json",
        ])
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
