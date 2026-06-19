//! Daemon ScanPath must decode files through the same filesystem decoder as
//! the normal in-process scan route.

#![cfg(unix)]

use crate::e2e::support::{binary, DaemonGuard};
use std::process::Command;
use tempfile::TempDir;

#[test]
fn daemon_scan_path_decodes_utf16le_file() {
    let dir = TempDir::new().expect("fixture dir");
    let fixture = dir.path().join("daemon-utf16.txt");
    write_utf16le_with_bom(
        &fixture,
        "token = \"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\"\n",
    );

    let daemon = DaemonGuard::start();

    let output = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args(["scan", "--daemon=on", "--format", "json"])
        .arg(&fixture)
        .output()
        .expect("daemon scan");

    assert_eq!(
        output.status.code(),
        Some(1),
        "daemon ScanPath must find a secret in UTF-16LE files; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let findings: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("daemon stdout is JSON");
    let arr = findings.as_array().expect("json findings array");
    assert!(
        arr.iter().any(|finding| {
            finding.get("detector_id").and_then(|value| value.as_str())
                == Some("github-classic-pat")
        }),
        "daemon ScanPath must return the same decoded detector hit as the filesystem source; got {arr:?}"
    );
}

fn write_utf16le_with_bom(path: &std::path::Path, text: &str) {
    let mut bytes = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    std::fs::write(path, bytes).expect("write UTF-16 fixture");
}
