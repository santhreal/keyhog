#![cfg(unix)]

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn forced_daemon_rejects_directory_without_in_process_fallback() {
    let work = TempDir::new().expect("work dir");
    std::fs::write(work.path().join("leak.env"), aws_key_line()).expect("write fixture");
    let runtime = TempDir::new().expect("isolated runtime");

    let out = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["scan", "--daemon=on", "--format", "json"])
        .arg(work.path())
        .output()
        .expect("spawn keyhog scan");

    let combined = combined_output(&out);
    assert_eq!(
        out.status.code(),
        Some(2),
        "forced daemon over a directory must fail instead of falling back to in-process; output={combined}"
    );
    assert!(
        combined.contains("--daemon=on cannot be honored")
            && combined.contains("single regular file"),
        "forced-daemon rejection must explain the unsupported shape; output={combined}"
    );
    assert!(
        !combined.contains("aws-access-key"),
        "forced daemon rejection must not scan and report findings; output={combined}"
    );
}

#[test]
fn forced_daemon_rejects_unenforceable_policy_without_in_process_fallback() {
    let work = TempDir::new().expect("work dir");
    let secret = aws_key();
    let path = work.path().join("leak.env");
    std::fs::write(&path, format!("AWS_ACCESS_KEY_ID = \"{secret}\"\n")).expect("write fixture");
    let runtime = TempDir::new().expect("isolated runtime");

    let out = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["scan", "--daemon=on", "--show-secrets", "--format", "json"])
        .arg(&path)
        .output()
        .expect("spawn keyhog scan");

    let combined = combined_output(&out);
    assert_eq!(
        out.status.code(),
        Some(2),
        "forced daemon with policy the daemon cannot enforce must fail; output={combined}"
    );
    assert!(
        combined.contains("--daemon=on cannot be honored")
            && combined.contains("policy the daemon cannot enforce"),
        "forced-daemon rejection must name the policy mismatch; output={combined}"
    );
    assert!(
        !combined.contains(&secret),
        "forced daemon rejection must not run the in-process show-secrets path; output={combined}"
    );
}

fn combined_output(out: &std::process::Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn aws_key_line() -> String {
    format!("AWS_ACCESS_KEY_ID = \"{}\"\n", aws_key())
}

fn aws_key() -> String {
    concat!("AKIA", "QYLPMN5HFIQR7XYA").to_string()
}
