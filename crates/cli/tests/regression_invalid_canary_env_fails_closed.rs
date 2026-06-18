use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn unreadable_keyhog_aws_canary_accounts_exits_two_before_scan() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("clean.txt");
    let missing = dir.path().join("missing-canaries.toml");
    std::fs::write(&target, "clean fixture\n").expect("write clean fixture");

    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--backend", "cpu", "--format", "json"])
        .arg(&target)
        .env("KEYHOG_AWS_CANARY_ACCOUNTS", &missing)
        .output()
        .expect("spawn keyhog scan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "bad KEYHOG_AWS_CANARY_ACCOUNTS must not run with the operator extension absent; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("KEYHOG_AWS_CANARY_ACCOUNTS points at unreadable file")
            && stderr.contains("missing-canaries.toml")
            && stderr.contains("Fix: unset KEYHOG_AWS_CANARY_ACCOUNTS"),
        "diagnostic must name the bad canary env and the fix; stderr={stderr}"
    );
}

#[test]
fn malformed_keyhog_aws_canary_accounts_exits_two_before_scan() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("clean.txt");
    let bad_canaries = dir.path().join("bad-canaries.toml");
    std::fs::write(&target, "clean fixture\n").expect("write clean fixture");
    std::fs::write(&bad_canaries, "[canary]\naccounts = [\"1234\"]\n")
        .expect("write malformed canary fixture");

    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--backend", "cpu", "--format", "json"])
        .arg(&target)
        .env("KEYHOG_AWS_CANARY_ACCOUNTS", &bad_canaries)
        .output()
        .expect("spawn keyhog scan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "malformed KEYHOG_AWS_CANARY_ACCOUNTS must not run with the operator extension absent; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("KEYHOG_AWS_CANARY_ACCOUNTS file")
            && stderr.contains("bad-canaries.toml")
            && stderr.contains("12-digit AWS account id"),
        "diagnostic must name the malformed canary file and parser error; stderr={stderr}"
    );
}
