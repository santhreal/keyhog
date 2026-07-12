//! Regression: expired `.keyhogignore` entries are policy errors, not silent
//! drops that let a scan continue under a stale suppression contract.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn scan_rejects_expired_keyhogignore_policy() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join(".keyhogignore"),
        "detector:aws-access-key ; expires=1970-01-01 ; reason=\"old waiver\"\n",
    )
    .expect("write expired allowlist");
    std::fs::write(
        dir.path().join("secret.env"),
        concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\n"),
    )
    .expect("write fixture");

    let output = Command::new(binary())
        .args(["scan", "--backend", "cpu", "--daemon=off"])
        .arg(dir.path())
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn keyhog scan");

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "expired allowlist policy must be a user-error exit; got: {combined}"
    );
    assert!(
        combined.contains(".keyhogignore")
            && combined.contains("expired allowlist policy")
            && combined.contains("line 1")
            && combined.contains("1970-01-01")
            && combined.contains("refusing to scan with stale suppressions"),
        "expired allowlist failure must be operator-visible; got: {combined}"
    );
}
