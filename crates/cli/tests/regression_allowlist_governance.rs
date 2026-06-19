//! Regression coverage for `[allowlist]` config governance wiring.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

const PLANTED_AWS: &str = concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\n");

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

fn run_scan(dir: &TempDir) -> (String, String, Option<i32>) {
    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "simd",
            "--format",
            "json",
        ])
        .arg(dir.path())
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn keyhog scan");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code(),
    )
}

fn fixture_dir(config: &str, allowlist: &str) -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join(".keyhog.toml"), config).expect("write config");
    std::fs::write(dir.path().join(".keyhogignore"), allowlist).expect("write allowlist");
    std::fs::write(dir.path().join("secret.env"), PLANTED_AWS).expect("write fixture");
    dir
}

#[test]
fn scan_rejects_allowlist_entry_missing_required_reason() {
    let dir = fixture_dir(
        "[allowlist]\nrequire_reason = true\n",
        "detector:aws-access-key\n",
    );
    let (stdout, stderr, code) = run_scan(&dir);
    let combined = format!("{stdout}\n{stderr}");

    assert_eq!(
        code,
        Some(2),
        "missing allowlist reason must be a user/config error; got: {combined}"
    );
    assert!(
        stdout.is_empty(),
        "allowlist policy failure must stop before JSON report output; stdout={stdout}"
    );
    assert!(
        combined.contains("allowlist governance")
            && combined.contains("line 1")
            && combined.contains("reason")
            && combined.contains("refusing to scan with unapproved suppressions"),
        "allowlist governance failure must be operator-visible; got: {combined}"
    );
}

#[test]
fn scan_rejects_allowlist_entry_beyond_configured_expiry_window() {
    let dir = fixture_dir(
        "[allowlist]\nmax_expires_days = 90\n",
        "detector:aws-access-key ; reason=\"known fixture\" ; approved_by=\"sec@example.com\" ; expires=2999-01-01\n",
    );
    let (stdout, stderr, code) = run_scan(&dir);
    let combined = format!("{stdout}\n{stderr}");

    assert_eq!(
        code,
        Some(2),
        "overlong allowlist expiry must be a user/config error; got: {combined}"
    );
    assert!(
        combined.contains("expires=2999-01-01")
            && combined.contains("more than 90 days")
            && combined.contains("line 1"),
        "expiry-window failure must name the bad date and limit; got: {combined}"
    );
}

#[test]
fn scan_uses_configured_allowlist_file() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join(".keyhog.toml"),
        "[allowlist]\nfile = \"custom.ignore\"\n",
    )
    .expect("write config");
    std::fs::write(dir.path().join("custom.ignore"), "path:**/secret.env\n")
        .expect("write configured allowlist");
    std::fs::write(dir.path().join("secret.env"), PLANTED_AWS).expect("write fixture");

    let (stdout, stderr, code) = run_scan(&dir);
    assert_eq!(
        code,
        Some(0),
        "[allowlist].file must select the configured suppression file; stdout={stdout}\nstderr={stderr}"
    );
    let findings: serde_json::Value = serde_json::from_str(&stdout).expect("json findings");
    assert_eq!(
        findings.as_array().map(Vec::len),
        Some(0),
        "configured allowlist must suppress the planted AWS key; stdout={stdout}"
    );
}
