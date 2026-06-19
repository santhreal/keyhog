use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn unreadable_keyhog_aws_canary_accounts_is_ignored() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("clean.txt");
    let missing = dir.path().join("missing-canaries.toml");
    std::fs::write(&target, "clean fixture\n").expect("write clean fixture");

    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "cpu",
            "--format",
            "json",
        ])
        .arg(&target)
        .env("KEYHOG_AWS_CANARY_ACCOUNTS", &missing)
        .output()
        .expect("spawn keyhog scan");

    assert_eq!(
        output.status.code(),
        Some(0),
        "legacy KEYHOG_AWS_CANARY_ACCOUNTS must not affect scans; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("KEYHOG_AWS_CANARY_ACCOUNTS"),
        "legacy env must be ignored without diagnostics; stderr={stderr}"
    );
}

#[test]
fn malformed_keyhog_aws_canary_accounts_is_ignored() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("clean.txt");
    let bad_canaries = dir.path().join("bad-canaries.toml");
    std::fs::write(&target, "clean fixture\n").expect("write clean fixture");
    std::fs::write(&bad_canaries, "[canary]\naccounts = [\"1234\"]\n")
        .expect("write malformed canary fixture");

    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "cpu",
            "--format",
            "json",
        ])
        .arg(&target)
        .env("KEYHOG_AWS_CANARY_ACCOUNTS", &bad_canaries)
        .output()
        .expect("spawn keyhog scan");

    assert_eq!(
        output.status.code(),
        Some(0),
        "legacy KEYHOG_AWS_CANARY_ACCOUNTS must not affect scans; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("KEYHOG_AWS_CANARY_ACCOUNTS"),
        "legacy env must be ignored without diagnostics; stderr={stderr}"
    );
}

#[test]
fn aws_canary_accounts_toml_key_reaches_scan_metadata() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("aws.txt");
    let config = dir.path().join(".keyhog.toml");
    std::fs::write(&target, "aws_access_key_id = ASIAY34FZKBOKMUTVV7A\n")
        .expect("write AWS fixture");
    std::fs::write(&config, "[aws]\ncanary_accounts = [\"609629065308\"]\n").expect("write config");

    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "cpu",
            "--format",
            "json",
            "--config",
        ])
        .arg(&config)
        .arg(&target)
        .output()
        .expect("spawn keyhog scan");

    assert_eq!(
        output.status.code(),
        Some(1),
        "configured canary account must still detect the AWS key; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let findings: serde_json::Value = serde_json::from_str(&stdout).expect("json scan output");
    let finding = findings
        .as_array()
        .and_then(|items| items.first())
        .expect("one AWS finding");
    assert_eq!(finding["detector_id"].as_str(), Some("aws-access-key"));
    assert_eq!(
        finding["metadata"]["account_id"].as_str(),
        Some("609629065308")
    );
    assert_eq!(
        finding["metadata"]["is_canary"].as_str(),
        Some("true"),
        "[aws].canary_accounts must reach offline finding metadata; finding={finding}"
    );
}
