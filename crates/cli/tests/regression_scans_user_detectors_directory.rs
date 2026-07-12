use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn scan_reports_secret_under_user_detectors_directory() {
    let dir = TempDir::new().expect("tempdir");
    let detectors_dir = dir.path().join("detectors");
    std::fs::create_dir_all(&detectors_dir).expect("mkdir detectors");
    let leak_path = detectors_dir.join("leak.env");
    std::fs::write(
        &leak_path,
        concat!("AWS_ACCESS_KEY_ID=\"AKIA", "QYLPMN5HFIQR7XYA\"\n"),
    )
    .expect("write leak");

    let output = Command::new(binary())
        .arg("scan")
        .arg("--daemon=off")
        .arg("--backend")
        .arg("cpu")
        .arg("--format")
        .arg("json")
        .arg(dir.path())
        .output()
        .expect("spawn keyhog scan");

    assert_eq!(
        output.status.code(),
        Some(1),
        "planted key under detectors/ must produce findings; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let findings: Vec<serde_json::Value> =
        serde_json::from_str(&stdout).expect("stdout is JSON findings");
    let aws = findings.iter().find(|finding| {
        let detector_id = finding.get("detector_id").and_then(|value| value.as_str());
        let file_path = finding
            .get("location")
            .and_then(|value| value.get("file_path"))
            .and_then(|value| value.as_str());
        matches!(detector_id, Some("aws-access-key" | "hot-aws_key"))
            && file_path.is_some_and(|path| path.ends_with("detectors/leak.env"))
    });
    assert!(
        aws.is_some(),
        "expected AWS finding from detectors/leak.env; findings={findings:?}; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}
