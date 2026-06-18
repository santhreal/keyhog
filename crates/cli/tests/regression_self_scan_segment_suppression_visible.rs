use std::path::PathBuf;
use std::process::Command;

use tempfile::Builder;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

#[test]
fn self_scan_segment_suppression_is_reported() {
    let root = repo_root();
    let dir = Builder::new()
        .prefix("keyhog-self-scan-segment-")
        .tempdir_in(&root)
        .expect("tempdir in repo");
    let fixtures_dir = dir.path().join("fixtures");
    std::fs::create_dir_all(&fixtures_dir).expect("mkdir fixtures");
    std::fs::write(
        fixtures_dir.join("leak.env"),
        concat!("AWS_ACCESS_KEY_ID=\"AKIA", "QYLPMN5HFIQR7XYA\"\n"),
    )
    .expect("write leak");

    let output = Command::new(binary())
        .current_dir(&root)
        .arg("scan")
        .arg("--no-daemon")
        .arg("--backend")
        .arg("cpu")
        .arg(dir.path())
        .output()
        .expect("spawn keyhog scan");

    assert_eq!(
        output.status.code(),
        Some(0),
        "self-scan test-data suppression should leave no reportable finding; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("No real secrets, but ") && stdout.contains("example/test key"),
        "self-scan segment suppression must be visible in the text report; stdout={stdout}; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}
