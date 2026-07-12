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

fn write_repo_local_fixture() -> (tempfile::TempDir, PathBuf) {
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
    (dir, root)
}

#[test]
fn self_scan_segment_suppression_is_reported() {
    let (dir, root) = write_repo_local_fixture();
    let output = Command::new(binary())
        .current_dir(&root)
        .arg("scan")
        .arg("--daemon=off")
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

#[test]
fn self_scan_segment_suppression_opt_out_reports_real_leak() {
    let (dir, root) = write_repo_local_fixture();
    let output = Command::new(binary())
        .current_dir(&root)
        .arg("scan")
        .arg("--daemon=off")
        .arg("--backend")
        .arg("cpu")
        .arg("--no-suppress-test-fixtures")
        .arg("--show-secrets")
        .arg(dir.path())
        .output()
        .expect("spawn keyhog scan");

    assert_eq!(
        output.status.code(),
        Some(1),
        "--no-suppress-test-fixtures must surface the repo-local fixture leak; stdout={}; stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("AWS Access Key")
            && stdout.contains("Secret:")
            && stdout.contains("AKIAQYLPMN5HFIQR7XYA"),
        "opt-out self-scan must report the real AWS key, not only disable the summary; stdout={stdout}; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !stdout.contains("No real secrets"),
        "opt-out self-scan must not keep the empty suppressed-summary path; stdout={stdout}"
    );
}
