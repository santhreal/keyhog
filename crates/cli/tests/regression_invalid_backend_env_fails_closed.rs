use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn invalid_keyhog_backend_env_exits_two_before_scan() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("clean.txt");
    std::fs::write(&target, "clean fixture\n").expect("write clean fixture");

    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--format", "json"])
        .arg(&target)
        .env("KEYHOG_BACKEND", "not-a-real-backend")
        .env_remove("KEYHOG_GPU_AUTOROUTE")
        .output()
        .expect("spawn keyhog scan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "invalid KEYHOG_BACKEND must be a user error, not an auto-routed scan; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid KEYHOG_BACKEND value")
            && stderr.contains("not-a-real-backend")
            && stderr.contains("Fix: unset KEYHOG_BACKEND"),
        "diagnostic must name the bad env value and the operator fix; stderr={stderr}"
    );
}
