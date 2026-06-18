use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn legacy_keyhog_backend_env_is_ignored_by_explicit_backend_flag() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("clean.txt");
    std::fs::write(&target, "clean fixture\n").expect("write clean fixture");

    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--format",
            "json",
            "--backend",
            "simd",
        ])
        .arg(&target)
        .env("KEYHOG_BACKEND", "not-a-real-backend")
        .env_remove("KEYHOG_GPU_AUTOROUTE")
        .output()
        .expect("spawn keyhog scan");

    assert_eq!(
        output.status.code(),
        Some(0),
        "legacy KEYHOG_BACKEND must be ignored when explicit --backend is present; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
