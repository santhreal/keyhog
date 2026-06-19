//! Contract: `keyhog --version --full` is explicit, env-free hardware output.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn keyhog_version_full_env_is_ignored() {
    let default = Command::new(binary())
        .arg("--version")
        .output()
        .expect("spawn default version");
    let env_full = Command::new(binary())
        .env("KEYHOG_VERSION_FULL", "1")
        .arg("--version")
        .output()
        .expect("spawn env version");

    assert_eq!(default.status.code(), Some(0));
    assert_eq!(env_full.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&env_full.stdout),
        String::from_utf8_lossy(&default.stdout),
        "KEYHOG_VERSION_FULL must not change version output; use --version --full"
    );
}

#[test]
fn version_full_flag_adds_hardware_lines() {
    let default = Command::new(binary())
        .arg("--version")
        .output()
        .expect("spawn default version");
    let full = Command::new(binary())
        .args(["--version", "--full"])
        .output()
        .expect("spawn full version");

    assert_eq!(default.status.code(), Some(0));
    assert_eq!(full.status.code(), Some(0));
    let default_out = String::from_utf8_lossy(&default.stdout);
    let full_out = String::from_utf8_lossy(&full.stdout);
    assert!(
        full_out.lines().count() > default_out.lines().count()
            && (full_out.contains("GPU Acceleration:") || full_out.contains("SIMD Regex:")),
        "--version --full must add hardware probe lines; default={default_out:?} full={full_out:?}"
    );
}

#[test]
fn version_full_flag_requires_version() {
    let output = Command::new(binary())
        .arg("--full")
        .output()
        .expect("spawn --full");

    assert_eq!(
        output.status.code(),
        Some(2),
        "--full without --version must be rejected by clap"
    );
}
