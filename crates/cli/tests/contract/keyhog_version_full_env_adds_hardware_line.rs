//! Contract: KEYHOG_VERSION_FULL=1 adds hardware probe line to --version.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn keyhog_version_full_env_adds_hardware_line() {
    let default = Command::new(binary()).arg("--version").output().expect("spawn");
    let full = Command::new(binary()).env("KEYHOG_VERSION_FULL", "1").arg("--version").output().expect("spawn");
    assert_eq!(default.status.code(), Some(0));
    assert_eq!(full.status.code(), Some(0));
    let default_out = String::from_utf8_lossy(&default.stdout);
    let full_out = String::from_utf8_lossy(&full.stdout);
    assert!(full_out.lines().count() > default_out.lines().count(), "KEYHOG_VERSION_FULL must add extra version lines; default={default_out:?} full={full_out:?}");
}
