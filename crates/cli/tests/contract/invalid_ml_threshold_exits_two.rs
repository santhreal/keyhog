//! Contract: out-of-range `--ml-threshold` exits 2.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn invalid_ml_threshold_exits_two() {
    let output = Command::new(binary())
        .args(["scan", "--ml-threshold", "2.0", "."])
        .output()
        .expect("spawn");
    assert_eq!(
        output.status.code(),
        Some(2),
        "invalid ml-threshold must exit 2; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}
