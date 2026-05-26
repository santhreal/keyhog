//! Contract: `explain` with unknown detector id exits 2.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn explain_unknown_detector_exits_two() {
    let output = Command::new(binary()).args(["explain", "no-such-detector-xyzzy"]).output().expect("spawn");
    assert_eq!(output.status.code(), Some(2), "unknown detector must exit 2; stderr={}", String::from_utf8_lossy(&output.stderr));
}
