//! CLI must reject scan of non-existent path with non-zero exit.

use std::process::Command;

#[test]
fn scan_missing_path_exits_non_zero() {
    let bin = env!("CARGO_BIN_EXE_keyhog");
    let out = Command::new(bin)
        .args(["scan", "/nonexistent/keyhog-missing-path-xyzzy"])
        .output()
        .expect("spawn keyhog scan");
    assert_ne!(
        out.status.code(),
        Some(0),
        "scan of missing path must not exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}
