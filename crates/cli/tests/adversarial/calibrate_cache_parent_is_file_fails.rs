//! Adversarial: calibrate --cache pointing at a directory/file mismatch fails.

use crate::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn calibrate_cache_parent_is_file_fails() {
    let dir = TempDir::new().expect("tempdir");
    let cache = dir.path().join("cache.json");
    std::fs::write(&cache, "{}").unwrap();
    let output = Command::new(binary())
        .args(["calibrate", "--show", "--cache"])
        .arg(cache.parent().unwrap())
        .output()
        .expect("spawn calibrate --show");
    assert_ne!(output.status.code(), Some(0));
    let combined = format!(
        "{}
{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("calibr")
            || combined.contains("cache")
            || combined.contains("Is a directory"),
        "calibrate with directory cache path must fail; got: {combined}"
    );
}
