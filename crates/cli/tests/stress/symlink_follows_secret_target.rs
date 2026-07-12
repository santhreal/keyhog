//! R5-D2 / KH-GAP-170: directory walks must follow symlinks to readable targets.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[cfg(unix)]
#[test]
fn symlink_follows_secret_target_exit_one() {
    let dir = TempDir::new().expect("tempdir");
    let real = dir.path().join("real.env");
    std::fs::write(&real, "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n").expect("write real secret");
    std::os::unix::fs::symlink(&real, dir.path().join("link.env")).expect("symlink");

    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "simd",
            "--format",
            "json",
            "--no-suppress-test-fixtures",
        ])
        .arg(dir.path())
        .output()
        .expect("spawn");

    assert_eq!(
        output.status.code(),
        Some(1),
        "symlinked secret must exit 1; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(not(unix))]
#[test]
fn symlink_follows_secret_target_exit_one() {}
