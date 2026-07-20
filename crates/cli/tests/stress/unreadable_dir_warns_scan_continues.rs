//! R5-D2 / KH-GAP-171: permission-denied entries warn on stderr but scan continues.

use crate::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[cfg(unix)]
#[test]
fn unreadable_dir_warns_scan_continues_exit_one() {
    let dir = TempDir::new().expect("tempdir");
    let readable = dir.path().join("readable.env");
    std::fs::write(&readable, "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n")
        .expect("write readable secret");
    let denied = dir.path().join("denied");
    std::fs::create_dir(&denied).expect("mkdir denied");
    std::fs::write(denied.join("hidden.env"), "AWS_ACCESS_KEY_ID=AKIA\n").expect("write hidden");
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");

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

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Permission denied") || stderr.contains("unreadable"),
        "must warn about unreadable entry; stderr={stderr}"
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "readable symlink target must still be found; stderr={stderr}"
    );

    let _ = std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o700));
}

#[cfg(unix)]
#[test]
fn unreadable_dir_without_findings_exits_source_failed() {
    let dir = TempDir::new().expect("tempdir");
    let readable = dir.path().join("readable.txt");
    std::fs::write(&readable, "ordinary prose with no credential\n").expect("write readable file");
    let denied = dir.path().join("denied");
    std::fs::create_dir(&denied).expect("mkdir denied");
    std::fs::write(
        denied.join("hidden.env"),
        "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n",
    )
    .expect("write hidden");
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");

    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "simd",
            "--format",
            "json",
        ])
        .arg(dir.path())
        .output()
        .expect("spawn");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Permission denied")
            || stderr.contains("unreadable")
            || stderr.contains("input coverage was incomplete"),
        "must explain unreadable incomplete coverage; stderr={stderr}"
    );
    assert_eq!(
        output.status.code(),
        Some(13),
        "unreadable input with zero findings must not report clean; stderr={stderr}"
    );

    let _ = std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
#[test]
fn unreadable_dir_warns_scan_continues_exit_one() {}

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
