//! Contract: `--format github-annotations` emits GitHub workflow commands.

use crate::support::{binary, write_temp_file};
use std::process::Command;

fn scan(path: &std::path::Path) -> std::process::Output {
    Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "simd",
            "--format",
            "github-annotations",
        ])
        .arg(path)
        .output()
        .expect("spawn keyhog scan --format github-annotations")
}

fn scan_directory_with_cap(path: &std::path::Path) -> std::process::Output {
    Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "simd",
            "--max-file-size",
            "15B",
            "--format",
            "github-annotations",
        ])
        .arg(path)
        .output()
        .expect("spawn capped keyhog scan --format github-annotations")
}

#[test]
fn clean_scan_emits_success_status_notice() {
    let (_dir, path) = write_temp_file("clean.env", "no secrets here\n");
    let output = scan(&path);
    assert_eq!(
        output.status.code(),
        Some(0),
        "clean scan with GitHub annotations must exit 0"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "::notice title=keyhog scan::scan status: success\n",
        "clean annotation output must carry an explicit terminal status"
    );
}

#[test]
fn planted_secret_emits_github_error_annotation() {
    let plaintext = "AKIAKPQXRMSNTBVWYZBN";
    let (_dir, path) = write_temp_file(
        "secret.env",
        &format!("clean line\nAWS_ACCESS_KEY_ID={plaintext}\n"),
    );
    let output = scan(&path);
    assert_eq!(
        output.status.code(),
        Some(1),
        "planted unverified secret must exit 1"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("::error "),
        "high-severity AWS finding must render as a GitHub error annotation: {stdout:?}"
    );
    assert!(
        stdout.contains("file=") && stdout.contains(",line=2,"),
        "annotation must carry file and one-based line number: {stdout:?}"
    );
    assert!(
        stdout.contains("title=keyhog"),
        "annotation must carry a title property: {stdout:?}"
    );
    assert!(
        stdout.contains("redacted=AK...BN"),
        "annotation message must carry the redacted credential: {stdout:?}"
    );
    assert!(
        !stdout.contains(plaintext),
        "annotation output must not leak plaintext credentials"
    );
}

#[test]
fn partial_scan_emits_github_coverage_warning() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("small.txt"), "plain text\n").expect("small fixture");
    std::fs::write(dir.path().join("large.txt"), "this file exceeds the cap\n")
        .expect("large fixture");

    let output = scan_directory_with_cap(dir.path());
    assert_eq!(
        output.status.code(),
        Some(13),
        "partial scan must retain the coverage-gap exit code"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("::warning title=keyhog coverage::partial scan coverage:")
            && stdout.contains("exceeded --max-file-size=1"),
        "GitHub annotations must surface partial coverage in the job log: {stdout:?}"
    );
}
