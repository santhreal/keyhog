//! Contract: `--format github-annotations` emits GitHub workflow commands.

use crate::e2e::support::{binary, write_temp_file};
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

#[test]
fn clean_scan_emits_no_github_annotations() {
    let (_dir, path) = write_temp_file("clean.env", "no secrets here\n");
    let output = scan(&path);
    assert_eq!(
        output.status.code(),
        Some(0),
        "clean scan with GitHub annotations must exit 0"
    );
    assert!(
        output.stdout.is_empty(),
        "GitHub annotations must not emit an empty-report skeleton"
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
