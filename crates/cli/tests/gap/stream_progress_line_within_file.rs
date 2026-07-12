//! KH-GAP-097: `--stream` progress lines must not cite line numbers beyond file length.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn stream_progress_lines_stay_within_file_line_count() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("leak.env");
    std::fs::write(
        &path,
        "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
    )
    .expect("write fixture");

    let line_count = std::fs::read_to_string(&path)
        .expect("read fixture")
        .lines()
        .count();
    assert_eq!(
        line_count, 2,
        "fixture must stay two lines for this regression"
    );

    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--stream",
            "--fast",
            "--no-suppress-test-fixtures",
            "--format",
            "text",
        ])
        .arg(dir.path())
        .output()
        .expect("spawn");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    for line in combined.lines().filter(|l| l.starts_with("[stream]")) {
        if let Some(colon) = line.rfind(':') {
            let tail = &line[colon + 1..];
            if let Some(space) = tail.find(' ') {
                if let Ok(n) = tail[..space].trim().parse::<usize>() {
                    assert!(
                        n <= line_count,
                        "stream line cited :{n} but file has {line_count} lines: {line}"
                    );
                }
            }
        }
    }
}
