//! KH-GAP-148: `scan --git-history` on a non-repo printed "Your code is clean"
//! before bailing with source error (CI false-clean UX).

use crate::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn git_history_on_non_repository_does_not_print_clean_summary() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("plain.txt"), "hello\n").expect("write");

    let output = Command::new(binary())
        .args(["scan", "--daemon=off", "--git-history"])
        .arg(dir.path())
        .output()
        .expect("spawn");

    assert_ne!(output.status.code(), Some(0));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("Your code is clean"),
        "source failure must not print clean-repo summary; combined={combined}"
    );
}
