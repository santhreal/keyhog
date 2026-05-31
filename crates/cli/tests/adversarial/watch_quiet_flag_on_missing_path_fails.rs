//! Adversarial: watch --quiet on missing path still fails fast.

use crate::support::binary;
use std::process::Command;

#[test]
fn watch_quiet_flag_on_missing_path_fails() {
    let output = Command::new(binary())
        .args(["watch", "--quiet", "/nonexistent/keyhog-watch-quiet"])
        .output()
        .expect("spawn watch --quiet");
    assert_ne!(output.status.code(), Some(0));
    let combined = format!(
        "{}
{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("watch") || combined.contains("canonicalize"),
        "quiet watch on bad path must still fail; got: {combined}"
    );
}
