//! Adversarial: watch on missing path must fail before blocking.

use crate::adversarial::support::binary;
use std::process::Command;

#[test]
fn watch_nonexistent_path_exits_before_blocking() {
    let output = Command::new(binary())
        .args(["watch", "/nonexistent/keyhog-adversarial-watch"])
        .output()
        .expect("spawn watch");
    assert_ne!(
        output.status.code(),
        Some(0),
        "watch on missing path must fail; stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    let combined = format!(
        "{}
{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("watch") || combined.contains("canonicalize"),
        "watch missing path must fail with actionable message; got: {combined}"
    );
}
