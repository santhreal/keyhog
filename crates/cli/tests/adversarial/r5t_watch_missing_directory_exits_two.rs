//! R5-T adversarial non-scan: watch on missing directory exits 2.

use crate::adversarial::support::binary;
use std::process::Command;

#[test]
fn r5t_watch_missing_directory_exits_two() {
    let output = Command::new(binary())
        .args(["watch", "/nonexistent/keyhog-r5t-watch-dir"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(2));
}
