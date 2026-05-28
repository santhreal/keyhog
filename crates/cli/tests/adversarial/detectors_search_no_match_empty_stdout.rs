//! Adversarial: detectors --search gibberish returns no false positives.

use crate::adversarial::support::binary;
use std::process::Command;

#[test]
fn detectors_search_no_match_empty_stdout() {
    let output = Command::new(binary())
        .args(["detectors", "--search", "keyhog-adversarial-zzzz-no-match"])
        .output()
        .expect("spawn detectors --search");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("aws-access-key"),
        "search with no match must not emit unrelated detectors; got: {stdout}"
    );
}
