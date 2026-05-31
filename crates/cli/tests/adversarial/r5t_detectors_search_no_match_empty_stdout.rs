//! R5-T adversarial non-scan: detectors search with no match yields empty stdout.

use crate::support::binary;
use std::process::Command;

#[test]
fn r5t_detectors_search_no_match_empty_stdout() {
    let output = Command::new(binary())
        .args(["detectors", "--search", "zzzz-no-detector-r5t-xyzzy"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    assert!(
        output.stdout.is_empty(),
        "no-match search must emit empty stdout"
    );
}
