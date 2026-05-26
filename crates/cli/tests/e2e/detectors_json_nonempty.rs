//! E2E: `detectors --json` returns a large array.

use crate::e2e::support::run;

#[test]
fn detectors_json_nonempty() {
    let output = run(&["detectors", "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let arr = serde_json::from_slice::<Vec<serde_json::Value>>(&output.stdout).expect("json array");
    assert!(arr.len() > 100, "expected hundreds of detectors; got {}", arr.len());
}
