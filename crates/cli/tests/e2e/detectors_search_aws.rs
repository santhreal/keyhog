//! E2E: `detectors --search aws --json` returns AWS detectors.

use crate::e2e::support::run;

#[test]
fn detectors_search_aws() {
    let output = run(&["detectors", "--search", "aws", "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let arr = serde_json::from_slice::<Vec<serde_json::Value>>(&output.stdout).expect("json");
    assert!(!arr.is_empty());
    assert!(arr
        .iter()
        .any(|d| d.get("service").and_then(|v| v.as_str()) == Some("aws")));
}
