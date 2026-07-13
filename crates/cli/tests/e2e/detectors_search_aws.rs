//! E2E: `detectors --search aws --format json` returns AWS detectors.

use crate::e2e::support::run;

#[test]
fn detectors_search_aws() {
    let output = run(&["detectors", "--search", "aws", "--format", "json"]);
    assert_eq!(output.status.code(), Some(0));
    let arr = serde_json::from_slice::<Vec<serde_json::Value>>(&output.stdout).expect("json");
    // Truth assert: the canonical aws-access-key detector (service=aws) is in the
    // search results (not merely "some non-empty list").
    assert!(
        arr.iter().any(|d| {
            d.get("id").and_then(|v| v.as_str()) == Some("aws-access-key")
                && d.get("service").and_then(|v| v.as_str()) == Some("aws")
        }),
        "`detectors --search aws --format json` must include aws-access-key (service=aws); got {arr:?}"
    );
}
