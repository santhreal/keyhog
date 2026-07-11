//! E2E: `detectors --format json` returns the embedded detector array.

use crate::e2e::support::run;

#[test]
fn detectors_json_nonempty() {
    let output = run(&["detectors", "--format", "json"]);
    assert_eq!(output.status.code(), Some(0));
    let arr = serde_json::from_slice::<Vec<serde_json::Value>>(&output.stdout).expect("json array");
    assert!(
        arr.len() > 100,
        "expected hundreds of detectors; got {}",
        arr.len()
    );
    // Law 6: pin that specific well-known detectors are actually present, not
    // just that the array is large (a corrupt list of the wrong 100 detectors
    // would pass a length-only check).
    let stdout = String::from_utf8_lossy(&output.stdout);
    for id in ["aws-access-key", "github-classic-pat", "slack-bot-token"] {
        assert!(
            stdout.contains(id),
            "`detectors --format json` must include {id}; got {} detectors",
            arr.len()
        );
    }
}
