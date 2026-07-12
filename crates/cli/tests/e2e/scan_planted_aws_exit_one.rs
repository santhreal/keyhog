//! E2E: planted AWS key yields exit 1.

use crate::e2e::support::scan_text_file;

#[test]
fn scan_planted_aws_exit_one() {
    let (stdout, _stderr, code) =
        scan_text_file("AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n", &[]);
    assert_eq!(code, Some(1), "planted AWS key must exit 1");
    let findings: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    let arr = findings.as_array().expect("findings must be a JSON array");
    // Law 6: pin the ACTUAL detector that must fire on an `AKIA...` key, not just
    // that *some* finding exists. The planted value is a valid-shape AWS access
    // key id, so the `aws-access-key` detector must be among the findings.
    assert!(
        arr.iter()
            .any(|f| f.get("detector_id").and_then(|v| v.as_str()) == Some("aws-access-key")),
        "aws-access-key detector must fire on the planted AKIA key; got {arr:?}"
    );
}
