//! E2E: planted AWS key yields exit 1.

use crate::e2e::support::scan_text_file;

#[test]
fn scan_planted_aws_exit_one() {
    let (stdout, _stderr, code) =
        scan_text_file("AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n", &[]);
    assert_eq!(code, Some(1), "planted AWS key must exit 1");
    let findings: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert!(findings.as_array().is_some_and(|a| !a.is_empty()));
}
