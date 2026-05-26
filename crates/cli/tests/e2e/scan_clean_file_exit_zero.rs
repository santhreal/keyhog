//! E2E: clean file yields exit 0.

use crate::e2e::support::scan_text_file;

#[test]
fn scan_clean_file_exit_zero() {
    let (stdout, _stderr, code) = scan_text_file("fn main() {}\n", &[]);
    assert_eq!(code, Some(0));
    let findings: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert!(findings.as_array().is_some_and(|a| a.is_empty()));
}
