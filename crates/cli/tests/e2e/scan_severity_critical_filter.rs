//! E2E: `--severity critical` filters low-severity noise.

use crate::e2e::support::scan_text_file;

#[test]
fn scan_severity_critical_filter() {
    let (stdout, _, code) = scan_text_file("password = \"hunter2\"\n", &["--severity", "critical"]);
    let _ = code;
    let arr = serde_json::from_str::<serde_json::Value>(&stdout)
        .expect("json")
        .as_array()
        .cloned()
        .unwrap_or_default();
    for f in &arr {
        let sev = f.get("severity").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(
            sev.to_lowercase(),
            "critical",
            "only critical findings allowed; got {f}"
        );
    }
}
