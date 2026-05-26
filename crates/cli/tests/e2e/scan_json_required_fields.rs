//! E2E: JSON findings carry required contract fields.

use crate::e2e::support::scan_text_file;

#[test]
fn scan_json_required_fields() {
    let (stdout, _, _) = scan_text_file(
        "GH_TOKEN = \"ghp_aBcD1234EFgh5678ijkl9012MNop3456qrST\"\n",
        &[],
    );
    let arr = serde_json::from_str::<serde_json::Value>(&stdout)
        .expect("json")
        .as_array()
        .expect("array")
        .clone();
    assert!(!arr.is_empty());
    for f in &arr {
        for field in [
            "detector_id",
            "detector_name",
            "service",
            "severity",
            "credential_redacted",
            "location",
        ] {
            assert!(f.get(field).is_some(), "missing {field}: {f}");
        }
    }
}
