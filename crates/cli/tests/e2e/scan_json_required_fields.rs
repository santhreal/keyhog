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
    assert_eq!(
        arr.len(),
        1,
        "exactly one finding for the planted ghp_ token"
    );
    // Truth: identity of the single finding, not just that fields exist.
    let only = &arr[0];
    assert_eq!(only["detector_id"], "github-classic-pat");
    assert_eq!(only["service"], "github");
    assert_eq!(only["severity"], "critical");
    assert_eq!(only["credential_redacted"], "ghp_...qrST");
    assert_eq!(only["location"]["line"], 1);
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
