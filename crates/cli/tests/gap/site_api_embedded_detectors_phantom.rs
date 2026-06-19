//! KH-GAP-144: site/api.html still documents phantom `embedded_detectors()`
//! after KH-GAP-107 fixed README only.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

#[test]
fn site_api_pages_use_embedded_detector_tomls_not_phantom_fn() {
    for rel in ["site/api.html", "site/pages/api.html"] {
        let html = std::fs::read_to_string(repo_root().join(rel)).expect(rel);
        assert!(
            !html.contains("embedded_detectors()"),
            "{rel} must not document phantom embedded_detectors(); use load_embedded_detectors_or_fail()"
        );
        assert!(
            !html.contains("embedded_detector_tomls()"),
            "{rel} must not show private embedded_detector_tomls() loader"
        );
        assert!(
            html.contains("load_embedded_detectors_or_fail()"),
            "{rel} must show fail-closed embedded detector loader"
        );
    }
}
