//! R5-T-SCAN homoglyph must not evade `google-api-key` when body is real.

#[path = "../oracle_support.rs"]
mod oracle_support;
use oracle_support::scan_text;

#[test]
fn homoglyph_mixed_script_google_key() {
    let text = "export TOKEN=\"\u{0410}IzaSyABCDEFGHIJKLMNOPQRSTUVWXYZabcd\"";
    let tail = "SyABCDEFGHIJKLMNOPQRSTUVWXYZabcd";
    let matches = scan_text(text, "homoglyph.env");
    assert!(
        matches.iter().any(|m| m.credential.as_ref().contains(tail)),
        "Cyrillic-prefixed AIza body must not fully evade — tail {tail:?}; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
