//! R5-T-SCAN homoglyph must not evade `slack-bot-token` when body is real.

#[path = "../oracle_support.rs"]
mod oracle_support;
use oracle_support::scan_text;

#[test]
fn homoglyph_cyrillic_e_in_xoxb() {
    let text = "export TOKEN=\"x\u{0435}xb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx\"";
    let tail = "1234567890-1234567890123-abcdefghijklmnopqrstuvwx";
    let matches = scan_text(text, "homoglyph.env");
    assert!(
        matches.iter().any(|m| m.credential.as_ref().contains(tail)),
        "Cyrillic-e homoglyph xoxb body must not fully evade — tail {tail:?}; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
