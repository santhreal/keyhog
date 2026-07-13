//! R5-T-SCAN homoglyph must not evade `npm-access-token` when body is real.

use crate::adversarial::oracle_support::scan_text;

#[test]
fn homoglyph_cyrillic_in_npm_token() {
    let text = "export NPM_TOKEN=\"npm_\u{0410}BCDEFGHIJKLMNOPQRSTUVWXYZ1234567890AB\"";
    let tail = "BCDEFGHIJKLMNOPQRSTUVWXYZ1234567890AB";
    let matches = scan_text(text, "homoglyph.env");
    assert!(
        matches.iter().any(|m| m.credential.as_ref().contains(tail)),
        "Cyrillic homoglyph npm token must not fully evade, tail {tail:?}; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
