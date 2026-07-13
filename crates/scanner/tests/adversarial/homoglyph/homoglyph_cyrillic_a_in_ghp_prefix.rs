//! R5-T-SCAN homoglyph must not evade `github-classic-pat` when body is real.

use crate::adversarial::oracle_support::scan_text;

#[test]
fn homoglyph_cyrillic_a_in_ghp_prefix() {
    let text = "export TOKEN=\"\u{0410}hp_abcdefghijklmnopqrstuvwxyz1234567890AB\"";
    let tail = "abcdefghijklmnopqrstuvwxyz1234567890AB";
    let matches = scan_text(text, "homoglyph.env");
    assert!(
        matches.iter().any(|m| m.credential.as_ref().contains(tail)),
        "Cyrillic-prefixed ghp body must not fully evade, tail {tail:?}; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
