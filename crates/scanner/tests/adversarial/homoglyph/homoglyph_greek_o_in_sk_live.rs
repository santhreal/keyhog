//! R5-T-SCAN homoglyph must not evade `stripe-secret-key` when body is real.

use crate::adversarial::oracle_support::scan_text;

#[test]
fn homoglyph_greek_o_in_sk_live() {
    let text = "export TOKEN=\"sk_\u{039f}ive_abcdefghijklmnopqrstuvwxyz\"";
    let tail = "abcdefghijklmnopqrstuvwxyz";
    let matches = scan_text(text, "homoglyph.env");
    assert!(
        matches.iter().any(|m| m.credential.as_ref().contains(tail)),
        "Greek-o homoglyph sk_live body must not fully evade — tail {tail:?}; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
