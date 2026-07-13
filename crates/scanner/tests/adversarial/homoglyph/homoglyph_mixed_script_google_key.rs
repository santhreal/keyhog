//! R5-T-SCAN homoglyph must not evade `google-api-key` when body is real.

use crate::adversarial::oracle_support::scan_text;

#[test]
fn homoglyph_mixed_script_google_key() {
    // Cyrillic А (U+0410) replaces the leading Latin `A` of a REAL,
    // high-entropy Google API key body (`AIza` + 35 chars). Homoglyph folding
    // restores `AIza...`, so `google-api-key` fires. The body is deliberately
    // high-entropy: a sequential placeholder like `ABCDEF...XYZ` is correctly
    // suppressed as a non-secret, which is NOT what "must not evade when the
    // body is real" is testing.
    let text = "export TOKEN=\"\u{0410}IzaSyC8kPq2Lm9Rt4Vw7Xz1Bn5Df3Gj0Hs6Kp7\"";
    let tail = "SyC8kPq2Lm9Rt4Vw7Xz1Bn5Df3Gj0Hs6Kp7";
    let matches = scan_text(text, "homoglyph.env");
    assert!(
        matches.iter().any(|m| m.credential.as_ref().contains(tail)),
        "Cyrillic-prefixed AIza body must not fully evade, tail {tail:?}; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
