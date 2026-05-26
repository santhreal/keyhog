//! Cyrillic homoglyphs in the `TESTKEY_` keyword prefix must normalize and
//! still surface real credentials. Negative twin uses the same homoglyph
//! prefix with a repetitive fake body that must stay suppressed.

use super::support::*;

/// Cyrillic capital Т (U+0422) and Е (U+0415) masquerading as `TE`.
const HOMOGLYPH_PREFIX: &str = "ТЕSTKEY_";

#[test]
fn homoglyph_keyword_prefix_normalizes_to_real_credential() {
    let homoglyph_cred = format!("{HOMOGLYPH_PREFIX}aK7xP9mQ2wE5rT8yU1iO");
    let body = format!("# rotated {HOMOGLYPH_PREFIX}token\nexport KEY=\"{homoglyph_cred}\"\n");
    let scanner = test_scanner();
    let matches = scanner.scan(&make_chunk(&body));
    assert!(
        matches
            .iter()
            .any(|m| m.credential.as_ref() == VALID_CREDENTIAL),
        "homoglyph keyword prefix must normalize to {VALID_CREDENTIAL}; matches={:?}",
        matches
            .iter()
            .map(|m| m.credential.as_ref())
            .collect::<Vec<_>>()
    );
}

#[test]
fn homoglyph_keyword_prefix_negative_twin_suppresses_fake() {
    let homoglyph_fake = format!("{HOMOGLYPH_PREFIX}11111111111111111111");
    let body = format!("# placeholder {HOMOGLYPH_PREFIX}token\nexport KEY=\"{homoglyph_fake}\"\n");
    assert_not_detected(&body, FAKE_CREDENTIAL);
}
