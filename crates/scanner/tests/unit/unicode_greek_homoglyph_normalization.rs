use keyhog_scanner::unicode_hardening::*;

/// Proving test: Greek homoglyphs normalize to Latin equivalents.
/// Contract: normalize_homoglyphs("sk_αbc") produces "sk_abc" (Greek α U+03B1 → 'a').
#[test]
fn normalize_greek_alpha_in_credential_body() {
    // Greek alpha (U+03B1) looks like 'a' but is a different character
    let text = "export SK_LIVE_\u{03B1}bcdefghijklmnopqrst";
    let normalized = normalize_homoglyphs(text);

    // The normalized string must contain the converted ASCII form
    assert!(
        normalized.contains("_abcdefghij"),
        "Greek alpha (U+03B1) must normalize to 'a'; got: {normalized:?}"
    );

    // Must be different from original (because we did convert something)
    assert_ne!(
        normalized.as_ref(),
        text,
        "Normalization should change Greek α to ASCII 'a'"
    );

    // The bytes after normalization must be all-ASCII
    assert!(
        normalized.is_ascii(),
        "Normalized text should be ASCII; got: {normalized:?}"
    );
}

/// Proving test: Greek lowercase rho normalizes correctly.
/// Contract: normalize_homoglyphs with Greek ρ (U+03C1) produces Latin 'p'.
#[test]
fn normalize_greek_rho_to_p() {
    // Greek lowercase rho (U+03C1) looks like 'p'
    let text = "ghp_\u{03C1}assword123456789";
    let normalized = normalize_homoglyphs(text);

    // Must produce ASCII 'p' in place of Greek ρ
    assert!(
        normalized.contains("ghp_password"),
        "Greek rho (U+03C1) must normalize to 'p'; got: {normalized:?}"
    );
    assert!(normalized.is_ascii());
}

/// Proving test: Uppercase Greek homoglyphs convert to uppercase Latin.
/// Contract: Greek uppercase Κ (U+039A) normalizes to 'K'.
#[test]
fn normalize_uppercase_greek_kappa() {
    // Greek uppercase Kappa (U+039A) looks like 'K'
    let text = "AKIAIOSFODNN\u{039A}EXAMPLE";
    let normalized = normalize_homoglyphs(text);

    // Must produce uppercase 'K' in place of Greek Κ
    assert!(
        normalized.contains("AKIAIOSFODNNKEXAMPLE"),
        "Greek Kappa (U+039A) must normalize to 'K'; got: {normalized:?}"
    );
    assert!(normalized.is_ascii());
}

/// Proving test: Multiple Greek characters normalize independently.
/// Contract: "αlphα" with Greek α at positions 0 and 5 both convert to 'a'.
#[test]
fn normalize_multiple_greek_alphas() {
    // Greek alpha at multiple positions
    let text = "\u{03B1}PPLE_\u{03B1}pple";
    let normalized = normalize_homoglyphs(text);

    // Both Greek alphas must be converted. U+03B1 is LOWERCASE alpha, whose
    // case-preserving Latin homoglyph is lowercase 'a' (the uppercase mapping
    // Α→A is covered by the Greek-Kappa test above), so the leading α becomes
    // 'a' and the result is "aPPLE_apple", not "APPLE_apple".
    assert_eq!(
        normalized.as_ref(),
        "aPPLE_apple",
        "Multiple Greek α characters must all normalize; got: {normalized:?}"
    );
    assert!(normalized.is_ascii());
}
