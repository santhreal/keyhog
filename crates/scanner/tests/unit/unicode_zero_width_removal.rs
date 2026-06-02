use keyhog_scanner::unicode_hardening::*;

/// Proving test: Multiple zero-width characters are all removed.
/// Contract: "token=abcd\u{200B}\u{200C}\u{200D}efgh" normalizes to "token=abcdefgh".
#[test]
fn normalize_removes_multiple_zero_width_characters() {
    // Mix of three different zero-width evasion characters:
    // U+200B = Zero-Width Space
    // U+200C = Zero-Width Non-Joiner
    // U+200D = Zero-Width Joiner
    let text = "token=abcd\u{200B}\u{200C}\u{200D}efgh";
    let normalized = normalize_homoglyphs(text);

    // All zero-width characters must be removed
    assert_eq!(
        normalized.as_ref(),
        "token=abcdefgh",
        "All three zero-width characters must be stripped; got: {normalized:?}"
    );

    // Result must not contain any of the zero-width characters
    assert!(!normalized.contains('\u{200B}'));
    assert!(!normalized.contains('\u{200C}'));
    assert!(!normalized.contains('\u{200D}'));

    assert!(normalized.is_ascii());
}

/// Proving test: Zero-width joiner (ZWJ) in credential body is removed.
/// Contract: normalize_homoglyphs("ghp_abc\u{200D}def") → "ghp_abcdef".
#[test]
fn normalize_removes_zero_width_joiner() {
    // Zero-Width Joiner (U+200D) between credential parts
    let text = "export PAT=\"ghp_\u{200D}abcdefghijklmnopqrstuvwxyz1234567890ab\"";
    let normalized = normalize_homoglyphs(text);

    // ZWJ must be removed, preserving the credential structure
    assert!(
        normalized.contains("ghp_abcdefghij"),
        "ZWJ (U+200D) must be removed; got: {normalized:?}"
    );
    assert!(!normalized.contains('\u{200D}'));
}

/// Proving test: BOM (U+FEFF) zero-width no-break space is removed.
/// Contract: Text starting with BOM normalizes without it.
#[test]
fn normalize_removes_bom_zero_width_no_break_space() {
    // U+FEFF can appear at start of file or embedded
    let text = "\u{FEFF}ghp_abcdefghijklmnopqrstuvwxyz1234567890ab";
    let normalized = normalize_homoglyphs(text);

    // BOM must be stripped
    assert!(
        normalized.starts_with("ghp_"),
        "BOM (U+FEFF) must be removed from start; got: {normalized:?}"
    );
    assert!(!normalized.contains('\u{FEFF}'));
}

/// Proving test: Word Joiner (U+2060) is removed.
/// Contract: normalize_homoglyphs with U+2060 removes it.
#[test]
fn normalize_removes_word_joiner() {
    // U+2060 Word Joiner
    let text = "token\u{2060}=abcd1234567890ab";
    let normalized = normalize_homoglyphs(text);

    // Word joiner must be removed
    assert!(
        normalized.contains("token=abcd"),
        "Word Joiner (U+2060) must be removed; got: {normalized:?}"
    );
    assert!(!normalized.contains('\u{2060}'));
}

/// Proving test: Directional marks (LTR/RTL marks) are removed.
/// Contract: "text\u{200E}more" normalizes to "textmore".
#[test]
fn normalize_removes_directional_marks() {
    // U+200E = Left-to-Right Mark
    // U+200F = Right-to-Left Mark
    let text = "ghp_abc\u{200E}def\u{200F}ghi";
    let normalized = normalize_homoglyphs(text);

    // Directional marks must be removed
    assert!(
        normalized.contains("ghp_abcdefghi"),
        "Directional marks (U+200E/U+200F) must be removed; got: {normalized:?}"
    );
    assert!(!normalized.contains('\u{200E}'));
    assert!(!normalized.contains('\u{200F}'));
}

/// Proving test: Directional isolate characters (U+2066-U+2069) are removed.
/// Contract: Text with LRI, RLI, FSI, PDI all strip cleanly.
#[test]
fn normalize_removes_directional_isolates() {
    // U+2066 = Left-to-Right Isolate
    // U+2067 = Right-to-Left Isolate
    // U+2068 = First Strong Isolate
    // U+2069 = Pop Directional Isolate
    let text = "sk_\u{2066}live\u{2067}secret\u{2068}key\u{2069}end";
    let normalized = normalize_homoglyphs(text);

    // All isolate characters must be removed
    assert!(
        normalized.contains("sk_livesecretkeyend"),
        "Directional isolates (U+2066-U+2069) must be removed; got: {normalized:?}"
    );
    assert!(!normalized.contains('\u{2066}'));
    assert!(!normalized.contains('\u{2067}'));
    assert!(!normalized.contains('\u{2068}'));
    assert!(!normalized.contains('\u{2069}'));
}

/// Proving test: Soft hyphen (U+00AD) adjacent to alphanumeric is removed.
/// Contract: "secret\u{00AD}123" normalizes to "secret123" (not "secret-123").
#[test]
fn normalize_removes_soft_hyphen_not_promotes_to_hyphen() {
    // U+00AD Soft Hyphen
    let text = "password\u{00AD}1234567890";
    let normalized = normalize_homoglyphs(text);

    // Soft hyphen must be removed, not converted to '-'
    assert_eq!(
        normalized.as_ref(),
        "password1234567890",
        "Soft hyphen (U+00AD) must be removed, not converted; got: {normalized:?}"
    );
    assert!(!normalized.contains('-'));
}
