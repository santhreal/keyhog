use keyhog_scanner::unicode_hardening::*;

/// Proving test: Right-to-Left Override (U+202E) is removed.
/// Contract: "ghp_\u{202E}secret" normalizes to "ghp_secret".
#[test]
fn normalize_removes_rtl_override() {
    // U+202E Right-to-Left Override — used to flip text display
    let text = "ghp_\u{202E}abcdefghijklmnopqrstuvwxyz1234567890ab";
    let normalized = normalize_homoglyphs(text);

    // RTL override must be removed
    assert!(
        normalized.contains("ghp_abc"),
        "RTL Override (U+202E) must be removed; got: {normalized:?}"
    );
    assert!(!normalized.contains('\u{202E}'));
    assert!(normalized.is_ascii());
}

/// Proving test: Left-to-Right Override (U+202D) is removed.
/// Contract: normalize_homoglyphs with U+202D strips it.
#[test]
fn normalize_removes_ltr_override() {
    // U+202D Left-to-Right Override
    let text = "token\u{202D}=secret123456789";
    let normalized = normalize_homoglyphs(text);

    // LTR override must be removed
    assert!(
        normalized.contains("token=secret"),
        "LTR Override (U+202D) must be removed; got: {normalized:?}"
    );
    assert!(!normalized.contains('\u{202D}'));
}

/// Proving test: Left-to-Right Embedding (U+202A) is removed.
/// Contract: Text with LRE removes it while preserving credential body.
#[test]
fn normalize_removes_ltr_embedding() {
    // U+202A Left-to-Right Embedding
    let text = "export PAT=\"ghp_\u{202A}abcdefghijklmnopqrstuvwxyz1234567890ab\"";
    let normalized = normalize_homoglyphs(text);

    // LRE must be removed
    assert!(
        normalized.contains("ghp_abcdef"),
        "LTR Embedding (U+202A) must be removed; got: {normalized:?}"
    );
    assert!(!normalized.contains('\u{202A}'));
}

/// Proving test: Right-to-Left Embedding (U+202B) is removed.
/// Contract: normalize_homoglyphs with U+202B strips it.
#[test]
fn normalize_removes_rtl_embedding() {
    // U+202B Right-to-Left Embedding
    let text = "sk_live\u{202B}secret";
    let normalized = normalize_homoglyphs(text);

    // RLE must be removed
    assert!(
        normalized.contains("sk_livesecret"),
        "RTL Embedding (U+202B) must be removed; got: {normalized:?}"
    );
    assert!(!normalized.contains('\u{202B}'));
}

/// Proving test: Pop Directional Formatting (U+202C) is removed.
/// Contract: "text\u{202C}more" normalizes to "textmore".
#[test]
fn normalize_removes_pop_directional_formatting() {
    // U+202C Pop Directional Formatting — terminates embedding/override
    let text = "ghp_\u{202E}abcd\u{202C}efgh";
    let normalized = normalize_homoglyphs(text);

    // Both the RTL override and the pop formatting must be removed
    assert!(
        normalized.contains("ghp_abcdefgh"),
        "Pop Directional Formatting (U+202C) must be removed; got: {normalized:?}"
    );
    assert!(!normalized.contains('\u{202E}'));
    assert!(!normalized.contains('\u{202C}'));
}

/// Proving test: Multiple RTL control characters are all removed.
/// Contract: RTL override followed by embeddings all strip cleanly.
#[test]
fn normalize_removes_multiple_rtl_controls() {
    // Adversarial sequence: override → embedding → pop
    let text = "token\u{202E}\u{202B}\u{202C}=secret";
    let normalized = normalize_homoglyphs(text);

    // All RTL control characters must be stripped
    assert_eq!(
        normalized.as_ref(),
        "token=secret",
        "Multiple RTL controls (U+202E/U+202B/U+202C) must all be removed; got: {normalized:?}"
    );
    assert!(!normalized.contains('\u{202E}'));
    assert!(!normalized.contains('\u{202B}'));
    assert!(!normalized.contains('\u{202C}'));
}

/// Proving test: RTL override in credential prefix evasion is detected.
/// Contract: "ghp_\u{202E}fake" detection should flag the override.
#[test]
fn detect_rtl_override_evasion() {
    let text = "ghp_\u{202E}secret";
    let attacks = detect_unicode_attacks(text);

    // Must detect the RTL override as an evasion attempt
    assert!(
        attacks.iter().any(|a| a.kind == EvasionKind::RTLOverride),
        "RTL Override (U+202E) must be detected as evasion; attacks={:?}",
        attacks
    );
}
