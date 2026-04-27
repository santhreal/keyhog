use keyhog_scanner::unicode_hardening::*;
#[test]
fn test_detect_cyrillic_homoglyph() {
    let text = "ghp_секрет"; // Cyrillic с and е
    let attacks = detect_unicode_attacks(text);
    assert!(!attacks.is_empty());
    assert!(attacks
        .iter()
        .any(|a| a.kind == EvasionKind::CyrillicHomoglyph));
}

#[test]
fn test_normalize_homoglyphs() {
    let text = "ｇｈｐ_fullwidth"; // Fullwidth ghp
    let normalized = normalize_homoglyphs(text);
    assert!(normalized.contains("ghp_"));
}

#[test]
fn test_remove_zero_width() {
    let text = "ghp_\u{200B}secret"; // Zero-width space
    let normalized = normalize_homoglyphs(text);
    assert!(!normalized.contains('\u{200B}'));
}

#[test]
fn test_full_normalize() {
    let text = "ghp_\u{0065}\u{0308}secret"; // ë (decomposed)
    let normalized = full_normalize(text);
    assert!(normalized.contains('e') && normalized.contains("ghp_"));
}
