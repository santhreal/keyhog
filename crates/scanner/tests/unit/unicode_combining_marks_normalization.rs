use keyhog_scanner::unicode_hardening::*;

/// Proving test: Combining diacritical marks are removed from credential.
/// Contract: "e\u{0301}" (é decomposed) normalizes to just "e".
#[test]
fn normalize_removes_combining_diacritical_marks() {
    // U+0301 is COMBINING ACUTE ACCENT, when applied to 'e' makes é (decomposed form)
    // This is in the range U+0300..=U+036F (combining diacritical marks)
    let text = "ghp_e\u{0301}xample";
    let normalized = normalize_homoglyphs(text);

    // Combining mark must be removed
    assert!(
        normalized.contains("ghp_example"),
        "Combining acute accent (U+0301) must be removed; got: {normalized:?}"
    );
    assert!(!normalized.contains('\u{0301}'));
}

/// Proving test: Multiple combining marks on same base character are all removed.
/// Contract: "o\u{0308}\u{0304}" normalizes to "o".
#[test]
fn normalize_removes_multiple_combining_marks_on_base() {
    // U+0308 = COMBINING DIAERESIS (ö)
    // U+0304 = COMBINING MACRON (ō)
    // Stacking them on 'o'
    let text = "token=o\u{0308}\u{0304}ther";
    let normalized = normalize_homoglyphs(text);

    // Both combining marks must be removed
    assert!(
        normalized.contains("token=other"),
        "Multiple combining marks (U+0308, U+0304) must be removed; got: {normalized:?}"
    );
    assert!(!normalized.contains('\u{0308}'));
    assert!(!normalized.contains('\u{0304}'));
}

/// Proving test: Combining marks distributed through credential are all stripped.
/// Contract: "p\u{0300}a\u{0301}s\u{0302}s" normalizes to "pass".
#[test]
fn normalize_removes_combining_marks_throughout_string() {
    // Multiple combining marks on different base characters
    let text = "ghp_p\u{0300}a\u{0301}ssw\u{0302}ord";
    let normalized = normalize_homoglyphs(text);

    // All combining marks must be removed
    assert_eq!(
        normalized.as_ref(),
        "ghp_password",
        "All distributed combining marks must be removed; got: {normalized:?}"
    );
    assert!(!normalized.contains('\u{0300}'));
    assert!(!normalized.contains('\u{0301}'));
    assert!(!normalized.contains('\u{0302}'));
}

/// Proving test: Combining grave accent (U+0300) is removed.
/// Contract: "a\u{0300}" normalizes to "a".
#[test]
fn normalize_removes_combining_grave_accent() {
    // U+0300 = COMBINING GRAVE ACCENT (à)
    let text = "token=a\u{0300}ccountId";
    let normalized = normalize_homoglyphs(text);

    assert!(
        normalized.contains("token=accountId"),
        "Combining grave accent (U+0300) must be removed; got: {normalized:?}"
    );
    assert!(!normalized.contains('\u{0300}'));
}

/// Proving test: Combining ring above (U+030A) is removed.
/// Contract: "a\u{030A}" normalizes to "a".
#[test]
fn normalize_removes_combining_ring_above() {
    // U+030A = COMBINING RING ABOVE (å)
    let text = "sk_live_a\u{030A}pi";
    let normalized = normalize_homoglyphs(text);

    assert!(
        normalized.contains("sk_live_api"),
        "Combining ring above (U+030A) must be removed; got: {normalized:?}"
    );
    assert!(!normalized.contains('\u{030A}'));
}

/// Proving test: Combining mark at credential boundary is removed.
/// Contract: Final character with combining mark strips the mark.
#[test]
fn normalize_removes_combining_mark_at_boundary() {
    // Combining mark on final 'y' in credential
    let text = "ghp_abcdefghijklmnopqrstuv\u{0308}y";
    let normalized = normalize_homoglyphs(text);

    // The combining diaeresis must be removed from the end
    assert!(
        normalized.ends_with('y') && !normalized.contains('\u{0308}'),
        "Combining mark at boundary must be removed; got: {normalized:?}"
    );
    assert!(!normalized.contains('\u{0308}'));
}

/// Proving test: Combining marks are detected as evasion.
/// Contract: detect_unicode_attacks flags combining marks as Suspicious or Decomposed.
#[test]
fn detect_combining_marks_as_evasion() {
    let text = "ghp_e\u{0301}xample";
    let attacks = detect_unicode_attacks(text);

    // Combining marks should be flagged as evasion
    assert!(
        !attacks.is_empty(),
        "Combining marks must be detected as evasion; got empty attacks"
    );
    // The detection may classify as Decomposed or Suspicious
    assert!(
        attacks
            .iter()
            .any(|a| matches!(a.kind, EvasionKind::Decomposed | EvasionKind::Suspicious)),
        "Combining mark (U+0301) must be flagged; attacks={:?}",
        attacks
    );
}
