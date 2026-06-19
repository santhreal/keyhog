//! Standalone unit coverage for `keyhog_scanner::testing::unicode_hardening`.
//!
//! Asserts the exact normalized BYTES of homoglyph/fullwidth/zero-width
//! evasion, the precise `EvasionKind` reported per attack class, and the
//! anchored interior-control strip — never `is_empty`/`is_some` decoration.

use keyhog_scanner::testing::unicode_hardening::{
    contains_evasion, detect_unicode_attacks, full_normalize, is_evasion_char,
    normalize_homoglyphs, strip_interior_evasion_controls, EvasionKind,
};

// ---------------------------------------------------------------------------
// normalize_homoglyphs — exact ASCII output, allocation-free fast path
// ---------------------------------------------------------------------------

#[test]
fn ascii_input_is_borrowed_unchanged() {
    let s = "ghp_abcdefghij0123456789";
    let out = normalize_homoglyphs(s);
    assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
    assert_eq!(out, s);
}

#[test]
fn cyrillic_homoglyphs_fold_to_latin() {
    // "ghр_" with a Cyrillic 'р' (U+0440) -> Latin "ghp_".
    let evasive = "gh\u{0440}_token0123456789";
    let out = normalize_homoglyphs(evasive);
    assert_eq!(out, "ghp_token0123456789");
    // The result must NOT still contain the Cyrillic codepoint.
    assert!(!out.contains('\u{0440}'));
}

#[test]
fn greek_homoglyphs_fold_to_latin() {
    // Greek omicron 'ο' (U+03BF) -> 'o', Greek rho 'ρ' (U+03C1) -> 'p'.
    let evasive = "t\u{03BF}ken_\u{03C1}assword";
    let out = normalize_homoglyphs(evasive);
    assert_eq!(out, "token_password");
}

#[test]
fn fullwidth_folds_to_ascii() {
    // Fullwidth 'ｇｈｐ' (U+FF47 U+FF48 U+FF50) -> "ghp".
    let evasive = "\u{FF47}\u{FF48}\u{FF50}_rest";
    let out = normalize_homoglyphs(evasive);
    assert_eq!(out, "ghp_rest");
}

#[test]
fn zero_width_chars_are_stripped() {
    // ZWSP (U+200B) injected mid-token is removed, reuniting the body.
    let evasive = "ghp_abc\u{200B}def0123456789";
    let out = normalize_homoglyphs(evasive);
    assert_eq!(out, "ghp_abcdef0123456789");
}

#[test]
fn rtl_override_is_stripped() {
    let evasive = "ghp_\u{202E}reversed";
    let out = normalize_homoglyphs(evasive);
    assert_eq!(out, "ghp_reversed");
    assert!(!out.contains('\u{202E}'));
}

#[test]
fn unicode_separator_is_stripped() {
    // No-break space (U+00A0) used to split a credential body is removed.
    let evasive = "AKIA\u{00A0}IOSFODNN7EXAMPLE";
    let out = normalize_homoglyphs(evasive);
    assert_eq!(out, "AKIAIOSFODNN7EXAMPLE");
}

// ---------------------------------------------------------------------------
// full_normalize — NFC then homoglyph fold
// ---------------------------------------------------------------------------

#[test]
fn full_normalize_composes_then_folds() {
    // Decomposed 'é' (e + U+0301) composes under NFC; the combining mark on the
    // homoglyph path is dropped, leaving plain 'e' is NOT what NFC does — NFC
    // composes to precomposed 'é' (U+00E9). Assert the precomposed form.
    let decomposed = "caf\u{0065}\u{0301}";
    let out = full_normalize(decomposed);
    assert_eq!(out, "caf\u{00E9}");
}

#[test]
fn full_normalize_handles_homoglyph_after_compose() {
    // Cyrillic 'а' (U+0430) survives NFC, then folds to Latin 'a'.
    let out = full_normalize("p\u{0430}ssword123");
    assert_eq!(out, "password123");
}

// ---------------------------------------------------------------------------
// detect_unicode_attacks — exact kind + replacement per class
// ---------------------------------------------------------------------------

#[test]
fn detect_reports_cyrillic_with_replacement() {
    let m = detect_unicode_attacks("gh\u{0440}_x");
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].kind, EvasionKind::CyrillicHomoglyph);
    assert_eq!(m[0].char, '\u{0440}');
    assert_eq!(m[0].replacement, Some('p'));
    // Byte position: "gh" is 2 bytes, so the Cyrillic char starts at offset 2.
    assert_eq!(m[0].position, 2);
}

#[test]
fn detect_reports_fullwidth_with_ascii_replacement() {
    let m = detect_unicode_attacks("\u{FF47}");
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].kind, EvasionKind::Fullwidth);
    assert_eq!(m[0].replacement, Some('g'));
}

#[test]
fn detect_reports_zero_width_no_replacement() {
    let m = detect_unicode_attacks("a\u{200B}b");
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].kind, EvasionKind::ZeroWidth);
    assert_eq!(m[0].replacement, None);
}

#[test]
fn detect_reports_rtl_override() {
    let m = detect_unicode_attacks("x\u{202E}y");
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].kind, EvasionKind::RTLOverride);
}

#[test]
fn detect_reports_combining_mark_as_decomposed() {
    let m = detect_unicode_attacks("e\u{0301}");
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].kind, EvasionKind::Decomposed);
}

#[test]
fn detect_clean_ascii_is_empty() {
    assert!(detect_unicode_attacks("ghp_abcdefghij0123456789").is_empty());
}

#[test]
fn detect_finds_multiple_distinct_attacks() {
    // Cyrillic 'а' then ZWSP then fullwidth 'ｇ'.
    let m = detect_unicode_attacks("\u{0430}\u{200B}\u{FF47}");
    assert_eq!(m.len(), 3);
    assert_eq!(m[0].kind, EvasionKind::CyrillicHomoglyph);
    assert_eq!(m[1].kind, EvasionKind::ZeroWidth);
    assert_eq!(m[2].kind, EvasionKind::Fullwidth);
}

// ---------------------------------------------------------------------------
// is_evasion_char
// ---------------------------------------------------------------------------

#[test]
fn is_evasion_char_true_for_zero_width_and_rtl() {
    assert!(is_evasion_char('\u{200B}')); // ZWSP
    assert!(is_evasion_char('\u{FEFF}')); // BOM
    assert!(is_evasion_char('\u{202E}')); // RTL override
}

#[test]
fn is_evasion_char_false_for_normal_chars() {
    assert!(!is_evasion_char('a'));
    assert!(!is_evasion_char('_'));
    assert!(!is_evasion_char(' '));
}

// ---------------------------------------------------------------------------
// contains_evasion
// ---------------------------------------------------------------------------

#[test]
fn contains_evasion_true_for_homoglyph_and_control() {
    assert!(contains_evasion("gh\u{0440}_x")); // Cyrillic homoglyph
    assert!(contains_evasion("a\u{200B}b")); // zero-width
    assert!(contains_evasion("a\u{0001}b")); // raw ASCII control evasion byte
}

#[test]
fn contains_evasion_false_for_clean_text() {
    assert!(!contains_evasion("ghp_abcdefghij0123456789"));
    // Newlines/tabs/CR are structural, not evasion.
    assert!(!contains_evasion("line1\n\tline2\r\n"));
}

// ---------------------------------------------------------------------------
// strip_interior_evasion_controls — anchored, structural-safe
// ---------------------------------------------------------------------------

#[test]
fn strips_interior_tab_inside_anchored_credential() {
    // AKIA prefix with a TAB interrupting the body must be rejoined.
    let evasive = "AKIA\tIOSFODNN7EXAMPLE";
    let out = strip_interior_evasion_controls(evasive);
    assert_eq!(out, "AKIAIOSFODNN7EXAMPLE");
}

#[test]
fn preserves_structural_tab_indentation() {
    // A leading TAB (indentation: control preceded by newline) is NOT interior
    // to a credential body and must be preserved -> borrowed, unchanged.
    let text = "key:\n\tvalue = something";
    let out = strip_interior_evasion_controls(text);
    assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
    assert_eq!(out, text);
}

#[test]
fn preserves_crlf_line_endings() {
    // \r followed by \n is a line ending, never interior to a credential.
    let text = "line1\r\nline2\r\n";
    let out = strip_interior_evasion_controls(text);
    assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
    assert_eq!(out, text);
}

#[test]
fn no_known_prefix_leaves_interior_control_intact() {
    // A TAB flanked by credential bytes but with NO known anchor prefix is left
    // alone (the strip is anchor-gated, not a blanket control removal).
    let text = "randomword\tmorewords";
    let out = strip_interior_evasion_controls(text);
    assert_eq!(out, text);
}
