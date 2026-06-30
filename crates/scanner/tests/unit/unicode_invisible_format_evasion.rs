//! Recall contract: invisible `General_Category=Cf` format characters that
//! render to nothing must be stripped on the scan path, so a credential they
//! split reassembles.
//!
//! `is_zero_width` curates the invisible-format codepoints the evasion strip
//! removes. It previously missed the invisible math operators U+2061–2064, the
//! Tags block U+E0000–E007F, and the interlinear annotation anchors
//! U+FFF9–FFFB — all invisible, all credential-splice vectors. This suite pins
//! that each is now stripped while the *meaningful* Cf chars (Arabic/Syriac
//! number signs) are preserved (the strip is curated, not a blanket Cf drop).
//!
//! Codepoint categories confirmed against `unicodedata` (Cf = format).

use keyhog_scanner::testing::unicode_hardening::{
    contains_evasion, detect_unicode_attacks, normalize_homoglyphs, EvasionKind,
};
use std::borrow::Cow;

/// Splice `c` into the middle of a `ghp_` token; assert it is stripped so the
/// clean token reassembles.
fn assert_invisible_stripped(c: char, label: &str) {
    let text = format!("ghp_ab{c}cd");
    let normalized = normalize_homoglyphs(&text);
    assert!(
        normalized.contains("ghp_abcd") && !normalized.contains(c),
        "{label} (U+{:04X}) must be stripped so the token reassembles; got {normalized:?}",
        c as u32
    );
}

// ── invisible math operators (U+2060–2064) ──────────────────────────────────

#[test]
fn word_joiner_2060_still_stripped() {
    // Regression: the existing endpoint of the new range must keep working.
    assert_invisible_stripped('\u{2060}', "word joiner");
}

#[test]
fn invisible_function_application_2061_stripped() {
    assert_invisible_stripped('\u{2061}', "function application");
}

#[test]
fn invisible_times_2062_stripped() {
    assert_invisible_stripped('\u{2062}', "invisible times");
}

#[test]
fn invisible_separator_2063_stripped() {
    assert_invisible_stripped('\u{2063}', "invisible separator");
}

#[test]
fn invisible_plus_2064_stripped() {
    assert_invisible_stripped('\u{2064}', "invisible plus (range end)");
}

// ── Tags block (U+E0000–E007F) ──────────────────────────────────────────────

#[test]
fn language_tag_e0001_stripped() {
    assert_invisible_stripped('\u{E0001}', "language tag");
}

#[test]
fn tag_space_e0020_stripped() {
    assert_invisible_stripped('\u{E0020}', "tag space");
}

#[test]
fn tag_letter_e0061_stripped() {
    assert_invisible_stripped('\u{E0061}', "tag latin small a");
}

#[test]
fn cancel_tag_e007f_stripped() {
    assert_invisible_stripped('\u{E007F}', "cancel tag (range end)");
}

// ── interlinear annotation (U+FFF9–FFFB) ────────────────────────────────────

#[test]
fn interlinear_anchor_fff9_stripped() {
    assert_invisible_stripped('\u{FFF9}', "interlinear annotation anchor");
}

#[test]
fn interlinear_terminator_fffb_stripped() {
    assert_invisible_stripped('\u{FFFB}', "interlinear annotation terminator");
}

// ── realistic exploit forms ─────────────────────────────────────────────────

#[test]
fn invisible_times_splice_reassembles_ghp() {
    let normalized = normalize_homoglyphs("g\u{2062}hp_deadbeefcafe");
    assert!(normalized.starts_with("ghp_"), "got {normalized:?}");
}

#[test]
fn tag_splice_lets_aws_key_reassemble() {
    let normalized = normalize_homoglyphs("AKIA\u{E0020}QYLPMN5HFIQR7BBB");
    assert!(
        normalized.contains("AKIAQYLPMN5HFIQR7BBB"),
        "tag char after AKIA must be stripped; got {normalized:?}"
    );
}

#[test]
fn multiple_invisible_blocks_in_one_token_all_stripped() {
    let normalized = normalize_homoglyphs("g\u{2061}h\u{FFF9}p\u{E0020}_secret");
    assert_eq!(normalized.as_ref(), "ghp_secret", "got {normalized:?}");
}

#[test]
fn string_of_only_invisible_format_normalizes_to_empty() {
    let normalized = normalize_homoglyphs("\u{2062}\u{FFF9}\u{E0020}");
    assert_eq!(normalized.as_ref(), "");
}

#[test]
fn leading_tag_dropped() {
    assert_eq!(
        normalize_homoglyphs("\u{E0001}ghp_token").as_ref(),
        "ghp_token"
    );
}

// ── detection + contains_evasion ────────────────────────────────────────────

#[test]
fn detect_classifies_invisible_operator_as_zero_width() {
    let attacks = detect_unicode_attacks("ghp_a\u{2062}b");
    assert!(
        attacks
            .iter()
            .any(|a| a.kind == EvasionKind::ZeroWidth && a.char == '\u{2062}'),
        "invisible times must be reported as ZeroWidth evasion; got {attacks:?}"
    );
}

#[test]
fn detect_classifies_tag_as_zero_width() {
    let attacks = detect_unicode_attacks("ghp_a\u{E0020}b");
    assert!(
        attacks.iter().any(|a| a.kind == EvasionKind::ZeroWidth),
        "tag char must be reported as evasion; got {attacks:?}"
    );
}

#[test]
fn contains_evasion_true_for_invisible_operator_and_tag() {
    assert!(contains_evasion("ghp_a\u{2062}b"));
    assert!(contains_evasion("ghp_a\u{E0020}b"));
    assert!(contains_evasion("ghp_a\u{FFF9}b"));
}

// ── curated, not blanket: meaningful Cf chars must be preserved ──────────────

#[test]
fn arabic_number_sign_0600_is_kept() {
    // U+0600 (Cf) prefixes Arabic numbers and has a real effect — must survive.
    let normalized = normalize_homoglyphs("amount_\u{0600}123_token");
    assert!(
        normalized.contains('\u{0600}'),
        "Arabic number sign (meaningful Cf) must not be stripped; got {normalized:?}"
    );
}

#[test]
fn syriac_abbreviation_mark_070f_is_kept() {
    let normalized = normalize_homoglyphs("x_\u{070F}_y");
    assert!(
        normalized.contains('\u{070F}'),
        "Syriac abbreviation mark must be kept; got {normalized:?}"
    );
}

#[test]
fn arabic_number_sign_not_flagged_as_evasion() {
    assert!(!contains_evasion("amount_\u{0600}123"));
}

// ── existing zero-widths + ASCII safety (regression) ────────────────────────

#[test]
fn zero_width_space_200b_still_stripped() {
    assert_invisible_stripped('\u{200B}', "zero width space");
}

#[test]
fn bom_feff_still_stripped() {
    assert_invisible_stripped('\u{FEFF}', "zero width no-break space (BOM)");
}

#[test]
fn pure_ascii_stays_borrowed_and_identical() {
    let normalized = normalize_homoglyphs("ghp_abcdef0123456789");
    assert!(
        matches!(normalized, Cow::Borrowed(_)),
        "pure-ASCII must not allocate"
    );
    assert_eq!(normalized.as_ref(), "ghp_abcdef0123456789");
}
