//! Recall contract: the evasion-normalization strip must remove combining
//! marks from **every** Unicode combining block, not just U+0300–U+036F.
//!
//! `normalize_homoglyphs` runs on the main scan path (`backend_dispatch`), so a
//! combining mark spliced between credential bytes: `g\u{1DC0}hp_…`: must be
//! dropped, or the underlying char sequence stops matching the detector regex
//! (`ghp_`) and the secret is missed. The original strip only covered the
//! Combining Diacritical Marks block (U+0300–036F); marks from the Supplement
//! (U+1DC0–1DFF), Extended (U+1AB0–1AFF), for-Symbols (U+20D0–20FF), Half Marks
//! (U+FE20–FE2F), and the Cyrillic/Hebrew/Arabic/Indic blocks all evaded it.
//! NFC does not rescue these (a mark with no precomposed base survives `nfc()`).
//!
//! Every codepoint below was confirmed `category == M*` against `unicodedata`.

use keyhog_scanner::testing::unicode_hardening::{
    contains_evasion, detect_unicode_attacks, full_normalize, normalize_homoglyphs, EvasionKind,
};
use std::borrow::Cow;

/// Splice `mark` into the middle of a `ghp_` token and assert the normalized
/// form reassembles the clean token (mark gone), proving the strip closed the
/// evasion for that block.
fn assert_mark_stripped_from_token(mark: char, label: &str) {
    let text = format!("ghp_ab{mark}cd");
    let normalized = normalize_homoglyphs(&text);
    assert!(
        normalized.contains("ghp_abcd"),
        "{label} (U+{:04X}) must be stripped so the token reassembles; got {normalized:?}",
        mark as u32
    );
    assert!(
        !normalized.contains(mark),
        "{label} (U+{:04X}) must not survive normalization; got {normalized:?}",
        mark as u32
    );
}

// ── one credential-reassembly proof per combining block ─────────────────────

#[test]
fn original_diacritical_block_still_stripped() {
    // Regression: the block the old code handled must keep working.
    assert_mark_stripped_from_token('\u{0300}', "combining grave (orig block)");
    assert_mark_stripped_from_token('\u{036F}', "orig block end");
}

#[test]
fn diacritical_extended_block_stripped() {
    assert_mark_stripped_from_token('\u{1AB0}', "Combining Diacritical Marks Extended");
}

#[test]
fn diacritical_supplement_block_stripped() {
    // The headline exploit codepoint.
    assert_mark_stripped_from_token('\u{1DC0}', "Combining Diacritical Marks Supplement");
}

#[test]
fn for_symbols_block_stripped() {
    assert_mark_stripped_from_token('\u{20D0}', "Combining Marks for Symbols");
}

#[test]
fn enclosing_mark_me_category_stripped() {
    assert_mark_stripped_from_token('\u{20DD}', "combining enclosing circle (Me)");
}

#[test]
fn half_marks_block_stripped() {
    assert_mark_stripped_from_token('\u{FE20}', "Combining Half Marks");
}

#[test]
fn cyrillic_combining_titlo_stripped() {
    assert_mark_stripped_from_token('\u{0483}', "combining Cyrillic titlo");
}

#[test]
fn cyrillic_millions_me_category_stripped() {
    assert_mark_stripped_from_token('\u{0489}', "combining Cyrillic millions (Me)");
}

#[test]
fn hebrew_combining_accent_stripped() {
    assert_mark_stripped_from_token('\u{0591}', "Hebrew accent etnahta");
}

#[test]
fn arabic_combining_fathatan_stripped() {
    assert_mark_stripped_from_token('\u{064B}', "Arabic fathatan");
}

#[test]
fn devanagari_combining_udatta_stripped() {
    assert_mark_stripped_from_token('\u{0951}', "Devanagari stress sign udatta");
}

// ── the realistic exploit forms ─────────────────────────────────────────────

#[test]
fn extended_mark_between_prefix_chars_reassembles_ghp() {
    // `g<mark>hp_`: the mark sits inside the literal prefix itself.
    let normalized = normalize_homoglyphs("g\u{1DC0}hp_deadbeefcafe");
    assert!(
        normalized.starts_with("ghp_"),
        "prefix-interior combining mark must be stripped; got {normalized:?}"
    );
}

#[test]
fn spliced_mark_lets_aws_key_reassemble() {
    // AKIA + 16, a mark spliced after the AKIA anchor must vanish so the
    // AKIA[0-9A-Z]{16} body is contiguous again.
    let normalized = normalize_homoglyphs("AKIA\u{20DD}QYLPMN5HFIQR7BBB");
    assert!(
        normalized.contains("AKIAQYLPMN5HFIQR7BBB"),
        "combining mark after AKIA must be stripped; got {normalized:?}"
    );
}

#[test]
fn marks_from_multiple_blocks_in_one_token_all_stripped() {
    let normalized = normalize_homoglyphs("g\u{1DC0}h\u{20DD}p\u{FE20}_secret");
    assert_eq!(
        normalized.as_ref(),
        "ghp_secret",
        "marks from three different blocks must all be stripped; got {normalized:?}"
    );
}

// ── boundary handling ───────────────────────────────────────────────────────

#[test]
fn leading_combining_mark_does_not_panic_and_is_dropped() {
    let normalized = normalize_homoglyphs("\u{1DC0}ghp_token");
    assert_eq!(normalized.as_ref(), "ghp_token");
}

#[test]
fn string_of_only_combining_marks_normalizes_to_empty() {
    let normalized = normalize_homoglyphs("\u{1DC0}\u{20DD}\u{FE20}");
    assert_eq!(normalized.as_ref(), "");
}

#[test]
fn trailing_extended_mark_dropped() {
    let normalized = normalize_homoglyphs("ghp_token\u{1AB0}");
    assert_eq!(normalized.as_ref(), "ghp_token");
}

// ── full_normalize (NFC then strip) also benefits ───────────────────────────

#[test]
fn full_normalize_strips_supplement_mark_nfc_cannot_compose() {
    // `g\u{1DC0}` has no precomposed form, so NFC leaves it; the strip must
    // still remove it.
    let normalized = full_normalize("ghp_g\u{1DC0}h");
    assert!(
        normalized.contains("ghp_gh") && !normalized.contains('\u{1DC0}'),
        "full_normalize must strip the supplement mark NFC leaves behind; got {normalized:?}"
    );
}

// ── detection + contains_evasion surface the marks ──────────────────────────

#[test]
fn detect_flags_supplement_mark_as_decomposed() {
    let attacks = detect_unicode_attacks("ghp_a\u{1DC0}b");
    assert!(
        attacks
            .iter()
            .any(|a| a.kind == EvasionKind::Decomposed && a.char == '\u{1DC0}'),
        "supplement combining mark must be reported as Decomposed evasion; got {attacks:?}"
    );
}

#[test]
fn detect_flags_half_mark_as_decomposed() {
    let attacks = detect_unicode_attacks("ghp_a\u{FE20}b");
    assert!(
        attacks.iter().any(|a| a.kind == EvasionKind::Decomposed),
        "half-mark must be reported as evasion; got {attacks:?}"
    );
}

#[test]
fn contains_evasion_true_for_extended_supplement_mark() {
    assert!(contains_evasion("ghp_a\u{1DC0}b"));
    assert!(contains_evasion("ghp_a\u{FE20}b"));
}

// ── safety: letters and ASCII must be preserved (no over-strip) ─────────────

#[test]
fn precomposed_letter_n_tilde_is_kept() {
    // U+00F1 ñ is a letter (Ll), not a combining mark (must survive).
    let normalized = normalize_homoglyphs("ma\u{00F1}ana_token");
    assert!(
        normalized.contains('\u{00F1}'),
        "precomposed ñ (a letter) must not be stripped; got {normalized:?}"
    );
}

#[test]
fn cjk_ideograph_is_kept() {
    // U+4E00 一 is Lo, not a mark.
    let normalized = normalize_homoglyphs("token_\u{4E00}_value");
    assert!(
        normalized.contains('\u{4E00}'),
        "CJK ideograph must be kept; got {normalized:?}"
    );
}

#[test]
fn pure_ascii_stays_borrowed_and_identical() {
    // No marks, no homoglyphs → zero-allocation borrow, byte-identical.
    let normalized = normalize_homoglyphs("ghp_abcdef0123456789");
    assert!(
        matches!(normalized, Cow::Borrowed(_)),
        "pure-ASCII must not allocate"
    );
    assert_eq!(normalized.as_ref(), "ghp_abcdef0123456789");
}

#[test]
fn ascii_credential_with_no_marks_is_unchanged() {
    let normalized = normalize_homoglyphs("AKIAQYLPMN5HFIQR7BBB");
    assert_eq!(normalized.as_ref(), "AKIAQYLPMN5HFIQR7BBB");
}

#[test]
fn precomposed_accent_letter_not_flagged_as_evasion() {
    // é (U+00E9, a letter) alone is not an evasion signal.
    assert!(!contains_evasion("cafe_\u{00E9}_token"));
}
