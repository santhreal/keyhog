//! Precision/perf contract for `is_fullwidth`: only the fullwidth forms of
//! printable ASCII (U+FF01–FF5E) are "fullwidth ASCII variants" and get
//! normalized to their ASCII twin. The rest of the Halfwidth-and-Fullwidth-Forms
//! block (halfwidth katakana U+FF61–FF9F, the VISIBLE hangul letters, fullwidth
//! brackets U+FF5F–FF60, CJK currency signs U+FFE0–FFE6) are NOT ASCII variants:
//! they must be left untouched and must NOT be reported as evasion, so legitimate
//! CJK text stays on the zero-allocation fast path. The ONE exception is the
//! INVISIBLE U+FFA0 HALFWIDTH HANGUL FILLER (zero-advance), which is a documented
//! credential-splice vector and IS stripped as evasion — see
//! `halfwidth_hangul_filler_ffa0_is_stripped_as_evasion` below.
//!
//! Every fullwidth credential-charset char (A–Z, a–z, 0–9, `_ + / = . -`) lives
//! in U+FF01–FF5E, so the narrowing preserves all credential normalization.

use keyhog_scanner::testing::unicode_hardening::{
    contains_evasion, detect_unicode_attacks, normalize_homoglyphs, EvasionKind,
};
use std::borrow::Cow;

/// Assert a fullwidth char normalizes to the given ASCII char (spliced into a
/// token so we exercise the real scan-path normalizer).
fn assert_fullwidth_maps(fw: char, ascii: char) {
    let input = format!("x{fw}y");
    let out = normalize_homoglyphs(&input);
    assert_eq!(
        out.as_ref(),
        format!("x{ascii}y"),
        "U+{:04X} must normalize to '{ascii}'; got {out:?}",
        fw as u32
    );
}

/// Assert a non-ASCII-variant char from the block is left untouched and not
/// treated as evasion.
fn assert_kept_and_not_evasion(c: char, label: &str) {
    let s = format!("token_{c}_value");
    let out = normalize_homoglyphs(&s);
    assert!(
        out.contains(c),
        "{label} (U+{:04X}) must be kept, not stripped/replaced; got {out:?}",
        c as u32
    );
    assert!(
        !contains_evasion(&s),
        "{label} (U+{:04X}) must NOT be flagged as evasion",
        c as u32
    );
}

// ── fullwidth ASCII (U+FF01–FF5E) still normalizes ──────────────────────────

#[test]
fn fullwidth_uppercase_letter_maps_to_ascii() {
    assert_fullwidth_maps('\u{FF21}', 'A'); // FULLWIDTH LATIN CAPITAL A
}

#[test]
fn fullwidth_lowercase_letter_maps_to_ascii() {
    assert_fullwidth_maps('\u{FF47}', 'g'); // FULLWIDTH LATIN SMALL G
}

#[test]
fn fullwidth_digit_maps_to_ascii() {
    assert_fullwidth_maps('\u{FF10}', '0'); // FULLWIDTH DIGIT ZERO
}

#[test]
fn fullwidth_underscore_maps_to_ascii() {
    assert_fullwidth_maps('\u{FF3F}', '_'); // FULLWIDTH LOW LINE
}

#[test]
fn fullwidth_plus_maps_to_ascii() {
    assert_fullwidth_maps('\u{FF0B}', '+');
}

#[test]
fn fullwidth_slash_maps_to_ascii() {
    assert_fullwidth_maps('\u{FF0F}', '/');
}

#[test]
fn fullwidth_equals_maps_to_ascii() {
    assert_fullwidth_maps('\u{FF1D}', '=');
}

#[test]
fn fullwidth_range_start_ff01_maps() {
    assert_fullwidth_maps('\u{FF01}', '!'); // range start
}

#[test]
fn fullwidth_range_end_ff5e_maps() {
    assert_fullwidth_maps('\u{FF5E}', '~'); // range end
}

#[test]
fn fullwidth_ghp_prefix_reassembles() {
    // ｇｈｐ＿ -> ghp_
    let out = normalize_homoglyphs("\u{FF47}\u{FF48}\u{FF50}\u{FF3F}deadbeef");
    assert_eq!(out.as_ref(), "ghp_deadbeef", "got {out:?}");
}

#[test]
fn fullwidth_aws_key_reassembles() {
    // ＡＫＩＡ + fullwidth body -> AKIA...
    let out = normalize_homoglyphs("\u{FF21}\u{FF2B}\u{FF29}\u{FF21}QYLPMN5HFIQR7BBB");
    assert!(
        out.contains("AKIA"),
        "fullwidth AKIA must normalize; got {out:?}"
    );
}

// ── classification + evasion still fire for fullwidth ASCII ──────────────────

#[test]
fn fullwidth_letter_still_classified_fullwidth() {
    let attacks = detect_unicode_attacks("ghp_\u{FF21}bc");
    assert!(
        attacks
            .iter()
            .any(|a| a.kind == EvasionKind::Fullwidth && a.char == '\u{FF21}'),
        "fullwidth letter must still be reported as Fullwidth evasion; got {attacks:?}"
    );
}

#[test]
fn fullwidth_letters_trigger_contains_evasion() {
    assert!(contains_evasion("\u{FF21}\u{FF22}\u{FF23}"));
}

// ── the non-ASCII-variant block members are now KEPT (the fix) ───────────────

#[test]
fn halfwidth_katakana_ff61_is_kept() {
    assert_kept_and_not_evasion('\u{FF61}', "halfwidth ideographic full stop");
}

#[test]
fn halfwidth_katakana_ka_ff76_is_kept() {
    assert_kept_and_not_evasion('\u{FF76}', "halfwidth katakana KA");
}

#[test]
fn halfwidth_katakana_ff9f_is_kept() {
    assert_kept_and_not_evasion(
        '\u{FF9F}',
        "halfwidth katakana semi-voiced mark (range edge)",
    );
}

#[test]
fn halfwidth_hangul_filler_ffa0_is_stripped_as_evasion() {
    // U+FFA0 HALFWIDTH HANGUL FILLER is the ONE exception to "halfwidth hangul is
    // kept": unlike the VISIBLE halfwidth hangul letters (U+FFA1–FFDC) and katakana
    // (U+FF61–FF9F) this file protects, the FILLER is INVISIBLE (zero-advance). It
    // is grouped in `unicode_hardening`'s invisible-`Lo`-filler strip set with the
    // other Hangul fillers (U+115F/1160/3164) precisely because it renders blank and
    // is a classic "looks empty" credential-splice vector — `gh<FFA0>p_token` must
    // fold to `ghp_token`. So it MUST be flagged as evasion and stripped, matching
    // `unicode_hardening`'s `hangul_filler_split_credential_is_recovered`.
    let spliced = "token_\u{FFA0}_value";
    assert!(
        contains_evasion(spliced),
        "the invisible halfwidth hangul filler U+FFA0 must be flagged as an evasion splice vector"
    );
    let normalized = normalize_homoglyphs(spliced);
    assert!(
        !normalized.contains('\u{FFA0}'),
        "U+FFA0 must be stripped from the value scan path, got {normalized:?}"
    );
}

#[test]
fn fullwidth_white_paren_ff5f_is_kept() {
    // FF5F is FF5E+1 — just past the ASCII-mappable range.
    assert_kept_and_not_evasion('\u{FF5F}', "fullwidth left white parenthesis");
}

#[test]
fn fullwidth_yen_sign_ffe5_is_kept() {
    assert_kept_and_not_evasion('\u{FFE5}', "fullwidth yen sign");
}

// ── perf: pure CJK text takes the zero-allocation fast path ──────────────────

#[test]
fn pure_katakana_text_is_not_evasion() {
    // U+30A2 ア (full katakana) + halfwidth — none are ASCII variants.
    assert!(
        !contains_evasion("\u{FF76}\u{FF77}\u{FF78}"),
        "halfwidth katakana run is not evasion"
    );
}

#[test]
fn katakana_only_text_stays_borrowed() {
    // No mapped/dropped char -> Cow::Borrowed, no allocation.
    let out = normalize_homoglyphs("config_\u{FF76}\u{FF77}\u{FF78}_name");
    assert!(
        matches!(out, Cow::Borrowed(_)),
        "CJK-only text must not allocate; got {out:?}"
    );
}

// ── boundary + ASCII safety ─────────────────────────────────────────────────

#[test]
fn unassigned_ff00_is_kept() {
    // FF00 is FF01-1 — just before the range, unassigned, must be kept.
    let out = normalize_homoglyphs("x\u{FF00}y");
    assert!(
        out.contains('\u{FF00}'),
        "U+FF00 (below range) must be kept; got {out:?}"
    );
}

#[test]
fn mixed_fullwidth_letter_and_katakana() {
    // Fullwidth 'Ａ' normalizes to 'A'; the halfwidth katakana stays.
    let out = normalize_homoglyphs("\u{FF21}\u{FF76}");
    assert_eq!(out.as_ref(), "A\u{FF76}", "got {out:?}");
}

#[test]
fn pure_ascii_stays_borrowed_and_identical() {
    let out = normalize_homoglyphs("ghp_abcdef0123456789");
    assert!(
        matches!(out, Cow::Borrowed(_)),
        "pure-ASCII must not allocate"
    );
    assert_eq!(out.as_ref(), "ghp_abcdef0123456789");
}
