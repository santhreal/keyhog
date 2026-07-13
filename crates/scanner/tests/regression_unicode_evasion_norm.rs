//! Regression: Unicode-evasion normalization on the main scan path.
//!
//! `crates/scanner/src/unicode_hardening.rs` strips / replaces the characters an
//! attacker splices into a credential body to break a detector regex. Every
//! assertion here pins the EXACT normalized bytes (not merely "non-empty"), so a
//! secret with zero-width chars, combining marks, homoglyphs, fullwidth forms,
//! RTL overrides, or ASCII control bytes injected is provably restored to the
//! clean token a detector would then match.
//!
//! Exercised through the crate's `testing::unicode_hardening` facade, the same
//! `pub(crate)` functions the scan path calls, no production visibility widened.

use std::borrow::Cow;

use keyhog_scanner::testing::unicode_hardening as uh;
use keyhog_scanner::testing::unicode_hardening::EvasionKind;

// ── Zero-width family ───────────────────────────────────────────────────────

#[test]
fn zero_width_space_u200b_stripped_restores_token() {
    // U+200B Zero Width Space spliced after the first byte of a `ghp_` token.
    let evaded = "g\u{200B}hp_ABCdef1234567890abcdef1234";
    let out = uh::normalize_homoglyphs(evaded);
    assert_eq!(out.as_ref(), "ghp_ABCdef1234567890abcdef1234");
    // A char was dropped, so the slow path must own the buffer, not borrow.
    assert!(
        matches!(out, Cow::Owned(_)),
        "stripping must allocate a new buffer"
    );
}

#[test]
fn invisible_operators_u2061_u2064_all_stripped() {
    // U+2061 FUNCTION APPLICATION .. U+2064 INVISIBLE PLUS, the exact block the
    // "is_zero_width still missing U+2061-2064" hardening note called out.
    let evaded = "gh\u{2061}\u{2062}\u{2063}\u{2064}p_secretbodyvalue0001";
    let out = uh::normalize_homoglyphs(evaded);
    assert_eq!(out.as_ref(), "ghp_secretbodyvalue0001");
}

#[test]
fn tag_block_u_e0041_stripped() {
    // U+E0041 (TAG LATIN CAPITAL A) from the invisible Tags block E0000..=E007F.
    let evaded = "AK\u{E0041}IA_ROTATED_KEY_BODY_00";
    let out = uh::normalize_homoglyphs(evaded);
    assert_eq!(out.as_ref(), "AKIA_ROTATED_KEY_BODY_00");
}

#[test]
fn bom_feff_and_rtl_override_dropped_together() {
    // U+FEFF (BOM / zero-width no-break) + U+202E (RTL override) inside AKIA.
    let evaded = "A\u{FEFF}K\u{202E}IA1234567890ABCDEF";
    let out = uh::normalize_homoglyphs(evaded);
    assert_eq!(out.as_ref(), "AKIA1234567890ABCDEF");
}

// ── Combining marks (decomposed forms) ──────────────────────────────────────

#[test]
fn combining_acute_u0301_stripped_without_nfc() {
    // normalize_homoglyphs does NOT run NFC; it drops the combining mark outright.
    let evaded = "g\u{0301}hp_body0123456789abcdef01";
    let out = uh::normalize_homoglyphs(evaded);
    assert_eq!(out.as_ref(), "ghp_body0123456789abcdef01");
}

#[test]
fn combining_mark_extended_block_u1dc0_dropped_and_nfc_cannot_rescue() {
    // U+1DC0 lives in the Combining Diacritical Marks Extended block and has no
    // precomposed base, so NFC leaves it in place. Both the strip path and the
    // full (NFC + homoglyph) path must remove it.
    let evaded = "g\u{1DC0}hp_extendedmarkbody00001";
    assert_eq!(
        uh::normalize_homoglyphs(evaded).as_ref(),
        "ghp_extendedmarkbody00001"
    );
    assert_eq!(uh::full_normalize(evaded), "ghp_extendedmarkbody00001");
}

// ── Homoglyph replacement ───────────────────────────────────────────────────

#[test]
fn cyrillic_homoglyph_prefix_replaced_with_latin() {
    // U+0455 (ѕ)→s, U+043A (к)→k reconstruct the Stripe `sk_live_` prefix.
    let evaded = "\u{0455}\u{043A}_live_51ABCdefGHIjkl0001";
    let out = uh::normalize_homoglyphs(evaded);
    assert_eq!(out.as_ref(), "sk_live_51ABCdefGHIjkl0001");
}

#[test]
fn greek_homoglyph_replaced_with_latin() {
    // U+03BF (ο)→o restores `oauth`.
    let evaded = "\u{03BF}auth_token_body_00112233";
    let out = uh::normalize_homoglyphs(evaded);
    assert_eq!(out.as_ref(), "oauth_token_body_00112233");
}

#[test]
fn fullwidth_forms_folded_to_ascii() {
    // U+FF47/FF48/FF50 (ｇｈｐ) fold to their ASCII twins via `- 0xFEE0`.
    let evaded = "\u{FF47}\u{FF48}\u{FF50}_fullwidthbody0000001";
    let out = uh::normalize_homoglyphs(evaded);
    assert_eq!(out.as_ref(), "ghp_fullwidthbody0000001");
}

// ── ASCII control-byte evasion (the DEL recall hole) ────────────────────────

#[test]
fn del_control_u007f_dropped() {
    // U+007F DEL is an ASCII control that `is_ascii_control()` covers but a naive
    // `b < 0x20` gate misses (the documented recall hole. It must be dropped).
    let evaded = "ghp_abc\u{7F}def0123456789ABCDEF";
    let out = uh::normalize_homoglyphs(evaded);
    assert_eq!(out.as_ref(), "ghp_abcdef0123456789ABCDEF");
    assert!(matches!(out, Cow::Owned(_)));
}

#[test]
fn nul_and_c0_controls_dropped_but_structural_whitespace_preserved() {
    // U+0000 NUL and U+0001 are dropped; \n \r \t are structural and preserved.
    assert_eq!(
        uh::normalize_homoglyphs("gh\u{0000}p_\u{0001}body00").as_ref(),
        "ghp_body00"
    );
    let structural = "ghp_abc\n\r\tdef";
    let out = uh::normalize_homoglyphs(structural);
    assert_eq!(out.as_ref(), structural);
    // Structural-only ASCII stays on the zero-allocation fast path.
    assert!(
        matches!(out, Cow::Borrowed(_)),
        "structural whitespace must not trigger a rebuild"
    );
}

// ── Fast-path identity (negative twin) ──────────────────────────────────────

#[test]
fn pure_ascii_token_returned_borrowed_unchanged() {
    let clean = "ghp_0123456789abcdefABCDEF0123456789abcd";
    let out = uh::normalize_homoglyphs(clean);
    assert_eq!(out.as_ref(), clean);
    assert!(
        matches!(out, Cow::Borrowed(_)),
        "clean ASCII must be borrowed with zero allocation"
    );
}

// ── contains_evasion / is_evasion_char truth tables ─────────────────────────

#[test]
fn contains_evasion_truth_table() {
    assert!(!uh::contains_evasion("ghp_clean0123456789abcdef"));
    assert!(!uh::contains_evasion("col1\tcol2\nrow")); // structural whitespace
    assert!(uh::contains_evasion("gh\u{200B}p")); // zero-width
    assert!(uh::contains_evasion("ghp_abc\u{7F}")); // DEL control
    assert!(uh::contains_evasion("\u{0430}pi_key")); // cyrillic homoglyph
    assert!(uh::contains_evasion("g\u{0301}hp")); // combining mark
}

#[test]
fn is_evasion_char_truth_table() {
    // is_evasion_char == zero-width OR rtl-override only (NOT homoglyph/combining).
    assert!(uh::is_evasion_char('\u{200B}')); // zero-width space
    assert!(uh::is_evasion_char('\u{FEFF}')); // BOM
    assert!(uh::is_evasion_char('\u{202E}')); // RTL override
    assert!(uh::is_evasion_char('\u{202A}')); // LRE
    assert!(!uh::is_evasion_char('a'));
    assert!(!uh::is_evasion_char('\u{0430}')); // cyrillic homoglyph: not this predicate
    assert!(!uh::is_evasion_char('\u{0301}')); // combining mark: not this predicate
}

// ── detect_unicode_attacks: exact per-match fields ──────────────────────────

#[test]
fn detect_reports_cyrillic_homoglyph_fields() {
    // "a" (1 byte) then U+0430 at byte offset 1.
    let matches = uh::detect_unicode_attacks("a\u{0430}");
    assert_eq!(matches.len(), 1);
    let m = &matches[0];
    assert_eq!(m.position, 1);
    assert_eq!(m.kind, EvasionKind::CyrillicHomoglyph);
    assert_eq!(m.char, '\u{0430}');
    assert_eq!(m.replacement, Some('a'));
}

#[test]
fn detect_reports_zero_width_fields() {
    let matches = uh::detect_unicode_attacks("g\u{200B}h");
    assert_eq!(matches.len(), 1);
    let m = &matches[0];
    assert_eq!(m.position, 1);
    assert_eq!(m.kind, EvasionKind::ZeroWidth);
    assert_eq!(m.char, '\u{200B}');
    assert_eq!(m.replacement, None);
}

#[test]
fn detect_reports_del_control_as_suspicious() {
    // DEL must be reported by the detector too, matching the normalize-path drop.
    let matches = uh::detect_unicode_attacks("ghp\u{7F}");
    assert_eq!(matches.len(), 1);
    let m = &matches[0];
    assert_eq!(m.position, 3);
    assert_eq!(m.kind, EvasionKind::Suspicious);
    assert_eq!(m.char, '\u{7F}');
    assert_eq!(m.replacement, None);
}

// ── strip_interior_evasion_controls: prefix-anchored control removal ─────────

#[test]
fn strip_interior_tab_inside_akia_body() {
    // A TAB spliced into an AKIA access-key body (flanked by credential bytes) is
    // removed; the anchor `AKIA` gates the strip so structural tabs are untouched.
    let evaded = "AKIA\tQYLPO1234567890ABC";
    let out = uh::strip_interior_evasion_controls(evaded);
    assert_eq!(out.as_ref(), "AKIAQYLPO1234567890ABC");
    assert!(matches!(out, Cow::Owned(_)));
}

#[test]
fn strip_interior_leaves_unanchored_tab_untouched() {
    // No structured prefix → the TAB is treated as structural, returned borrowed.
    let plain = "col1\tcol2value000";
    let out = uh::strip_interior_evasion_controls(plain);
    assert_eq!(out.as_ref(), plain);
    assert!(matches!(out, Cow::Borrowed(_)));
}

// ── full_normalize: NFC composition + homoglyph fold ─────────────────────────

#[test]
fn full_normalize_composes_nfd_sequence() {
    // "cafe" + U+0301 combining acute → NFC composes to "café" (U+00E9), which is
    // not a homoglyph and survives the fold unchanged.
    assert_eq!(uh::full_normalize("cafe\u{0301}"), "caf\u{00E9}");
}
