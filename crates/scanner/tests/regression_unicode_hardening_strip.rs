//! Regression: Unicode-hardening strip/detect truth table.
//!
//! Pins the EXACT behavior of `crates/scanner/src/unicode_hardening.rs` — the
//! module that strips/replaces the characters an attacker splices into a
//! credential body to break a detector regex. Every assertion here is a
//! concrete value: exact stripped bytes, exact `EvasionKind`, exact
//! `replacement`, exact `bool`, exact `Cow` variant. No `is_empty`/`is_some`.
//!
//! Coverage focus (complementary to `regression_unicode_evasion_norm.rs`):
//!   - `detect_unicode_attacks` classification (kind + replacement + position),
//!   - `normalize_homoglyphs` / `full_normalize` exact stripped forms,
//!   - `is_evasion_char` as the observable proxy for the private
//!     `is_zero_width || is_rtl_override` predicate — including the historical
//!     "is_zero_width still missing U+2061-2064" note, which the CURRENT code
//!     has CLOSED (`'\u{2060}'..='\u{2064}'` is in the zero-width set), so the
//!     real current value asserted below is `true`, and the stale gap is noted,
//!   - `is_combining_mark` reaching the FULL Grapheme_Extend set (blocks beyond
//!     U+0300–036F: Extended U+1DC0, Half Marks U+FE20),
//!   - `strip_interior_evasion_controls` anchored strip vs structural-whitespace
//!     preservation (TSV tabs, CRLF, mid-identifier non-anchoring).
//!
//! Exercised through the crate's `testing::unicode_hardening` facade — the same
//! `pub(crate)` functions the scan path calls, no production visibility widened.

use std::borrow::Cow;

use keyhog_scanner::testing::unicode_hardening as uh;
use keyhog_scanner::testing::unicode_hardening::EvasionKind;

// ── detect_unicode_attacks: classification, replacement, position ────────────

#[test]
fn detect_zero_width_space_is_zerowidth_no_replacement() {
    let m = uh::detect_unicode_attacks("\u{200B}");
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].position, 0);
    assert_eq!(m[0].kind, EvasionKind::ZeroWidth);
    assert_eq!(m[0].char, '\u{200B}');
    assert_eq!(m[0].replacement, None);
}

#[test]
fn detect_bom_feff_is_zerowidth() {
    // U+FEFF BOM (3 UTF-8 bytes) at offset 0; the trailing ASCII is clean.
    let m = uh::detect_unicode_attacks("\u{FEFF}abc");
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].position, 0);
    assert_eq!(m[0].kind, EvasionKind::ZeroWidth);
    assert_eq!(m[0].char, '\u{FEFF}');
    assert_eq!(m[0].replacement, None);
}

#[test]
fn detect_combining_acute_is_decomposed() {
    // U+0301 COMBINING ACUTE ACCENT — a Grapheme_Extend mark, reported as
    // Decomposed (it is stripped on the normalization path), not ZeroWidth.
    let m = uh::detect_unicode_attacks("\u{0301}");
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].position, 0);
    assert_eq!(m[0].kind, EvasionKind::Decomposed);
    assert_eq!(m[0].char, '\u{0301}');
    assert_eq!(m[0].replacement, None);
}

#[test]
fn detect_combining_extended_block_u1dc0_is_decomposed() {
    // U+1DC0 lives in the Combining Diacritical Marks Extended block, OUTSIDE
    // the U+0300–036F block. It must still classify as a combining mark, proving
    // `is_combining_mark` covers the full Grapheme_Extend set, not one block.
    let m = uh::detect_unicode_attacks("\u{1DC0}");
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].kind, EvasionKind::Decomposed);
    assert_eq!(m[0].char, '\u{1DC0}');
    assert_eq!(m[0].replacement, None);
}

#[test]
fn detect_cyrillic_homoglyph_maps_to_latin_a() {
    // U+0430 Cyrillic 'а' looks like Latin 'a'; replacement is the Latin twin.
    let m = uh::detect_unicode_attacks("\u{0430}");
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].position, 0);
    assert_eq!(m[0].kind, EvasionKind::CyrillicHomoglyph);
    assert_eq!(m[0].char, '\u{0430}');
    assert_eq!(m[0].replacement, Some('a'));
}

#[test]
fn detect_fullwidth_g_maps_to_ascii_g() {
    // U+FF47 fullwidth 'ｇ' = 0x67 + 0xFEE0; replacement is ASCII 'g'.
    let m = uh::detect_unicode_attacks("\u{FF47}");
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].kind, EvasionKind::Fullwidth);
    assert_eq!(m[0].char, '\u{FF47}');
    assert_eq!(m[0].replacement, Some('g'));
}

#[test]
fn detect_rtl_override_no_replacement() {
    let m = uh::detect_unicode_attacks("\u{202E}");
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].kind, EvasionKind::RTLOverride);
    assert_eq!(m[0].char, '\u{202E}');
    assert_eq!(m[0].replacement, None);
}

// ── normalize_homoglyphs: exact stripped bytes + Cow variant ─────────────────

#[test]
fn normalize_strips_zwj_bom_zwsp_to_clean_token() {
    // ZWJ + BOM + ZWSP spliced through a `ghp_` token → all dropped.
    let evaded = "g\u{200D}h\u{FEFF}p\u{200B}_secretvalue00";
    let out = uh::normalize_homoglyphs(evaded);
    assert_eq!(&*out, "ghp_secretvalue00");
    // A drop happened, so the slow path must OWN the rebuilt buffer.
    assert!(matches!(out, Cow::Owned(_)), "strip must allocate");
}

#[test]
fn normalize_strips_combining_marks_from_two_blocks() {
    // U+1DC0 (Extended block) + U+FE20 (Combining Half Marks block) both dropped
    // — neither is in the legacy U+0300–036F block.
    let evaded = "g\u{1DC0}h\u{FE20}p_x1234567890abcd";
    let out = uh::normalize_homoglyphs(evaded);
    assert_eq!(&*out, "ghp_x1234567890abcd");
    assert!(matches!(out, Cow::Owned(_)));
}

#[test]
fn normalize_clean_ascii_borrows_unchanged() {
    // Pure-ASCII, no evasion control → zero-allocation fast path, byte-identical.
    let clean = "ghp_cleanASCII_1234567890";
    let out = uh::normalize_homoglyphs(clean);
    assert_eq!(&*out, "ghp_cleanASCII_1234567890");
    assert!(
        matches!(out, Cow::Borrowed(_)),
        "clean ASCII must not allocate"
    );
}

#[test]
fn normalize_standalone_combining_drops_to_base() {
    // `normalize_homoglyphs` (no NFC) DROPS the mark, leaving the bare base 'e'.
    let out = uh::normalize_homoglyphs("e\u{0301}");
    assert_eq!(&*out, "e");
    assert!(matches!(out, Cow::Owned(_)));
}

#[test]
fn full_normalize_nfc_precomposes_before_strip() {
    // Contrast with the test above: `full_normalize` runs NFC FIRST, so
    // e + U+0301 precomposes to U+00E9 'é' (not a mark) and survives.
    let out = uh::full_normalize("e\u{0301}");
    assert_eq!(out, "\u{00E9}");
}

#[test]
fn normalize_fullwidth_and_cyrillic_map_to_ascii() {
    // Fullwidth ｇｈｐ → ghp.
    let fw = uh::normalize_homoglyphs("\u{FF47}\u{FF48}\u{FF50}_1234");
    assert_eq!(&*fw, "ghp_1234");
    // Cyrillic а р і → a p i.
    let cy = uh::normalize_homoglyphs("\u{0430}\u{0440}\u{0456}");
    assert_eq!(&*cy, "api");
}

// ── is_evasion_char: proxy for (is_zero_width || is_rtl_override) ─────────────

#[test]
fn is_evasion_char_zero_width_and_rtl_true() {
    // is_zero_width members.
    assert!(uh::is_evasion_char('\u{200B}'), "ZWSP is evasion");
    assert!(uh::is_evasion_char('\u{FEFF}'), "BOM is evasion");
    assert!(uh::is_evasion_char('\u{200D}'), "ZWJ is evasion");
    // is_rtl_override member.
    assert!(uh::is_evasion_char('\u{202E}'), "RTL override is evasion");
    // Ordinary ASCII is never evasion.
    assert!(!uh::is_evasion_char('a'));
    assert!(!uh::is_evasion_char('_'));
}

#[test]
fn is_evasion_char_invisible_operators_gap_now_closed() {
    // Historical memory note: "is_zero_width still missing U+2061-2064" — now
    // closed AND the block extended. `is_zero_width` (unicode_hardening.rs) covers
    // the WHOLE `U+2060..=206F` invisible-operator/format/isolate block (2065
    // Reserved/Default_Ignorable, 2066-2069 bidi isolates, 206A-206F deprecated
    // Cf) — NOT just 2060-2064. It does NOT include the visible-width space
    // separators (NBSP U+00A0, MMSP U+205F, …); those are a separate
    // `contains_evasion` concern. `is_evasion_char = is_zero_width ||
    // is_rtl_override`. TEST TRUTH — the whole invisible block is flagged:
    for cp in 0x2060u32..=0x206F {
        let ch = char::from_u32(cp).unwrap();
        assert!(
            uh::is_evasion_char(ch),
            "U+{cp:04X} (invisible-operator block) must be flagged"
        );
    }
    // Boundary: U+2070 (SUPERSCRIPT ZERO) is the first codepoint past the 206F
    // block that is in NEITHER is_zero_width NOR is_rtl_override (U+202A..=202E).
    assert!(
        !uh::is_evasion_char('\u{2070}'),
        "U+2070 is a visible superscript digit, outside every evasion set"
    );
    // NBSP (U+00A0) and MMSP (U+205F) are visible-width SPACE SEPARATORS, NOT in
    // is_zero_width (invisible/zero-advance format chars only), so is_evasion_char
    // is false for them — a broader `contains_evasion` separator pass handles them.
    assert!(
        !uh::is_evasion_char('\u{00A0}'),
        "NBSP is a space separator, not in is_zero_width/is_rtl_override"
    );
    assert!(
        !uh::is_evasion_char('\u{205F}'),
        "MMSP is a space separator, not in is_zero_width/is_rtl_override"
    );
}

// ── contains_evasion: full truth table incl. the DEL / structural boundary ───

#[test]
fn contains_evasion_truth_table() {
    // Clean token: no evasion.
    assert!(!uh::contains_evasion("ghp_clean_ASCII_1234567890"));
    // Zero-width spliced in: evasion.
    assert!(uh::contains_evasion("a\u{200B}b"));
    // Structural whitespace is NOT evasion.
    assert!(!uh::contains_evasion("col1\tcol2"));
    assert!(!uh::contains_evasion("line1\nline2"));
    assert!(!uh::contains_evasion("line1\r\nline2"));
    // DEL (U+007F) IS an ASCII evasion control (the recall-hole class).
    let del = "ghp_ab\u{7F}cd";
    assert!(uh::contains_evasion(del));
    // A separator (NBSP) that is_evasion_char misses is still caught here.
    assert!(uh::contains_evasion("a\u{00A0}b"));
}

// ── strip_interior_evasion_controls: anchored strip vs structural preserve ───

#[test]
fn strip_interior_tab_inside_akia_body() {
    // AKIA at a word boundary, TAB flanked by credential bytes → dropped.
    let evaded = "AKIAIOSFODNN7\tEXAMPLE";
    let out = uh::strip_interior_evasion_controls(evaded);
    assert_eq!(&*out, "AKIAIOSFODNN7EXAMPLE");
    assert!(matches!(out, Cow::Owned(_)), "interior strip must allocate");
}

#[test]
fn strip_interior_cr_inside_ghp_body() {
    // ghp_ anchor, CR flanked by credential bytes → dropped.
    let evaded = "ghp_ABCdef123\r4567890";
    let out = uh::strip_interior_evasion_controls(evaded);
    assert_eq!(&*out, "ghp_ABCdef1234567890");
    assert!(matches!(out, Cow::Owned(_)));
}

#[test]
fn strip_preserves_structural_tsv_and_crlf() {
    // TSV tabs with NO credential anchor: must be preserved, zero-alloc borrow.
    let tsv = "col1\tcol2\tcol3";
    let out = uh::strip_interior_evasion_controls(tsv);
    assert_eq!(&*out, "col1\tcol2\tcol3");
    assert!(matches!(out, Cow::Borrowed(_)), "structural tabs preserved");

    // CRLF after a real anchor body: CR is followed by '\n' (not a credential
    // byte), so it is a line ending, not interior evasion → preserved, borrowed.
    let crlf = "ghp_ABCdef1234567890\r\nnextline";
    let out2 = uh::strip_interior_evasion_controls(crlf);
    assert_eq!(&*out2, "ghp_ABCdef1234567890\r\nnextline");
    assert!(matches!(out2, Cow::Borrowed(_)), "CRLF line end preserved");
}

#[test]
fn strip_does_not_anchor_mid_identifier() {
    // 'xAKIA...' — the AKIA match is preceded by an identifier byte, so the word
    // boundary check blocks the anchor; the interior TAB is left untouched.
    let evaded = "xAKIAIOSFODNN7\tEXAMPLE";
    let out = uh::strip_interior_evasion_controls(evaded);
    assert_eq!(&*out, "xAKIAIOSFODNN7\tEXAMPLE");
    assert!(
        matches!(out, Cow::Borrowed(_)),
        "mid-identifier anchor blocked, tab preserved"
    );
}
