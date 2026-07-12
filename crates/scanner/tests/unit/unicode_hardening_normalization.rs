//! Unicode homoglyph/invisible normalization + evasion detection
//! (`unicode_hardening.rs`), reached via the `keyhog_scanner::testing::unicode_hardening`
//! facade. Migrated from an inline `mod tests` to satisfy the
//! `unicode_hardening_no_inline_tests` gate.

use keyhog_scanner::testing::unicode_hardening::{
    char_normalization_is_drop, char_normalization_is_keep, contains_evasion, cyrillic_to_latin,
    detect_unicode_attacks, fullwidth_to_ascii, greek_to_latin, is_combining_mark, is_fullwidth,
    is_rtl_override, is_zero_width, normalize_homoglyphs, strip_interior_evasion_controls,
};
use std::borrow::Cow;
use std::collections::BTreeSet;

// A canonical target secret every evasion below tries (and fails) to hide.
const CANON: &str = "ghp_aBcD1234EfGh5678IjKl";

/// Splice `sep` between every char of `s`, so the raw byte sequence never
/// contains the canonical prefix but normalization must recover it.
fn interleave(s: &str, sep: char) -> String {
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 {
            out.push(sep);
        }
        out.push(ch);
    }
    out
}

// ----- Homoglyph classes -----------------------------------------------

#[test]
fn cyrillic_homoglyphs_map_to_latin_twins() {
    // Cyrillic о U+043E, р U+0440, е U+0435 + uppercase Н U+041D -> o p e H.
    let evil = "\u{043E}\u{0440}\u{0435}\u{041D}";
    assert_eq!(normalize_homoglyphs(evil), "opeH");
    // Individual mapping truth.
    assert_eq!(cyrillic_to_latin('\u{0440}'), Some('p'));
    assert_eq!(cyrillic_to_latin('\u{04BB}'), Some('h')); // һ
    assert_eq!(cyrillic_to_latin('\u{041D}'), Some('H')); // Н
    assert_eq!(cyrillic_to_latin('a'), None); // ASCII untouched
}

#[test]
fn cyrillic_disguised_prefix_normalizes_to_canonical() {
    // g-һ-p_… with Cyrillic һ (U+04BB) standing in for Latin h.
    let evil = format!("g\u{04BB}p_aBcD1234EfGh5678IjKl");
    assert_eq!(normalize_homoglyphs(&evil), CANON);
}

#[test]
fn greek_homoglyphs_map_to_latin_twins() {
    // α β ε ο ρ τ  ->  a b e o p t
    let evil = "\u{03B1}\u{03B2}\u{03B5}\u{03BF}\u{03C1}\u{03C4}";
    assert_eq!(normalize_homoglyphs(evil), "abeopt");
    assert_eq!(greek_to_latin('\u{03C1}'), Some('p')); // ρ
    assert_eq!(greek_to_latin('a'), None);
}

#[test]
fn fullwidth_ascii_maps_to_halfwidth() {
    // ｇｈｐ＿ = U+FF47 FF48 FF50 FF3F
    let evil = "\u{FF47}\u{FF48}\u{FF50}\u{FF3F}aBcD1234EfGh5678IjKl";
    assert_eq!(normalize_homoglyphs(evil), CANON);
    assert_eq!(fullwidth_to_ascii('\u{FF10}'), '0');
    assert_eq!(fullwidth_to_ascii('\u{FF5E}'), '~');
    assert!(!is_fullwidth('\u{FF61}')); // halfwidth katakana middle dot: not ASCII
}

// ----- Zero-width / invisible strip (incl. newly added ranges) ----------

#[test]
fn newly_added_zero_width_ranges_are_stripped() {
    // Each newly-added invisible codepoint must classify as zero-width...
    for &cp in &[
        '\u{2065}',
        '\u{206A}',
        '\u{206F}',
        '\u{180B}',
        '\u{180C}',
        '\u{180D}',
        '\u{180F}',
        '\u{115F}',
        '\u{1160}',
        '\u{3164}',
        '\u{FFA0}',
        '\u{1BCA0}',
        '\u{1BCA3}',
        '\u{1D173}',
        '\u{1D17A}',
        '\u{FFF0}',
        '\u{FFF8}',
    ] {
        assert!(is_zero_width(cp), "{:04X} must be zero-width", cp as u32);
    }
    // ...and be DROPPED (not replaced) by the normalizer.
    for &cp in &[
        '\u{2065}',
        '\u{206C}',
        '\u{180F}',
        '\u{115F}',
        '\u{3164}',
        '\u{FFA0}',
        '\u{1BCA1}',
        '\u{1D175}',
        '\u{FFF4}',
    ] {
        assert!(char_normalization_is_drop(cp), "{:04X}", cp as u32);
    }
}

#[test]
fn zero_width_negative_twins_are_not_stripped() {
    // Adjacent assigned, VISIBLE codepoints must survive untouched.
    for &cp in &[
        '\u{2070}',  // SUPERSCRIPT ZERO (right after 206F)
        '\u{FFA1}',  // HALFWIDTH HANGUL LETTER KIYEOK (right after filler FFA0)
        '\u{1161}',  // HANGUL JUNGSEONG A (right after filler 1160)
        '\u{3163}',  // HANGUL LETTER I (right before filler 3164)
        '\u{1D17B}', // MUSICAL SYMBOL COMBINING ACCENT (Mn, right after 1D17A range)
    ] {
        assert!(
            !is_zero_width(cp),
            "{:04X} must NOT be zero-width",
            cp as u32
        );
    }
    // 1D17B is a combining mark though (Mn) — it is still handled, just by a
    // different owner. A plain visible letter is fully kept:
    assert!(char_normalization_is_keep('\u{2070}'));
    assert!(char_normalization_is_keep('\u{FFA1}'));
}

#[test]
fn hangul_filler_split_credential_is_recovered() {
    // Invisible Hangul fillers (Lo, not Cf, not Mark) spliced through the body.
    let evil = interleave(CANON, '\u{3164}');
    assert_ne!(evil, CANON); // raw bytes are different
    assert_eq!(normalize_homoglyphs(&evil), CANON);
}

#[test]
fn mixed_invisible_splice_is_recovered() {
    // A cocktail of old + newly-added invisibles between every char.
    let seps = [
        '\u{200B}', '\u{2065}', '\u{206A}', '\u{180F}', '\u{FFA0}', '\u{FEFF}',
    ];
    let mut evil = String::new();
    for (i, ch) in CANON.chars().enumerate() {
        evil.push(seps[i % seps.len()]);
        evil.push(ch);
    }
    assert_eq!(normalize_homoglyphs(&evil), CANON);
}

#[test]
fn classic_zero_width_joiner_still_stripped() {
    let evil = "ghp\u{200D}_aBcD1234EfGh5678IjKl";
    assert_eq!(normalize_homoglyphs(evil), CANON);
}

// ----- Combining marks (decomposed) -------------------------------------

#[test]
fn combining_marks_are_stripped_across_blocks() {
    // U+0301 (Diacritical block) and U+1DC0 (Extended block, no precomposed
    // base) both interrupt the body and must be dropped.
    assert!(is_combining_mark('\u{0301}'));
    assert!(is_combining_mark('\u{1DC0}'));
    assert!(!is_combining_mark('a'));
    let evil = "g\u{0301}h\u{1DC0}p_aBcD1234EfGh5678IjKl";
    assert_eq!(normalize_homoglyphs(evil), CANON);
}

// ----- Tag block --------------------------------------------------------

#[test]
fn tag_block_is_stripped() {
    assert!(is_zero_width('\u{E0000}'));
    assert!(is_zero_width('\u{E007F}')); // CANCEL TAG
    assert!(is_zero_width('\u{E0041}')); // TAG LATIN A
                                         // Tag chars spliced through the body vanish.
    let evil = "ghp_\u{E0041}\u{E0042}aBcD1234EfGh5678IjKl";
    assert_eq!(normalize_homoglyphs(evil), CANON);
}

// ----- Bidi / RTL -------------------------------------------------------

#[test]
fn bidi_controls_are_stripped() {
    // Overrides/embeddings go through is_rtl_override; isolates through
    // is_zero_width; both Drop.
    for &cp in &['\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}'] {
        assert!(is_rtl_override(cp), "{:04X}", cp as u32);
        assert!(char_normalization_is_drop(cp));
    }
    for &cp in &['\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{061C}'] {
        assert!(is_zero_width(cp), "{:04X}", cp as u32);
        assert!(char_normalization_is_drop(cp));
    }
    let evil = "ghp_\u{202E}aBcD1234EfGh5678IjKl";
    assert_eq!(normalize_homoglyphs(evil), CANON);
}

// ----- Negatives: legitimate text must be untouched ---------------------

#[test]
fn plain_ascii_is_borrowed_unchanged() {
    let s = "ghp_aBcD1234EfGh5678IjKl and normal_code = fn(x) { y }";
    let out = normalize_homoglyphs(s);
    assert!(
        matches!(out, Cow::Borrowed(_)),
        "clean ASCII must not allocate"
    );
    assert_eq!(out, s);
}

#[test]
fn structural_whitespace_is_preserved() {
    let s = "col1\tcol2\r\nnext\tline";
    let out = normalize_homoglyphs(s);
    assert_eq!(out, s);
    assert!(matches!(out, Cow::Borrowed(_)));
}

#[test]
fn legitimate_cjk_text_is_unchanged() {
    // Real CJK (not fullwidth ASCII variants) must stay on the identity path.
    let s = "日本語のコメント 中文注释 한국어";
    assert_eq!(normalize_homoglyphs(s), s);
}

// ----- Detector / normalizer parity -------------------------------------

#[test]
fn detector_reports_every_evasion_class() {
    let evil = "g\u{04BB}p_\u{200B}\u{3164}a\u{0301}\u{E0041}\u{202E}b\u{FF10}\u{2065}";
    let hits = detect_unicode_attacks(evil);
    let kinds: BTreeSet<_> = hits.iter().map(|m| format!("{:?}", m.kind)).collect();
    assert!(kinds.contains("CyrillicHomoglyph"), "{kinds:?}");
    assert!(kinds.contains("ZeroWidth"), "{kinds:?}");
    assert!(kinds.contains("Decomposed"), "{kinds:?}");
    assert!(kinds.contains("RTLOverride"), "{kinds:?}");
    assert!(kinds.contains("Fullwidth"), "{kinds:?}");
}

#[test]
fn contains_evasion_agrees_with_normalized_char() {
    assert!(contains_evasion("ghp\u{2065}_x")); // newly-added invisible
    assert!(contains_evasion("g\u{04BB}p")); // homoglyph
    assert!(!contains_evasion("ghp_plain_ascii_token"));
}

// ----- Fail-closed automaton (Law 10) -----------------------------------

#[test]
fn evasion_anchor_ac_is_present_and_strips_interior_control() {
    // If the LazyLock had silently returned None on a build bug, this strip
    // would no-op and the assertion would fail loudly.
    let evil = "AKIA\tQYLPMN5HFIQR7XYA";
    let stripped = strip_interior_evasion_controls(evil);
    assert_eq!(stripped, "AKIAQYLPMN5HFIQR7XYA");
    assert!(matches!(stripped, Cow::Owned(_)));
}

#[test]
fn structural_control_outside_credential_is_kept() {
    // TAB between ordinary identifiers (no anchor) must survive.
    let s = "value\tother";
    assert_eq!(strip_interior_evasion_controls(s), s);
    // CRLF line end must survive even after an anchor.
    let s2 = "ghp_abcdef\r\nnext";
    assert_eq!(strip_interior_evasion_controls(s2), s2);
}
