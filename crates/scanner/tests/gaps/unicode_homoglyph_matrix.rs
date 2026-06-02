//! Gap suite: unicode_homoglyph_matrix
//!
//! Exhaustive truth tests for `keyhog_scanner::unicode_hardening::normalize_homoglyphs`
//! (and the NFC-fronted `full_normalize`) across the full homoglyph matrix:
//! Cyrillic, Greek, fullwidth, zero-width, RTL/bidi, Unicode separators, and
//! combining marks. Every expected value below is derived directly from the
//! match tables in `crates/scanner/src/unicode_hardening.rs`:
//!
//!   * `cyrillic_to_latin`  (lines ~338-375)
//!   * `greek_to_latin`     (lines ~378-408)
//!   * `is_fullwidth` / `fullwidth_to_ascii` (lines ~411-429): code - 0xFEE0 for
//!     U+FF01..=U+FF5E, else returned unchanged.
//!   * `is_zero_width`      (lines ~437-454): stripped (replacement None).
//!   * `is_rtl_override`    (lines ~476-485): stripped.
//!   * `is_unicode_separator_evasion` (lines ~456-469): stripped.
//!   * `is_combining_mark`  (U+0300..=U+036F, line ~471): stripped.
//!   * `is_ascii_evasion_control` (line ~334): ASCII control except \n \r \t,
//!     stripped on the slow path.
//!
//! Slow-path char order (normalize_homoglyphs, lines ~163-185):
//!   cyrillic -> greek -> fullwidth -> (zero-width | rtl | separator |
//!   combining | ascii-evasion-control => drop) -> else keep verbatim.
//!
//! Case preservation: the tables map lowercase source codepoints to lowercase
//! Latin and uppercase source codepoints to uppercase Latin, so e.g.
//! lowercase Greek alpha U+03B1 => 'a' and uppercase Greek Alpha U+0391 => 'A'.

use keyhog_scanner::unicode_hardening::*;
use std::borrow::Cow;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Owned normalized string (collapses the Cow for value assertions).
fn norm(s: &str) -> String {
    normalize_homoglyphs(s).into_owned()
}

/// True when the Cow returned is the zero-copy borrowed variant pointing at the
/// exact same backing bytes (proves the fast path took, no allocation).
fn is_borrowed_same_ptr(input: &str) -> bool {
    match normalize_homoglyphs(input) {
        Cow::Borrowed(b) => b.as_ptr() == input.as_ptr(),
        Cow::Owned(_) => false,
    }
}

/// True when the Cow returned is owned (slow rebuild path took).
fn is_owned(input: &str) -> bool {
    matches!(normalize_homoglyphs(input), Cow::Owned(_))
}

// ---------------------------------------------------------------------------
// Cyrillic lowercase homoglyphs -> lowercase Latin
// ---------------------------------------------------------------------------

#[test]
fn cyrillic_lowercase_full_table_to_latin() {
    // (source codepoint, expected Latin) — derived from cyrillic_to_latin.
    let cases: &[(char, char)] = &[
        ('\u{0430}', 'a'), // а
        ('\u{0435}', 'e'), // е
        ('\u{0456}', 'i'), // і
        ('\u{0458}', 'j'), // ј
        ('\u{043E}', 'o'), // о
        ('\u{0440}', 'p'), // р
        ('\u{0441}', 'c'), // с
        ('\u{0443}', 'y'), // у
        ('\u{0445}', 'x'), // х
        ('\u{0455}', 's'), // ѕ
        ('\u{04BB}', 'h'), // һ
        ('\u{0261}', 'g'), // ɡ
        ('\u{0457}', 'i'), // ї
        ('\u{043A}', 'k'), // к
        ('\u{0442}', 't'), // т
    ];
    for (src, want) in cases {
        let input = format!("ghp_{src}END");
        let want_str = format!("ghp_{want}END");
        assert_eq!(
            norm(&input),
            want_str,
            "Cyrillic U+{:04X} must normalize to '{want}'",
            *src as u32
        );
    }
}

#[test]
fn cyrillic_uppercase_full_table_to_latin() {
    let cases: &[(char, char)] = &[
        ('\u{0410}', 'A'), // А
        ('\u{0412}', 'B'), // В
        ('\u{0415}', 'E'), // Е
        ('\u{0406}', 'I'), // І
        ('\u{0408}', 'J'), // Ј
        ('\u{041A}', 'K'), // К
        ('\u{041C}', 'M'), // М
        ('\u{041D}', 'H'), // Н (Cyrillic En -> visual H)
        ('\u{041E}', 'O'), // О
        ('\u{0420}', 'P'), // Р
        ('\u{0421}', 'C'), // С
        ('\u{0405}', 'S'), // Ѕ
        ('\u{0422}', 'T'), // Т
        ('\u{0425}', 'X'), // Х
        ('\u{04AE}', 'Y'), // Ү
        ('\u{0407}', 'I'), // Ї
    ];
    for (src, want) in cases {
        let input = format!("PRE{src}post");
        let want_str = format!("PRE{want}post");
        assert_eq!(
            norm(&input),
            want_str,
            "Cyrillic U+{:04X} must normalize to '{want}'",
            *src as u32
        );
    }
}

#[test]
fn cyrillic_en_capital_is_uppercase_h_not_lowercase() {
    // U+041D (Cyrillic capital En) maps to ASCII 'H', proving case preservation:
    // it is NOT folded to lowercase 'h'.
    assert_eq!(norm("\u{041D}"), "H");
    assert_ne!(norm("\u{041D}"), "h");
}

#[test]
fn cyrillic_whole_word_password_homoglyphs() {
    // "раѕѕ" built from Cyrillic р(p) а(a) ѕ(s) ѕ(s) -> "pass".
    let input = "\u{0440}\u{0430}\u{0455}\u{0455}word";
    assert_eq!(norm(input), "password");
    assert!(norm(input).is_ascii());
}

// ---------------------------------------------------------------------------
// Greek lowercase homoglyphs -> lowercase Latin
// ---------------------------------------------------------------------------

#[test]
fn greek_lowercase_full_table_to_latin() {
    let cases: &[(char, char)] = &[
        ('\u{03B1}', 'a'), // α
        ('\u{03B2}', 'b'), // β  (lowercase beta -> lowercase 'b')
        ('\u{03B5}', 'e'), // ε
        ('\u{03B9}', 'i'), // ι
        ('\u{03BA}', 'k'), // κ
        ('\u{03BD}', 'v'), // ν  (nu -> 'v', NOT 'n')
        ('\u{03BF}', 'o'), // ο
        ('\u{03C1}', 'p'), // ρ
        ('\u{03C4}', 't'), // τ
        ('\u{03C5}', 'u'), // υ  (upsilon -> 'u', NOT 'y')
        ('\u{03C7}', 'x'), // χ
        ('\u{03C9}', 'w'), // ω  (omega -> 'w')
    ];
    for (src, want) in cases {
        let input = format!("sk_{src}tail");
        let want_str = format!("sk_{want}tail");
        assert_eq!(
            norm(&input),
            want_str,
            "Greek U+{:04X} must normalize to '{want}'",
            *src as u32
        );
    }
}

#[test]
fn greek_uppercase_full_table_to_latin() {
    let cases: &[(char, char)] = &[
        ('\u{0391}', 'A'), // Α
        ('\u{0392}', 'B'), // Β
        ('\u{0395}', 'E'), // Ε
        ('\u{0397}', 'H'), // Η  (Eta -> 'H')
        ('\u{0399}', 'I'), // Ι
        ('\u{039A}', 'K'), // Κ
        ('\u{039C}', 'M'), // Μ
        ('\u{039D}', 'N'), // Ν  (Nu uppercase -> 'N')
        ('\u{039F}', 'O'), // Ο
        ('\u{03A1}', 'P'), // Ρ
        ('\u{03A4}', 'T'), // Τ
        ('\u{03A5}', 'Y'), // Υ  (uppercase Upsilon -> 'Y')
        ('\u{03A7}', 'X'), // Χ
        ('\u{0396}', 'Z'), // Ζ  (Zeta -> 'Z')
    ];
    for (src, want) in cases {
        let input = format!("X{src}X");
        let want_str = format!("X{want}X");
        assert_eq!(
            norm(&input),
            want_str,
            "Greek U+{:04X} must normalize to '{want}'",
            *src as u32
        );
    }
}

#[test]
fn greek_nu_lower_is_v_upper_is_n() {
    // Adversarial: nu's case-asymmetric mapping. Lowercase ν->'v', uppercase Ν->'N'.
    assert_eq!(norm("\u{03BD}"), "v");
    assert_eq!(norm("\u{039D}"), "N");
}

#[test]
fn greek_upsilon_lower_is_u_upper_is_y() {
    // Lowercase υ -> 'u', uppercase Υ -> 'Y'. Both case-asymmetric.
    assert_eq!(norm("\u{03C5}"), "u");
    assert_eq!(norm("\u{03A5}"), "Y");
}

#[test]
fn greek_beta_lower_is_b_lowercase() {
    // U+03B2 lowercase beta maps to lowercase 'b' (comment notes it "can look
    // like B", but the table value is 'b').
    assert_eq!(norm("\u{03B2}"), "b");
    assert_ne!(norm("\u{03B2}"), "B");
}

#[test]
fn greek_only_alpha_uppercase_preserved() {
    // Uppercase Greek Alpha -> uppercase Latin 'A'.
    assert_eq!(norm("\u{0391}KIA"), "AKIA");
}

// ---------------------------------------------------------------------------
// Fullwidth ASCII variants (U+FF01..=U+FF5E => code - 0xFEE0)
// ---------------------------------------------------------------------------

#[test]
fn fullwidth_lowercase_letters_to_ascii() {
    // ｇｈｐ -> ghp. U+FF47 - 0xFEE0 = 0x67 = 'g', etc.
    let input = "\u{FF47}\u{FF48}\u{FF50}_token";
    assert_eq!(norm(input), "ghp_token");
    assert!(norm(input).is_ascii());
}

#[test]
fn fullwidth_uppercase_letters_to_ascii() {
    // Ａ U+FF21 -> 0x41 'A'; Ｋ U+FF2B -> 0x4B 'K'; Ｉ U+FF29 -> 0x49 'I'.
    let input = "\u{FF21}\u{FF2B}\u{FF29}\u{FF21}";
    assert_eq!(norm(input), "AKIA");
}

#[test]
fn fullwidth_digits_and_underscore_region() {
    // Fullwidth digit ０ U+FF10 -> '0', ９ U+FF19 -> '9'.
    // Underscore '_' U+005F has fullwidth form U+FF3F -> 0x5F '_'.
    assert_eq!(norm("\u{FF10}\u{FF19}"), "09");
    assert_eq!(norm("\u{FF3F}"), "_");
}

#[test]
fn fullwidth_punctuation_boundaries_ff01_and_ff5e() {
    // Lower bound of the convertible window: U+FF01 (fullwidth '!') -> 0x21 '!'.
    assert_eq!(norm("\u{FF01}"), "!");
    // Upper bound: U+FF5E (fullwidth '~') -> 0x7E '~'.
    assert_eq!(norm("\u{FF5E}"), "~");
}

#[test]
fn fullwidth_outside_convertible_window_is_kept_verbatim() {
    // is_fullwidth covers U+FF00..=U+FFEF, but fullwidth_to_ascii only converts
    // U+FF01..=U+FF5E. Codepoints in [FF00..=FFEF] OUTSIDE that window are
    // returned UNCHANGED (the `else { ch }` branch), so they survive in output.
    // U+FFE0 (fullwidth cent sign) is in is_fullwidth's range but not converted.
    assert_eq!(norm("\u{FFE0}"), "\u{FFE0}");
    // U+FF00 itself (just below FF01) is also not converted.
    assert_eq!(norm("\u{FF00}"), "\u{FF00}");
    // U+FFEF (top of range) -> not converted, kept verbatim.
    assert_eq!(norm("\u{FFEF}"), "\u{FFEF}");
}

#[test]
fn fullwidth_space_ff5f_boundary_not_converted() {
    // U+FF5F is above FF5E, still within is_fullwidth, so NOT converted.
    assert_eq!(norm("\u{FF5F}"), "\u{FF5F}");
}

// ---------------------------------------------------------------------------
// Zero-width characters: stripped entirely
// ---------------------------------------------------------------------------

#[test]
fn zero_width_full_table_stripped() {
    // Each zero-width codepoint embedded between credential bytes must vanish.
    let zw: &[char] = &[
        '\u{200B}', // ZWSP
        '\u{200C}', // ZWNJ
        '\u{200D}', // ZWJ
        '\u{FEFF}', // BOM / ZWNBSP
        '\u{2060}', // Word Joiner
        '\u{180E}', // Mongolian Vowel Separator
        '\u{200E}', // LRM
        '\u{200F}', // RLM
        '\u{00AD}', // Soft Hyphen
        '\u{2066}', // LRI
        '\u{2067}', // RLI
        '\u{2068}', // FSI
        '\u{2069}', // PDI
    ];
    for ch in zw {
        let input = format!("AKIA{ch}QYLP");
        assert_eq!(
            norm(&input),
            "AKIAQYLP",
            "zero-width U+{:04X} must be stripped",
            *ch as u32
        );
    }
}

#[test]
fn soft_hyphen_is_zero_width_stripped() {
    // U+00AD soft hyphen is classified zero-width (not a separator), so a
    // single soft hyphen between two halves of a token collapses them.
    assert_eq!(norm("ghp\u{00AD}_secret"), "ghp_secret");
}

#[test]
fn bom_stripped_mid_string() {
    assert_eq!(norm("sk_live_\u{FEFF}abc"), "sk_live_abc");
}

// ---------------------------------------------------------------------------
// RTL / bidi override characters: stripped
// ---------------------------------------------------------------------------

#[test]
fn rtl_override_full_table_stripped() {
    let rtl: &[char] = &[
        '\u{202E}', // RLO
        '\u{202D}', // LRO
        '\u{202A}', // LRE
        '\u{202B}', // RLE
        '\u{202C}', // PDF
    ];
    for ch in rtl {
        let input = format!("token{ch}value");
        assert_eq!(
            norm(&input),
            "tokenvalue",
            "RTL override U+{:04X} must be stripped",
            *ch as u32
        );
    }
}

#[test]
fn rtl_override_does_not_reorder_remaining_bytes() {
    // Stripping is positional removal only: surviving chars keep source order.
    assert_eq!(norm("abc\u{202E}def"), "abcdef");
}

// ---------------------------------------------------------------------------
// Unicode separator-evasion characters: stripped
// ---------------------------------------------------------------------------

#[test]
fn unicode_separator_full_table_stripped() {
    let seps: &[char] = &[
        '\u{0085}', // NEL
        '\u{00A0}', // NBSP
        '\u{2000}', // EN QUAD (low bound of 2000..=200A range)
        '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}', '\u{2005}', '\u{2006}', '\u{2007}',
        '\u{2008}', '\u{2009}', '\u{200A}', // HAIR SPACE (high bound of range)
        '\u{2028}', // LINE SEPARATOR
        '\u{2029}', // PARAGRAPH SEPARATOR
        '\u{202F}', // NARROW NBSP
        '\u{205F}', // MEDIUM MATH SPACE
        '\u{3000}', // IDEOGRAPHIC SPACE
    ];
    for ch in seps {
        let input = format!("AKIA{ch}IOSFODNN7");
        assert_eq!(
            norm(&input),
            "AKIAIOSFODNN7",
            "separator U+{:04X} must be stripped",
            *ch as u32
        );
    }
}

#[test]
fn nbsp_between_assignment_collapses() {
    // No-break space U+00A0 used to split `key=value` is removed entirely.
    assert_eq!(norm("api_key\u{00A0}=\u{00A0}sk_live"), "api_key=sk_live");
}

#[test]
fn ideographic_space_stripped() {
    assert_eq!(norm("ghp\u{3000}token"), "ghptoken");
}

// ---------------------------------------------------------------------------
// Combining marks (NFD residue) U+0300..=U+036F: stripped by normalize_homoglyphs
// ---------------------------------------------------------------------------

#[test]
fn combining_marks_stripped_keeping_base() {
    // Base letter survives, the combining diacritic is dropped.
    // 'e' + U+0301 (combining acute) -> "e".
    assert_eq!(norm("e\u{0301}"), "e");
    // 'n' + U+0303 (combining tilde) -> "n".
    assert_eq!(norm("n\u{0303}"), "n");
}

#[test]
fn combining_mark_range_boundaries_stripped() {
    // Lower bound U+0300 and upper bound U+036F both stripped.
    assert_eq!(norm("a\u{0300}b\u{036F}c"), "abc");
}

#[test]
fn combining_mark_just_above_range_is_kept() {
    // U+0370 is one past the combining range; it is NOT a combining mark, NOT a
    // homoglyph, NOT a separator -> kept verbatim. (Greek capital Heta letter.)
    assert_eq!(norm("\u{0370}"), "\u{0370}");
}

#[test]
fn combining_mark_just_below_range_kept() {
    // U+02FF (one below 0x0300) is not in the combining range -> kept verbatim.
    assert_eq!(norm("a\u{02FF}b"), "a\u{02FF}b");
}

// ---------------------------------------------------------------------------
// ASCII evasion control bytes: stripped on slow path (\n \r \t whitelisted)
// ---------------------------------------------------------------------------

#[test]
fn ascii_prohibited_control_stripped_on_slow_path() {
    // 0x01 (SOH) is an ASCII control NOT in {\n,\r,\t}: contains_ascii_evasion
    // is true, so the slow path runs and is_ascii_evasion_control drops it.
    assert_eq!(norm("ghp_abc\u{0001}def"), "ghp_abcdef");
}

#[test]
fn ascii_multiple_prohibited_controls_stripped() {
    // VT 0x0B and FF 0x0C are both stripped; tab between survives... but the
    // presence of 0x0B forces the slow path, and \t is whitelisted so it stays.
    assert_eq!(norm("a\u{000B}b\tc\u{000C}d"), "ab\tcd");
}

#[test]
fn ascii_null_byte_stripped() {
    assert_eq!(norm("sk\u{0000}live"), "sklive");
}

// ---------------------------------------------------------------------------
// Cow fast-path / slow-path discrimination (allocation behavior is contract)
// ---------------------------------------------------------------------------

#[test]
fn fast_path_pure_ascii_is_borrowed_zero_copy() {
    let text = "ghp_ABCDEFghijkl0123456789_-=+/.";
    assert!(
        is_borrowed_same_ptr(text),
        "pure ASCII with no evasion must be Cow::Borrowed at the same pointer"
    );
}

#[test]
fn fast_path_ascii_with_whitelisted_whitespace_is_borrowed() {
    // \n \r \t are whitelisted by contains_ascii_evasion -> fast path holds.
    let text = "line1\nline2\r\n\tindented";
    assert!(is_borrowed_same_ptr(text));
}

#[test]
fn fast_path_empty_string_is_borrowed() {
    // Empty string is ASCII with no evasion -> borrowed, normalizes to "".
    let text = "";
    assert!(is_borrowed_same_ptr(text));
    assert_eq!(norm(text), "");
}

#[test]
fn fast_path_clean_non_ascii_is_borrowed() {
    // Accented Latin PRECOMPOSED chars (single codepoints, explicit escapes so
    // no decomposed combining residue sneaks in) are not homoglyphs/evasion.
    // !is_ascii() && !contains_evasion() -> Cow::Borrowed, unchanged.
    // caf(U+00E9) na(U+00EF)ve r(U+00E9)sum(U+00E9)
    let text = "caf\u{00E9}_na\u{00EF}ve_r\u{00E9}sum\u{00E9}";
    assert!(
        is_borrowed_same_ptr(text),
        "clean non-ASCII must stay borrowed"
    );
    assert_eq!(norm(text), text);
}

#[test]
fn slow_path_ascii_prohibited_control_is_owned() {
    assert!(is_owned("ghp_abc\u{0001}def"));
}

#[test]
fn slow_path_homoglyph_present_is_owned() {
    assert!(is_owned("ghp_\u{0430}bc")); // Cyrillic а
}

#[test]
fn slow_path_zero_width_present_is_owned() {
    assert!(is_owned("ghp\u{200B}token"));
}

// ---------------------------------------------------------------------------
// Mixed-script / compound attacks: combinations across categories
// ---------------------------------------------------------------------------

#[test]
fn mixed_cyrillic_greek_fullwidth_one_pass() {
    // Cyrillic р(p), Greek α(a), two fullwidth ｓ(s) -> "pass", then ASCII "word".
    // The two ｓ supply both s's so the mixed-script attack spells "password".
    let input = "\u{0440}\u{03B1}\u{FF53}\u{FF53}word";
    assert_eq!(norm(input), "password");
    assert!(norm(input).is_ascii());
}

#[test]
fn mixed_homoglyph_plus_zero_width_plus_combining() {
    // Greek ο(o) + ZWSP + 'k' + combining acute -> "ok".
    let input = "\u{03BF}\u{200B}k\u{0301}";
    assert_eq!(norm(input), "ok");
}

#[test]
fn aws_access_key_id_fully_homoglyphed() {
    // Rebuild "AKIA" from Greek Α(A) + Cyrillic К(K) + Cyrillic І(I) + Greek Α(A),
    // then literal "IOSFODNN7EXAMPLE".
    let input = "\u{0391}\u{041A}\u{0406}\u{0391}IOSFODNN7EXAMPLE";
    assert_eq!(norm(input), "AKIAIOSFODNN7EXAMPLE");
    assert!(norm(input).is_ascii());
}

#[test]
fn separator_split_then_homoglyph_combined() {
    // Attacker splits a token with NBSP and swaps a Cyrillic letter.
    // "sk_live_" + NBSP + Cyrillic с(c) + "afe" -> "sk_live_cafe".
    let input = "sk_live_\u{00A0}\u{0441}afe";
    assert_eq!(norm(input), "sk_live_cafe");
}

#[test]
fn order_cyrillic_takes_priority_over_other_checks() {
    // Cyrillic 'о' U+043E and Greek 'ο' U+03BF both look like 'o'. Each maps to
    // 'o' independently; interleaving them yields all 'o'.
    let input = "\u{043E}\u{03BF}\u{043E}";
    assert_eq!(norm(input), "ooo");
}

// ---------------------------------------------------------------------------
// Non-homoglyph clean characters are preserved (negative twins)
// ---------------------------------------------------------------------------

#[test]
fn cyrillic_non_homoglyph_letter_kept_but_triggers_slow_path() {
    // Cyrillic 'б' (U+0431, "be") is NOT in cyrillic_to_latin, NOT a separator,
    // NOT combining. It is non-ASCII; contains_evasion() returns false for it
    // (no ascii-evasion, detect_unicode_attacks empty, not separator/combining),
    // so the fast non-ASCII borrow path keeps it verbatim.
    let text = "\u{0431}token";
    assert_eq!(norm(text), "\u{0431}token");
    assert!(is_borrowed_same_ptr(text));
}

#[test]
fn emoji_is_preserved_and_borrowed() {
    // Emoji is non-ASCII, not an evasion character -> borrowed, unchanged.
    let text = "deploy \u{1F680} now";
    assert_eq!(norm(text), text);
    assert!(is_borrowed_same_ptr(text));
}

#[test]
fn plain_ascii_letters_never_rewritten() {
    // Latin ASCII 'a','o','p' must never be touched — only their lookalikes are.
    let text = "aop_AOP";
    assert_eq!(norm(text), "aop_AOP");
    assert!(is_borrowed_same_ptr(text));
}

// ---------------------------------------------------------------------------
// is_evasion_char public predicate (zero-width OR rtl-override only)
// ---------------------------------------------------------------------------

#[test]
fn is_evasion_char_zero_width_and_rtl_true() {
    assert!(is_evasion_char('\u{200B}')); // ZWSP
    assert!(is_evasion_char('\u{FEFF}')); // BOM
    assert!(is_evasion_char('\u{202E}')); // RLO
    assert!(is_evasion_char('\u{00AD}')); // soft hyphen (zero-width)
}

#[test]
fn is_evasion_char_false_for_homoglyph_separator_and_ascii() {
    // is_evasion_char is ONLY zero-width|rtl. Homoglyphs, separators, combining
    // marks, and plain ASCII are NOT covered by this predicate.
    assert!(!is_evasion_char('\u{0430}')); // Cyrillic а (homoglyph, not evasion-char)
    assert!(!is_evasion_char('\u{00A0}')); // NBSP (separator, not zero-width here)
    assert!(!is_evasion_char('\u{0301}')); // combining acute
    assert!(!is_evasion_char('a')); // ASCII
    assert!(!is_evasion_char('\u{FF41}')); // fullwidth 'a'
}

// ---------------------------------------------------------------------------
// detect_unicode_attacks: kind, position, char, replacement matrix
// ---------------------------------------------------------------------------

#[test]
fn detect_cyrillic_reports_kind_position_and_replacement() {
    // "x" (1 byte) then Cyrillic а at byte offset 1.
    let attacks = detect_unicode_attacks("x\u{0430}");
    assert_eq!(attacks.len(), 1);
    let m = &attacks[0];
    assert_eq!(m.kind, EvasionKind::CyrillicHomoglyph);
    assert_eq!(m.position, 1);
    assert_eq!(m.char, '\u{0430}');
    assert_eq!(m.replacement, Some('a'));
}

#[test]
fn detect_greek_reports_greek_kind_and_replacement() {
    let attacks = detect_unicode_attacks("\u{03B1}");
    assert_eq!(attacks.len(), 1);
    assert_eq!(attacks[0].kind, EvasionKind::GreekHomoglyph);
    assert_eq!(attacks[0].position, 0);
    assert_eq!(attacks[0].replacement, Some('a'));
}

#[test]
fn detect_fullwidth_reports_fullwidth_kind_and_ascii_replacement() {
    let attacks = detect_unicode_attacks("\u{FF47}"); // fullwidth g
    assert_eq!(attacks.len(), 1);
    assert_eq!(attacks[0].kind, EvasionKind::Fullwidth);
    assert_eq!(attacks[0].replacement, Some('g'));
}

#[test]
fn detect_zero_width_has_none_replacement() {
    let attacks = detect_unicode_attacks("\u{200B}");
    assert_eq!(attacks.len(), 1);
    assert_eq!(attacks[0].kind, EvasionKind::ZeroWidth);
    assert_eq!(attacks[0].replacement, None);
}

#[test]
fn detect_rtl_override_kind_none_replacement() {
    let attacks = detect_unicode_attacks("\u{202E}");
    assert_eq!(attacks.len(), 1);
    assert_eq!(attacks[0].kind, EvasionKind::RTLOverride);
    assert_eq!(attacks[0].replacement, None);
}

#[test]
fn detect_combining_mark_is_decomposed_kind() {
    let attacks = detect_unicode_attacks("a\u{0301}");
    // Only the combining mark is flagged; the base 'a' is clean ASCII.
    assert_eq!(attacks.len(), 1);
    assert_eq!(attacks[0].kind, EvasionKind::Decomposed);
    assert_eq!(attacks[0].position, 1); // 'a' is 1 byte, mark at offset 1
    assert_eq!(attacks[0].char, '\u{0301}');
    assert_eq!(attacks[0].replacement, None);
}

#[test]
fn detect_separator_is_suspicious_kind() {
    let attacks = detect_unicode_attacks("\u{00A0}");
    assert_eq!(attacks.len(), 1);
    assert_eq!(attacks[0].kind, EvasionKind::Suspicious);
    assert_eq!(attacks[0].replacement, None);
}

#[test]
fn detect_byte_positions_account_for_multibyte_width() {
    // 'A' (1 byte) + Cyrillic К U+041A (2 bytes, at offset 1) + Greek α (2 bytes,
    // at offset 3) + ZWSP (3 bytes, at offset 5).
    let text = "A\u{041A}\u{03B1}\u{200B}";
    let attacks = detect_unicode_attacks(text);
    assert_eq!(attacks.len(), 3);
    assert_eq!(attacks[0].position, 1);
    assert_eq!(attacks[0].kind, EvasionKind::CyrillicHomoglyph);
    assert_eq!(attacks[1].position, 3);
    assert_eq!(attacks[1].kind, EvasionKind::GreekHomoglyph);
    assert_eq!(attacks[2].position, 5);
    assert_eq!(attacks[2].kind, EvasionKind::ZeroWidth);
}

#[test]
fn detect_clean_ascii_returns_empty() {
    assert!(detect_unicode_attacks("ghp_abcdef0123").is_empty());
}

#[test]
fn evasion_kind_descriptions_are_exact() {
    assert_eq!(
        EvasionKind::CyrillicHomoglyph.description(),
        "Cyrillic lookalike character"
    );
    assert_eq!(
        EvasionKind::GreekHomoglyph.description(),
        "Greek lookalike character"
    );
    assert_eq!(
        EvasionKind::Fullwidth.description(),
        "Fullwidth ASCII variant"
    );
    assert_eq!(EvasionKind::ZeroWidth.description(), "Zero-width character");
    assert_eq!(
        EvasionKind::RTLOverride.description(),
        "Right-to-left override"
    );
    assert_eq!(
        EvasionKind::Decomposed.description(),
        "Decomposed Unicode form"
    );
    assert_eq!(
        EvasionKind::Suspicious.description(),
        "Suspicious Unicode usage"
    );
}

// ---------------------------------------------------------------------------
// contains_evasion gate (must agree with normalize_homoglyphs' Cow decision)
// ---------------------------------------------------------------------------

#[test]
fn contains_evasion_true_for_each_category() {
    assert!(contains_evasion("\u{0430}")); // cyrillic
    assert!(contains_evasion("\u{03B1}")); // greek
    assert!(contains_evasion("\u{FF47}")); // fullwidth
    assert!(contains_evasion("\u{200B}")); // zero-width
    assert!(contains_evasion("\u{202E}")); // rtl
    assert!(contains_evasion("\u{00A0}")); // separator
    assert!(contains_evasion("a\u{0301}")); // combining
    assert!(contains_evasion("a\u{0001}b")); // ascii control evasion
}

#[test]
fn contains_evasion_false_for_clean_inputs() {
    assert!(!contains_evasion("ghp_abc123")); // ascii clean
    assert!(!contains_evasion("caf\u{00E9}")); // clean non-ascii precomposed (é U+00E9)
    assert!(!contains_evasion("ab\tcd\r\n")); // whitelisted controls
    assert!(!contains_evasion("\u{0431}")); // Cyrillic 'б' not a tracked homoglyph
}

// ---------------------------------------------------------------------------
// full_normalize: NFC composition THEN homoglyph normalization
// ---------------------------------------------------------------------------

#[test]
fn full_normalize_composes_nfd_then_keeps_precomposed() {
    // 'e' + U+0301 -> NFC -> U+00E9 ("é" precomposed), which is clean non-ASCII
    // and survives homoglyph normalization. Contrast: normalize_homoglyphs alone
    // STRIPS the combining mark (-> "e"), but full_normalize composes first.
    assert_eq!(full_normalize("e\u{0301}"), "\u{00E9}");
    assert_eq!(norm("e\u{0301}"), "e");
}

#[test]
fn full_normalize_still_converts_homoglyphs() {
    // NFC leaves the Cyrillic homoglyph alone (it's already composed), then
    // normalize_homoglyphs converts it.
    assert_eq!(full_normalize("\u{0430}bc"), "abc");
}

#[test]
fn full_normalize_strips_zero_width_after_nfc() {
    assert_eq!(full_normalize("ghp\u{200B}_tok"), "ghp_tok");
}

#[test]
fn full_normalize_pure_ascii_identity() {
    assert_eq!(full_normalize("ghp_abc123"), "ghp_abc123");
}

// ---------------------------------------------------------------------------
// Property-style loops over pure tables (idempotence + invariants)
// ---------------------------------------------------------------------------

#[test]
fn property_normalize_is_idempotent_over_homoglyph_corpus() {
    // For a spread of inputs, normalizing twice equals normalizing once.
    let corpus = [
        "ghp_\u{0430}\u{03B1}\u{FF53}word",
        "AKIA\u{200B}\u{202E}IOSFODNN7",
        "e\u{0301}n\u{0303}",
        "sk_live_\u{00A0}\u{0441}afe",
        "\u{0391}\u{041A}\u{0406}\u{0391}",
        "plain ascii line",
        "caf\u{00E9} r\u{00E9}sum\u{00E9}",
    ];
    for input in corpus {
        let once = norm(input);
        let twice = norm(&once);
        assert_eq!(once, twice, "normalize must be idempotent for {input:?}");
    }
}

#[test]
fn property_normalized_homoglyph_only_input_is_ascii() {
    // Any string built solely from mapped homoglyphs + ASCII must normalize to
    // a fully-ASCII string (no non-ASCII residue from the mapped set).
    let mapped: &[char] = &[
        '\u{0430}', '\u{03B1}', '\u{FF53}', '\u{041A}', '\u{0391}', '\u{03BD}', '\u{03C5}',
        '\u{FF10}', '\u{FF21}',
    ];
    for &c in mapped {
        let s = format!("PRE{c}post");
        assert!(
            norm(&s).is_ascii(),
            "mapped homoglyph U+{:04X} must normalize to ASCII",
            c as u32
        );
    }
}

#[test]
fn property_stripped_chars_never_appear_in_output() {
    // Strip-only categories must never leak into the normalized output.
    let stripped: &[char] = &[
        '\u{200B}', '\u{200D}', '\u{FEFF}', '\u{2060}', '\u{00AD}', '\u{202E}', '\u{202C}',
        '\u{00A0}', '\u{2028}', '\u{3000}', '\u{0301}', '\u{036F}', '\u{0001}', '\u{0000}',
    ];
    for &c in stripped {
        let s = format!("A{c}B");
        let out = norm(&s);
        assert_eq!(out, "AB", "U+{:04X} must be stripped entirely", c as u32);
        assert!(!out.contains(c));
    }
}

#[test]
fn property_clean_inputs_are_byte_identical_after_normalize() {
    // Inputs with no evasion at all must come back byte-for-byte identical.
    let clean = [
        "ghp_0123456789abcdefABCDEF",
        "no evasion here",
        "tabs\tand\nnewlines\r",
        "caf\u{00E9}_na\u{00EF}ve",
        "\u{0431}\u{0432}\u{0433}", // Cyrillic non-homoglyph letters
    ];
    for input in clean {
        assert_eq!(
            norm(input),
            input,
            "clean input must be unchanged: {input:?}"
        );
    }
}
