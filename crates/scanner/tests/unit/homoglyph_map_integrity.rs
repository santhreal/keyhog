//! Structural integrity contract for the homoglyph map (`homoglyph.rs`).
//!
//! The homoglyph mechanism maps an ASCII character to its **non-ASCII** Unicode
//! lookalikes (the module's own example: replace `a` with Cyrillic `а`) so a
//! secret obfuscated with confusables still matches. An ASCII glyph in the map is
//! definitionally invalid: it cannot be Unicode obfuscation, and it only widens
//! the ASCII-folded class (`[l…]→[lOo]`) to over-match a literal ASCII char in
//! that position — pure false-positive surface and automaton bloat, and on the
//! anchor path it manufactures junk candidate starts (`sk_live_` → also
//! `sk_Oive_`). This suite pins the invariant that every glyph is non-ASCII, plus
//! the surrounding well-formedness, exercised THROUGH the public
//! `expand_homoglyphs` (no need to widen `homoglyph_map`'s visibility).
//!
//! Regression: the `'l'` entry previously carried ASCII `'O'`/`'o'`; tests 11–12
//! lock their removal.

use keyhog_scanner::homoglyph::expand_homoglyphs;

/// The character-class members `expand_homoglyphs` emits for a single char, or
/// `None` when the char is unmapped (emitted as a literal, not a `[…]` class).
fn class_members(c: char) -> Option<Vec<char>> {
    let s = expand_homoglyphs(&c.to_string());
    let inner = s.strip_prefix('[')?.strip_suffix(']')?;
    Some(inner.chars().collect())
}

/// Every ASCII letter, the domain over which the map is defined.
fn ascii_letters() -> impl Iterator<Item = char> {
    ('a'..='z').chain('A'..='Z')
}

/// The mapped letters (those expand wraps in a class).
fn mapped_letters() -> Vec<char> {
    ascii_letters().filter(|&c| class_members(c).is_some()).collect()
}

// ---------------------------------------------------------------------------
// expand_homoglyphs surface behaviour.
// ---------------------------------------------------------------------------

#[test]
fn expand_lowercase_a_class_is_exact() {
    assert_eq!(class_members('a'), Some(vec!['a', 'а', 'α', 'ａ']));
}

#[test]
fn expand_lowercase_s_class_is_exact() {
    assert_eq!(class_members('s'), Some(vec!['s', 'ѕ', 'ｓ']));
}

#[test]
fn expand_unmapped_letter_is_literal() {
    // 'd' has no listed homoglyphs → emitted verbatim, not a class.
    assert_eq!(expand_homoglyphs("d"), "d");
    assert_eq!(class_members('d'), None);
}

#[test]
fn expand_digit_is_literal() {
    assert_eq!(expand_homoglyphs("1"), "1");
}

#[test]
fn expand_underscore_is_literal() {
    assert_eq!(expand_homoglyphs("_"), "_");
}

#[test]
fn expand_ghp_matches_doc_example() {
    // The doc comment on `expand_homoglyphs` pins this exact expansion.
    assert_eq!(expand_homoglyphs("ghp_"), "[gɡｇ][hнһｈ][pрρｐ]_");
}

#[test]
fn expand_empty_is_empty() {
    assert_eq!(expand_homoglyphs(""), "");
}

#[test]
fn expand_multichar_concatenates_classes() {
    let ab = expand_homoglyphs("ab");
    let a = expand_homoglyphs("a");
    let b = expand_homoglyphs("b");
    assert_eq!(ab, format!("{a}{b}"));
}

#[test]
fn expand_escapes_regex_metachar_dot() {
    // The dot between two mapped letters must be escaped so it stays a literal.
    let out = expand_homoglyphs("a.b");
    assert!(out.contains("\\."), "dot must be escaped: {out}");
}

#[test]
fn expand_is_deterministic() {
    assert_eq!(expand_homoglyphs("password"), expand_homoglyphs("password"));
}

// ---------------------------------------------------------------------------
// The 'l' regression — ASCII 'O'/'o' must be gone, I/l-lookalikes retained.
// ---------------------------------------------------------------------------

#[test]
fn l_class_excludes_ascii_capital_o() {
    let m = class_members('l').expect("'l' is mapped");
    assert!(!m.contains(&'O'), "'l' must not map to ASCII 'O': {m:?}");
}

#[test]
fn l_class_excludes_ascii_small_o() {
    let m = class_members('l').expect("'l' is mapped");
    assert!(!m.contains(&'o'), "'l' must not map to ASCII 'o': {m:?}");
}

#[test]
fn l_class_retains_il_lookalikes() {
    let m = class_members('l').expect("'l' is mapped");
    // The load-bearing I/l confusables must survive the ASCII-glyph removal.
    assert!(m.contains(&'і'), "Cyrillic dotless i lookalike kept: {m:?}");
    assert!(m.contains(&'ｌ'), "fullwidth l lookalike kept: {m:?}");
}

#[test]
fn l_folded_form_is_single_ascii_member() {
    // With the ASCII glyphs gone, the only ASCII member of `[l…]` is 'l', so its
    // ASCII fold is `[l]` — no longer the over-broad `[lOo]`.
    let ascii_members: Vec<char> = class_members('l')
        .expect("'l' is mapped")
        .into_iter()
        .filter(char::is_ascii)
        .collect();
    assert_eq!(ascii_members, vec!['l']);
}

// ---------------------------------------------------------------------------
// Map-wide structural invariants (the integrity guard).
// ---------------------------------------------------------------------------

#[test]
fn every_glyph_is_non_ascii() {
    // THE core invariant: a homoglyph is a non-ASCII lookalike. The key is the
    // only ASCII char permitted in its own class.
    for c in mapped_letters() {
        let members = class_members(c).unwrap();
        for &g in &members[1..] {
            assert!(
                !g.is_ascii(),
                "homoglyph map['{c}'] has ASCII glyph '{g}' (U+{:04X}); glyphs must be non-ASCII",
                g as u32
            );
        }
    }
}

#[test]
fn every_class_starts_with_its_key() {
    for c in mapped_letters() {
        let members = class_members(c).unwrap();
        assert_eq!(members[0], c, "map['{c}'] class must start with its key");
    }
}

#[test]
fn key_appears_exactly_once_per_class() {
    for c in mapped_letters() {
        let members = class_members(c).unwrap();
        let count = members.iter().filter(|&&m| m == c).count();
        assert_eq!(count, 1, "key '{c}' must appear once in its class, found {count}");
    }
}

#[test]
fn no_duplicate_members_in_any_class() {
    for c in mapped_letters() {
        let members = class_members(c).unwrap();
        let mut seen = std::collections::HashSet::new();
        for &m in &members {
            assert!(seen.insert(m), "map['{c}'] has duplicate member '{m}'");
        }
    }
}

#[test]
fn every_class_has_at_least_one_glyph() {
    for c in mapped_letters() {
        let members = class_members(c).unwrap();
        assert!(members.len() >= 2, "map['{c}'] must have key + >=1 glyph, got {members:?}");
    }
}

#[test]
fn map_covers_a_reasonable_letter_set() {
    // Guards against an accidental wipe of the map (it would silently disable
    // homoglyph matching). The shipped map covers most ASCII letters.
    let n = mapped_letters().len();
    assert!(n >= 30, "expected >=30 mapped letters, got {n}");
}

#[test]
fn a_maps_to_known_confusables() {
    let m = class_members('a').unwrap();
    assert!(m.contains(&'а'), "Cyrillic a (U+0430)"); // U+0430
    assert!(m.contains(&'α'), "Greek alpha");
    assert!(m.contains(&'ａ'), "fullwidth a");
}

#[test]
fn no_class_contains_a_different_ascii_letter() {
    // Stronger framing of the core invariant: no class may pull in a *different*
    // ASCII letter (the 'l'→'O'/'o' bug class), which would cross-match letters.
    for c in mapped_letters() {
        let members = class_members(c).unwrap();
        for &g in &members {
            if g != c {
                assert!(
                    !g.is_ascii_alphabetic(),
                    "map['{c}'] cross-maps to ASCII letter '{g}'"
                );
            }
        }
    }
}
