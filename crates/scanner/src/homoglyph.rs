//! Homoglyph detection: finds secrets obfuscated with lookalike Unicode characters.
//!
//! Attackers may replace 'a' with Cyrillic 'а' to bypass simple regexes.
//! This module provides a way to match patterns against homoglyph-expanded forms.

use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, OnceLock};

/// Returns a map of ASCII characters to their common Unicode homoglyphs.
fn homoglyph_map() -> &'static HashMap<char, Vec<char>> {
    static MAP: OnceLock<HashMap<char, Vec<char>>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert('a', vec!['а', 'α', 'ａ']);
        m.insert('b', vec!['Ь', 'β', 'ｂ']);
        m.insert('c', vec!['с', 'ｃ']);
        m.insert('e', vec!['е', 'ε', 'ｅ']);
        m.insert('g', vec!['ɡ', 'ｇ']); // U+0261
        m.insert('h', vec!['н', 'һ', 'ｈ']); // U+04BB for h
        m.insert('i', vec!['і', 'ι', 'ｉ']);
        m.insert('j', vec!['ј', 'ｊ']);
        m.insert('k', vec!['к', 'κ', 'ｋ']);
        m.insert('m', vec!['м', 'ｍ']);
        m.insert('n', vec!['п', 'ν', 'ｎ']);
        m.insert('o', vec!['о', 'ο', 'ｏ']);
        m.insert('p', vec!['р', 'ρ', 'ｐ']);
        m.insert('s', vec!['ѕ', 'ｓ']);
        m.insert('t', vec!['т', 'τ', 'ｔ']);
        m.insert('u', vec!['υ', 'ｕ']);
        // 'l' confuses with the I/1/| cluster: Cyrillic/Greek dotless i and
        // fullwidth l. The Greek/Cyrillic o-lookalikes (Ο/ο/о) are an 'o' cluster,
        // not 'l', and only add a false-positive/automaton-bloat surface here.
        m.insert('l', vec!['і', 'І', 'ι', 'Ι', 'ｌ']);
        m.insert('x', vec!['х', 'χ', 'ｘ']);
        m.insert('y', vec!['у', 'ｙ']);
        m.insert('L', vec!['Ｌ']);

        m.insert('A', vec!['А', 'Α', 'Ａ']);
        m.insert('B', vec!['В', 'Β', 'Ｂ']);
        m.insert('E', vec!['Е', 'Ε', 'Ｅ']);
        m.insert('H', vec!['Н', 'Η', 'Ｈ']);
        m.insert('I', vec!['І', 'Ι', 'Ｉ']);
        m.insert('J', vec!['Ј', 'Ｊ']);
        m.insert('K', vec!['К', 'Κ', 'Ｋ']);
        m.insert('M', vec!['М', 'Ｍ']);
        m.insert('N', vec!['Ν', 'Ｎ']);
        m.insert('O', vec!['О', 'Ο', 'Ｏ']);
        m.insert('P', vec!['Р', 'Ρ', 'Ｐ']);
        m.insert('S', vec!['С', 'Ｓ']);
        m.insert('T', vec!['Т', 'Τ', 'Ｔ']);
        m.insert('X', vec!['Х', 'Χ', 'Ｘ']);
        m.insert('Y', vec!['Υ', 'Ｙ']);
        m
    })
}

/// The `(ascii, confusable-glyphs)` entries of [`homoglyph_map`], sorted by the
/// ASCII key for deterministic iteration. Exposed (via the `testing` facade) so a
/// cross-map consistency gate can assert this AC/regex-expand map agrees with the
/// `unicode_hardening` normalize-path folds (`cyrillic_to_latin`/`greek_to_latin`)
/// on every shared codepoint (the two are separate scan paths that must not drift).
pub(crate) fn homoglyph_confusables() -> Vec<(char, Vec<char>)> {
    let mut entries: Vec<(char, Vec<char>)> = homoglyph_map()
        .iter()
        .map(|(k, v)| (*k, v.clone()))
        .collect();
    entries.sort_by_key(|(k, _)| *k);
    entries
}

/// The set of FIRST UTF-8 bytes of every confusable glyph in
/// [`homoglyph_map`], as a 256-entry table.
///
/// Derived from the map rather than hand-listed, so adding a glyph cannot
/// leave the table behind. Every confusable is non-ASCII, so an ASCII-only
/// text sets none of these.
fn confusable_lead_bytes() -> &'static [bool; 256] {
    static LEADS: OnceLock<[bool; 256]> = OnceLock::new();
    LEADS.get_or_init(|| {
        let mut table = [false; 256];
        let mut buffer = [0_u8; 4];
        for glyphs in homoglyph_map().values() {
            for glyph in glyphs {
                let encoded = glyph.encode_utf8(&mut buffer).as_bytes();
                table[usize::from(encoded[0])] = true;
            }
        }
        table
    })
}

fn exact_confusable_glyphs() -> &'static HashSet<char> {
    static GLYPHS: LazyLock<HashSet<char>> =
        LazyLock::new(|| homoglyph_map().values().flatten().copied().collect());
    &GLYPHS
}

/// Whether `text` contains any confusable glyph.
///
/// The byte table is a cheap sound prefilter. A matching UTF-8 lead byte is not
/// sufficient by itself: unrelated characters such as the replacement glyph
/// `U+FFFD` share the fullwidth block's `0xEF` lead. Those false positives used
/// to compile and retain the complete Unicode residual matcher set for ordinary
/// invalid-UTF-8 input. Candidate texts therefore receive one exact character
/// membership pass against the same map that builds the matcher variants.
pub(crate) fn may_contain_confusable(text: &str) -> bool {
    let leads = confusable_lead_bytes();
    if !text.as_bytes().iter().any(|byte| leads[usize::from(*byte)]) {
        return false;
    }
    let confusables = exact_confusable_glyphs();
    text.chars()
        .any(|character| confusables.contains(&character))
}

/// Expand a regex pattern to include homoglyphs.
/// e.g. "ghp_" -> "[gɡｇ][hнһｈ][pрρｐ]_"
pub(crate) fn expand_homoglyphs(pattern: &str) -> String {
    let map = homoglyph_map();
    // Every mapped ASCII char becomes a `[<ascii><glyphs>]` class (~8 bytes);
    // reserve up front so expansion over all detector prefixes does not realloc
    // as it grows. Byte-identical to building from an empty String.
    let mut expanded = String::with_capacity(pattern.len() * 8);

    // Simple implementation: replace ASCII chars with character classes
    for ch in pattern.chars() {
        if let Some(glyphs) = map.get(&ch) {
            expanded.push('[');
            expanded.push(ch);
            for &g in glyphs {
                expanded.push(g);
            }
            expanded.push(']');
        } else {
            push_regex_literal_char(&mut expanded, ch);
        }
    }

    expanded
}

fn push_regex_literal_char(out: &mut String, ch: char) {
    if matches!(
        ch,
        '\\' | '.'
            | '+'
            | '*'
            | '?'
            | '('
            | ')'
            | '|'
            | '['
            | ']'
            | '{'
            | '}'
            | '^'
            | '$'
            | '#'
            | '&'
            | '-'
    ) {
        out.push('\\');
    }
    out.push(ch);
}
