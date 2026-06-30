//! Homoglyph detection: finds secrets obfuscated with lookalike Unicode characters.
//!
//! Attackers may replace 'a' with Cyrillic 'а' to bypass simple regexes.
//! This module provides a way to match patterns against homoglyph-expanded forms.

use std::collections::HashMap;
use std::sync::OnceLock;

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
        // 'l' confuses with the I/1/| cluster (Cyrillic/Greek dotless i, fullwidth
        // l). The ASCII 'O'/'o' previously here were invalid: a homoglyph maps an
        // ASCII char to its NON-ASCII lookalikes, so ASCII glyphs add no obfuscation
        // coverage — they only made the ASCII-folded class `[l...Oo]→[lOo]` match a
        // literal 'O'/'o' in the 'l' position (pure false-positive surface +
        // automaton bloat). Removed; the load-bearing 'l' member is preserved.
        // (The non-ASCII O-lookalikes Ο/ο/о are also a wrong cluster for 'l' but
        // trimming them changes non-ASCII matching, so that is deferred to a
        // differential-bench-validated pass.)
        m.insert('l', vec!['і', 'І', 'ι', 'Ι', 'ｌ', 'Ο', 'ο', 'о']);
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
