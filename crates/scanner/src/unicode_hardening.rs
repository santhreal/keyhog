//! Unicode hardening: detect and normalize Unicode evasion attacks.
//!
//! Attackers use Unicode tricks to evade detection:
//! - Homoglyphs (Cyrillic 'а' vs Latin 'a')
//! - Decomposed forms (NFD normalization)
//! - Zero-width characters (invisible joiners)
//! - Fullwidth characters (ｇｈｐ vs ghp)
//! - RTL overrides (can flip displayed text)
//!
//! This module detects these attacks and provides normalized forms for scanning.

use std::collections::BTreeSet;

#[cfg(test)]
use unicode_normalization::UnicodeNormalization;

/// Types of Unicode evasion attacks detected
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum EvasionKind {
    /// Cyrillic characters that look like Latin (homoglyphs)
    CyrillicHomoglyph,
    /// Greek characters that look like Latin
    GreekHomoglyph,
    /// Fullwidth ASCII variants (U+FF00-FFEF)
    Fullwidth,
    /// Zero-width characters (joiners, spaces)
    ZeroWidth,
    /// Right-to-left override characters
    RTLOverride,
    /// Decomposed forms (NFD vs NFC)
    Decomposed,
    /// Other suspicious Unicode usage
    Suspicious,
}

/// Detected Unicode evasion attempt
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct EvasionMatch {
    /// Byte position in original text
    pub position: usize,
    /// Type of evasion
    pub kind: EvasionKind,
    /// The suspicious character
    pub char: char,
    /// Suggested replacement (Latin equivalent if homoglyph)
    pub replacement: Option<char>,
}

/// Detect Unicode evasion attempts in text
#[cfg(test)]
pub(crate) fn detect_unicode_attacks(text: &str) -> Vec<EvasionMatch> {
    let mut matches = Vec::new();

    for (byte_pos, ch) in text.char_indices() {
        // Check for Cyrillic homoglyphs
        if let Some(latin) = cyrillic_to_latin(ch) {
            matches.push(EvasionMatch {
                position: byte_pos,
                kind: EvasionKind::CyrillicHomoglyph,
                char: ch,
                replacement: Some(latin),
            });
            continue;
        }

        // Check for Greek homoglyphs
        if let Some(latin) = greek_to_latin(ch) {
            matches.push(EvasionMatch {
                position: byte_pos,
                kind: EvasionKind::GreekHomoglyph,
                char: ch,
                replacement: Some(latin),
            });
            continue;
        }

        // Check for fullwidth characters
        if is_fullwidth(ch) {
            matches.push(EvasionMatch {
                position: byte_pos,
                kind: EvasionKind::Fullwidth,
                char: ch,
                replacement: Some(fullwidth_to_ascii(ch)),
            });
            continue;
        }

        // Check for zero-width characters
        if is_zero_width(ch) {
            matches.push(EvasionMatch {
                position: byte_pos,
                kind: EvasionKind::ZeroWidth,
                char: ch,
                replacement: None,
            });
            continue;
        }

        // Check for RTL overrides
        if is_rtl_override(ch) {
            matches.push(EvasionMatch {
                position: byte_pos,
                kind: EvasionKind::RTLOverride,
                char: ch,
                replacement: None,
            });
            continue;
        }

        // Check for combining marks (NFD/decomposed forms): e + U+0301 = é.
        // These are stripped on the normalization path (line ~154) and must be
        // reported here so detect_unicode_attacks matches its documented purpose.
        if is_combining_mark(ch) {
            matches.push(EvasionMatch {
                position: byte_pos,
                kind: EvasionKind::Decomposed,
                char: ch,
                replacement: None,
            });
            continue;
        }

        // Check for Unicode separators/spaces used to split a credential body
        // (no-break space, line/paragraph separators, ideographic space, …).
        if is_unicode_separator_evasion(ch) {
            matches.push(EvasionMatch {
                position: byte_pos,
                kind: EvasionKind::Suspicious,
                char: ch,
                replacement: None,
            });
            continue;
        }
    }

    matches
}

/// Normalize text, replacing homoglyphs with ASCII equivalents.
///
/// Fast path: pure-ASCII inputs (the vast majority of source code) are
/// returned `Cow::Borrowed` with no allocation. Only inputs containing actual
/// homoglyphs/zero-width/RTL characters take the slow per-char-rebuild path.
pub(crate) fn normalize_homoglyphs(text: &str) -> std::borrow::Cow<'_, str> {
    match ascii_normalization_scan(text.as_bytes()) {
        AsciiNormalizationScan::CleanAscii => return std::borrow::Cow::Borrowed(text),
        AsciiNormalizationScan::EvasiveAscii | AsciiNormalizationScan::NonAscii => {}
    }
    normalize_evasive_chars(text)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NormalizedChar {
    Keep,
    Replace(char),
    Drop,
}

fn normalized_char(ch: char) -> NormalizedChar {
    if let Some(latin) = cyrillic_to_latin(ch) {
        return NormalizedChar::Replace(latin);
    }
    if let Some(latin) = greek_to_latin(ch) {
        return NormalizedChar::Replace(latin);
    }
    if is_fullwidth(ch) {
        return NormalizedChar::Replace(fullwidth_to_ascii(ch));
    }
    if is_zero_width(ch)
        || is_rtl_override(ch)
        || is_unicode_separator_evasion(ch)
        || is_combining_mark(ch)
        || is_ascii_evasion_control(ch)
    {
        return NormalizedChar::Drop;
    }
    NormalizedChar::Keep
}

fn normalize_evasive_chars(text: &str) -> std::borrow::Cow<'_, str> {
    let mut normalized: Option<String> = None;
    for (byte_pos, ch) in text.char_indices() {
        match normalized_char(ch) {
            NormalizedChar::Keep => {
                if let Some(out) = &mut normalized {
                    out.push(ch);
                }
            }
            NormalizedChar::Replace(replacement) => {
                let out = normalized.get_or_insert_with(|| {
                    let mut out = String::with_capacity(text.len());
                    out.push_str(&text[..byte_pos]);
                    out
                });
                out.push(replacement);
            }
            NormalizedChar::Drop => {
                normalized.get_or_insert_with(|| {
                    let mut out = String::with_capacity(text.len());
                    out.push_str(&text[..byte_pos]);
                    out
                });
            }
        }
    }
    normalized
        .map(std::borrow::Cow::Owned)
        .unwrap_or(std::borrow::Cow::Borrowed(text))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AsciiNormalizationScan {
    CleanAscii,
    EvasiveAscii,
    NonAscii,
}

fn ascii_normalization_scan(bytes: &[u8]) -> AsciiNormalizationScan {
    for &byte in bytes {
        if byte >= 0x80 {
            return AsciiNormalizationScan::NonAscii;
        }
        if byte < 0x20 && !matches!(byte, b'\n' | b'\r' | b'\t') {
            return AsciiNormalizationScan::EvasiveAscii;
        }
    }
    AsciiNormalizationScan::CleanAscii
}

/// Full Unicode normalization (NFC + homoglyph replacement)
#[cfg(test)]
pub(crate) fn full_normalize(text: &str) -> String {
    let nfc: String = text.nfc().collect();
    normalize_homoglyphs(&nfc).into_owned()
}

#[derive(serde::Deserialize)]
struct EvasionAnchorFile {
    anchors: Vec<String>,
}

/// Structured-credential anchor prefixes (Tier-B, community-extensible via
/// `data/evasion-anchors.toml`). Loaded once. Malformed bundled data is a broken
/// build; do not continue with evasion normalization weakened.
static EVASION_ANCHORS: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
    match parse_evasion_anchors(include_str!("../data/evasion-anchors.toml")) {
        Ok(anchors) => anchors,
        Err(error) => {
            panic!(
                "crates/scanner/data/evasion-anchors.toml is invalid: {error}. \
                 Fix the bundled Tier-B evasion anchors; refusing to run without \
                 split-credential evasion normalization truth."
            )
        }
    }
});

pub(crate) fn parse_evasion_anchors(raw: &str) -> Result<Vec<String>, String> {
    let parsed: EvasionAnchorFile =
        toml::from_str(raw).map_err(|error| format!("invalid evasion-anchors.toml: {error}"))?;
    let mut seen = BTreeSet::new();
    let mut anchors = Vec::with_capacity(parsed.anchors.len());
    for raw_anchor in parsed.anchors {
        let anchor = raw_anchor.trim();
        if anchor.is_empty() {
            return Err("evasion anchor entries must not be empty".to_string());
        }
        if !seen.insert(anchor.to_string()) {
            return Err(format!("duplicate evasion anchor {anchor:?}"));
        }
        anchors.push(anchor.to_string());
    }
    if anchors.is_empty() {
        return Err("evasion anchors must contain at least one entry".to_string());
    }
    Ok(anchors)
}

/// Single Aho-Corasick automaton over all anchors — one O(n) pass to find every
/// prefix occurrence, instead of one search per anchor.
static EVASION_ANCHOR_AC: std::sync::LazyLock<Option<aho_corasick::AhoCorasick>> =
    std::sync::LazyLock::new(|| {
        let anchors = &*EVASION_ANCHORS;
        if anchors.is_empty() {
            return None;
        }
        match aho_corasick::AhoCorasick::new(anchors) {
            Ok(ac) => Some(ac),
            Err(error) => {
                crate::prefilter_degrade::warn_prefilter_disabled(
                    "evasion-anchor Aho-Corasick (EVASION_ANCHOR_AC)",
                    &error,
                );
                None
            }
        }
    });

#[inline]
fn is_credential_body_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'+' | b'/' | b'=' | b'.' | b'-')
}

#[inline]
fn is_anchor_start_blocked_by(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[inline]
fn is_interior_control(b: u8) -> bool {
    matches!(b, b'\t' | b'\r')
}

/// Strip attacker-inserted interior control bytes (`\t`, `\r`) that sit INSIDE a
/// credential body immediately following a known structured prefix
/// (`AKIA…`, `sk_live_…`, `ghp_…`). This is the middle path between two bad
/// extremes: a blanket strip of `\t`/`\r` would corrupt TSV columns,
/// indentation, and CRLF line ends (false positives + offset chaos), while
/// preserving them lets `AKIA<TAB>QYLP…` evade the `AKIA[0-9A-Z]{16}` regex.
/// By anchoring on a boundary-matched credential prefix, a control is removed
/// only where it provably interrupts a credential, never where it is structural.
///
/// Returns [`std::borrow::Cow::Borrowed`] unless an actual prefix-anchored
/// interior control is present, so the hot scan path stays zero-allocation.
pub(crate) fn strip_interior_evasion_controls(text: &str) -> std::borrow::Cow<'_, str> {
    let bytes = text.as_bytes();
    if bytes.len() < 3 {
        return std::borrow::Cow::Borrowed(text);
    }
    // Cheap gate: is there ANY `\t`/`\r` flanked by credential bytes? Indentation
    // (control preceded by `\n`/space) and CRLF (`\r` followed by `\n`) fail this,
    // so the overwhelming majority of inputs return here with no anchor scan.
    let has_candidate = memchr::memchr2_iter(b'\t', b'\r', &bytes[1..bytes.len() - 1]).any(|i| {
        let i = i + 1;
        is_credential_body_byte(bytes[i - 1]) && is_credential_body_byte(bytes[i + 1])
    });
    if !has_candidate {
        return std::borrow::Cow::Borrowed(text);
    }
    let Some(ac) = &*EVASION_ANCHOR_AC else {
        return std::borrow::Cow::Borrowed(text);
    };

    // Body window cap: bounds the per-anchor walk so a pathological input can't
    // turn the strip into an O(n^2) scan.
    const MAX_BODY_WINDOW: usize = 256;
    let mut drop_indices = Vec::new();
    for mat in ac.find_iter(text) {
        let start = mat.start();
        let end = mat.end();
        // Word boundary before the anchor: start-of-text or a non-identifier
        // byte. Stops mid-identifier false anchoring (e.g. `xAKIA…`) while
        // allowing ordinary assignments such as `key=AKIA...`.
        if start > 0 && is_anchor_start_blocked_by(bytes[start - 1]) {
            continue;
        }
        let window_end = end.saturating_add(MAX_BODY_WINDOW).min(bytes.len());
        let mut j = end;
        while j < window_end {
            let b = bytes[j];
            if is_credential_body_byte(b) {
                j += 1;
            } else if is_interior_control(b)
                && j + 1 < bytes.len()
                && is_credential_body_byte(bytes[j + 1])
            {
                // A control with a credential byte on both sides: interior to the
                // body, so it's evasion — drop it and keep walking.
                drop_indices.push(j);
                j += 1;
            } else {
                break;
            }
        }
    }
    if drop_indices.is_empty() {
        return std::borrow::Cow::Borrowed(text);
    }
    drop_indices.sort_unstable();
    drop_indices.dedup();
    // Rebuild dropping only the flagged ASCII control bytes. Removing standalone
    // ASCII bytes from valid UTF-8 yields valid UTF-8, so `from_utf8` succeeds;
    // the `unwrap_or` keeps us safe even if that invariant ever changes.
    let mut out = Vec::with_capacity(bytes.len() - drop_indices.len());
    let mut keep_start = 0;
    for drop_index in drop_indices {
        out.extend_from_slice(&bytes[keep_start..drop_index]);
        keep_start = drop_index + 1;
    }
    out.extend_from_slice(&bytes[keep_start..]);
    String::from_utf8(out)
        .map(std::borrow::Cow::Owned)
        .unwrap_or(std::borrow::Cow::Borrowed(text)) // LAW10: no transform / invalid codepoint => original text/char unchanged; recall-safe identity
}

/// Check if text contains potential evasion
pub(crate) fn contains_evasion(text: &str) -> bool {
    contains_ascii_evasion(text.as_bytes())
        || text.chars().any(|ch| {
            cyrillic_to_latin(ch).is_some()
                || greek_to_latin(ch).is_some()
                || is_fullwidth(ch)
                || is_zero_width(ch)
                || is_rtl_override(ch)
                || is_unicode_separator_evasion(ch)
                || is_combining_mark(ch)
                || is_ascii_evasion_control(ch)
        })
}

fn contains_ascii_evasion(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .any(|&b| b < 0x20 && !matches!(b, b'\n' | b'\r' | b'\t'))
}

fn is_ascii_evasion_control(ch: char) -> bool {
    ch.is_ascii_control() && !matches!(ch, '\n' | '\r' | '\t')
}

fn cyrillic_to_latin(ch: char) -> Option<char> {
    match ch {
        // Lowercase Cyrillic lookalikes
        'а' => Some('a'), // U+0430
        'е' => Some('e'), // U+0435
        'і' => Some('i'), // U+0456
        'ј' => Some('j'), // U+0458
        'о' => Some('o'), // U+043E
        'р' => Some('p'), // U+0440
        'с' => Some('c'), // U+0441
        'у' => Some('y'), // U+0443
        'х' => Some('x'), // U+0445
        'ѕ' => Some('s'), // U+0455
        'һ' => Some('h'), // U+04BB
        'ɡ' => Some('g'), // U+0261
        'ї' => Some('i'), // U+0457
        'к' => Some('k'), // U+043A (Cyrillic ka — visual 'k')
        'т' => Some('t'), // U+0442 (Cyrillic te — lowercase often rendered 't')
        // Uppercase
        'А' => Some('A'), // U+0410
        'В' => Some('B'), // U+0412
        'Е' => Some('E'), // U+0415
        'І' => Some('I'), // U+0406
        'Ј' => Some('J'), // U+0408
        'К' => Some('K'), // U+041A
        'М' => Some('M'), // U+041C
        'Н' => Some('H'), // U+041D
        'О' => Some('O'), // U+041E
        'Р' => Some('P'), // U+0420
        'С' => Some('C'), // U+0421
        'Ѕ' => Some('S'), // U+0405 (Cyrillic capital dze — visual 'S')
        'Т' => Some('T'), // U+0422
        'Х' => Some('X'), // U+0425
        'Ү' => Some('Y'), // U+04AE
        'Ї' => Some('I'), // U+0407
        _ => None,
    }
}

/// Greek characters that look like Latin
fn greek_to_latin(ch: char) -> Option<char> {
    match ch {
        'α' => Some('a'), // U+03B1
        'β' => Some('b'), // U+03B2 (can look like B)
        'ε' => Some('e'), // U+03B5
        'ι' => Some('i'), // U+03B9
        'κ' => Some('k'), // U+03BA
        'ν' => Some('v'), // U+03BD
        'ο' => Some('o'), // U+03BF
        'ρ' => Some('p'), // U+03C1
        'τ' => Some('t'), // U+03C4
        'υ' => Some('u'), // U+03C5 (sometimes looks like y)
        'χ' => Some('x'), // U+03C7
        'ω' => Some('w'), // U+03C9 (not really but sometimes used)
        'Α' => Some('A'), // U+0391
        'Β' => Some('B'), // U+0392
        'Ε' => Some('E'), // U+0395
        'Η' => Some('H'), // U+0397
        'Ι' => Some('I'), // U+0399
        'Κ' => Some('K'), // U+039A
        'Μ' => Some('M'), // U+039C
        'Ν' => Some('N'), // U+039D
        'Ο' => Some('O'), // U+039F
        'Ρ' => Some('P'), // U+03A1
        'Τ' => Some('T'), // U+03A4
        'Υ' => Some('Y'), // U+03A5
        'Χ' => Some('X'), // U+03A7
        'Ζ' => Some('Z'), // U+0396
        _ => None,
    }
}

/// Fullwidth ASCII variants (U+FF00-FFEF)
fn is_fullwidth(ch: char) -> bool {
    matches!(ch, '\u{FF00}'..='\u{FFEF}')
}

/// Convert fullwidth to ASCII
fn fullwidth_to_ascii(ch: char) -> char {
    if is_fullwidth(ch) {
        // Fullwidth forms are at U+FF00-U+FF5E for ASCII equivalents
        // The offset is 0xFEE0 (FF01 - 0021 = FE00, roughly)
        let code = ch as u32;
        if (0xFF01..=0xFF5E).contains(&code) {
            std::char::from_u32(code - 0xFEE0).unwrap_or(ch) // LAW10: no transform / invalid codepoint => original text/char unchanged; recall-safe identity
        } else {
            ch
        }
    } else {
        ch
    }
}

/// Check if a character is a Unicode evasion character (zero-width or RTL override)
pub(crate) fn is_evasion_char(ch: char) -> bool {
    is_zero_width(ch) || is_rtl_override(ch)
}

/// Zero-width characters
fn is_zero_width(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}' | // Zero Width Space
        '\u{200C}' | // Zero Width Non-Joiner
        '\u{200D}' | // Zero Width Joiner
        '\u{FEFF}' | // Zero Width No-Break Space (BOM)
        '\u{2060}' | // Word Joiner
        '\u{180E}' | // Mongolian Vowel Separator
        '\u{200E}' | // Left-to-Right Mark
        '\u{200F}' | // Right-to-Left Mark
        '\u{00AD}' | // Soft Hyphen
        '\u{2066}' | // Left-to-Right Isolate
        '\u{2067}' | // Right-to-Left Isolate
        '\u{2068}' | // First Strong Isolate
        '\u{2069}' // Pop Directional Isolate
    )
}

fn is_unicode_separator_evasion(ch: char) -> bool {
    matches!(
        ch,
        '\u{0085}' | // Next Line (NEL) — invisible line splitter
        '\u{00A0}' | // No-Break Space — invisible word splitter
        '\u{2000}'
            ..='\u{200A}' | // En/em/thin/hair and related spaces
        '\u{2028}' | // Line Separator
        '\u{2029}' | // Paragraph Separator
        '\u{202F}' | // Narrow No-Break Space
        '\u{205F}' | // Medium Mathematical Space
        '\u{3000}' // Ideographic Space
    )
}

fn is_combining_mark(ch: char) -> bool {
    matches!(ch, '\u{0300}'..='\u{036F}')
}

/// RTL override characters
fn is_rtl_override(ch: char) -> bool {
    matches!(
        ch,
        '\u{202E}' | // Right-to-Left Override
        '\u{202D}' | // Left-to-Right Override
        '\u{202A}' | // Left-to-Right Embedding
        '\u{202B}' | // Right-to-Left Embedding
        '\u{202C}' // Pop Directional Formatting
    )
}
