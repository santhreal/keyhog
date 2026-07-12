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

use unicode_normalization::UnicodeNormalization;

/// Types of Unicode evasion attacks detected
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum EvasionKind {
    /// Cyrillic characters that look like Latin (homoglyphs)
    CyrillicHomoglyph,
    /// Greek characters that look like Latin
    GreekHomoglyph,
    /// Fullwidth ASCII variants (U+FF01-FF5E)
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

        // ASCII evasion controls (C0 U+0000–001F + DEL U+007F, minus the
        // structural whitespace \n/\r/\t). `normalize_homoglyphs` DROPS these
        // (via `is_ascii_evasion_control`), so the detector must report the SAME
        // chars — leaving them out is exactly the detect/normalize desync class
        // that hid the DEL recall hole. Grouped with separators under
        // `Suspicious`: both are non-printing characters that split a credential.
        if is_ascii_evasion_control(ch) {
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
pub(crate) enum NormalizedChar {
    Keep,
    Replace(char),
    Drop,
}

pub(crate) fn normalized_char(ch: char) -> NormalizedChar {
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
        .unwrap_or(std::borrow::Cow::Borrowed(text)) // LAW10: recall-preserving no-transform identity; whole-file scan text is unchanged.
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
        if is_ascii_evasion_control_byte(byte) {
            return AsciiNormalizationScan::EvasiveAscii;
        }
    }
    AsciiNormalizationScan::CleanAscii
}

/// True for an ASCII control byte an attacker can splice into a credential body
/// to break its byte sequence — every C0 control (U+0000–001F) **and DEL
/// (U+007F)**, EXCEPT the structural whitespace `\n`/`\r`/`\t`. Newlines, CR,
/// and tabs are legitimate layout (TSV columns, indentation, CRLF line ends);
/// dropping them would corrupt offsets and mangle ordinary text, so they are
/// never evasion.
///
/// This is the SINGLE source of truth for "ASCII evasion control": the fast-path
/// gate ([`ascii_normalization_scan`]), the [`contains_evasion`] detector, and
/// the per-char Drop classifier ([`is_ascii_evasion_control`]) all delegate here
/// so they cannot desync. DEL is a real hole when missed: `is_ascii_control()`
/// includes 0x7F, so a gate that only tested `b < 0x20` let `ghp_abc\x7Fdef…`
/// reach the scanner as `CleanAscii` (returned `Cow::Borrowed` unchanged), and
/// the spliced DEL broke the credential body regex — the secret evaded.
#[inline]
fn is_ascii_evasion_control_byte(b: u8) -> bool {
    (b < 0x20 || b == 0x7F) && !matches!(b, b'\n' | b'\r' | b'\t')
}

/// Full Unicode normalization (NFC + homoglyph replacement)
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
///
/// LAW 10 (fail closed): the anchor set is embedded Tier-B data
/// ([`EVASION_ANCHORS`], already validated non-empty at parse time), so this
/// automaton is compiled from a fixed, in-binary literal set. If
/// `AhoCorasick::new` cannot build it, that is a BUILD/data bug, not a runtime
/// condition to degrade around — silently returning `None` here would disable
/// split-credential evasion normalization for the whole process with no signal,
/// exactly the invisible recall loss Law 10 bans. We panic instead: a broken
/// build fails loud, a working build always has the automaton.
static EVASION_ANCHOR_AC: std::sync::LazyLock<aho_corasick::AhoCorasick> =
    std::sync::LazyLock::new(|| {
        let anchors = &*EVASION_ANCHORS;
        // `EVASION_ANCHORS` cannot be empty: `parse_evasion_anchors` errors (and
        // the `EVASION_ANCHORS` init panics) on an empty set. Assert it so the
        // invariant is checked at the point it is relied on.
        assert!(
            !anchors.is_empty(),
            "EVASION_ANCHORS is empty; parse_evasion_anchors must reject empty anchor sets"
        );
        aho_corasick::AhoCorasick::new(anchors).unwrap_or_else(|error| {
            panic!(
                "failed to build the evasion-anchor Aho-Corasick automaton from \
                 embedded Tier-B anchors: {error}. This is a build/data bug in \
                 crates/scanner/data/evasion-anchors.toml; refusing to run with \
                 split-credential evasion normalization silently disabled."
            )
        })
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
    // Fail-closed automaton (see `EVASION_ANCHOR_AC`): always present in a working
    // build, so there is no silent no-anchor fallback path here.
    let ac = &*EVASION_ANCHOR_AC;

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
    // A char is "evasive" exactly when `normalized_char` would not Keep it
    // (Replace covers the cyrillic/greek/fullwidth homoglyphs; Drop covers
    // zero-width/RTL/separator/combining/ascii-control). Delegating here keeps
    // `normalized_char` the single owner of that classification, so a new
    // evasion category added there can never silently desync this detector.
    contains_ascii_evasion(text.as_bytes())
        || text
            .chars()
            .any(|ch| !matches!(normalized_char(ch), NormalizedChar::Keep))
}

fn contains_ascii_evasion(bytes: &[u8]) -> bool {
    bytes.iter().any(|&b| is_ascii_evasion_control_byte(b))
}

fn is_ascii_evasion_control(ch: char) -> bool {
    ch.is_ascii() && is_ascii_evasion_control_byte(ch as u8)
}

pub(crate) fn cyrillic_to_latin(ch: char) -> Option<char> {
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
pub(crate) fn greek_to_latin(ch: char) -> Option<char> {
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

/// Fullwidth ASCII variants: U+FF01..=U+FF5E, the fullwidth forms of printable
/// ASCII `!`..`~` (each maps to its ASCII twin via `- 0xFEE0`, see
/// [`fullwidth_to_ascii`]).
///
/// The surrounding Halfwidth-and-Fullwidth-Forms block (U+FF00..=U+FFEF) also
/// holds halfwidth katakana (U+FF61–FF9F), halfwidth hangul, fullwidth white
/// brackets (U+FF5F–FF60), and CJK currency signs (U+FFE0–FFE6) — NONE of which
/// are ASCII variants. Matching the whole block falsely flagged legitimate CJK
/// text as "fullwidth evasion" and pushed it onto the slow normalization path
/// with a `Replace(self)` no-op rebuild allocation. Every fullwidth form of the
/// credential charset (A–Z, a–z, 0–9, `_ + / = . -`) lives in U+FF01–FF5E, so
/// narrowing to it preserves all credential normalization while keeping real
/// CJK text on the zero-allocation fast path.
pub(crate) fn is_fullwidth(ch: char) -> bool {
    matches!(ch, '\u{FF01}'..='\u{FF5E}')
}

/// Convert a fullwidth ASCII variant (U+FF01..=U+FF5E) to its ASCII twin;
/// any other char is returned unchanged.
pub(crate) fn fullwidth_to_ascii(ch: char) -> char {
    if is_fullwidth(ch) {
        // Each fullwidth form sits exactly 0xFEE0 above its ASCII twin
        // (U+FF01 '!' = 0x21 + 0xFEE0 … U+FF5E '~' = 0x7E + 0xFEE0). `is_fullwidth`
        // already bounds `code` to this range, so the subtraction is always a
        // valid scalar; `unwrap_or(ch)` keeps the identity on the impossible
        // failure rather than panicking (LAW10: recall-safe, never a silent drop).
        let code = ch as u32;
        std::char::from_u32(code - 0xFEE0).unwrap_or(ch)
    } else {
        ch
    }
}

/// Check if a character is a Unicode evasion character (zero-width or RTL override)
pub(crate) fn is_evasion_char(ch: char) -> bool {
    is_zero_width(ch) || is_rtl_override(ch)
}

/// Invisible / zero-advance format characters used to split a credential body.
///
/// This is a **curated** set of `General_Category=Cf` (plus soft hyphen)
/// codepoints that render to nothing, NOT a blanket `Cf` drop: some format
/// chars carry meaning and a visible/structural effect — the Arabic number
/// signs (U+0600–0605), Syriac abbreviation mark (U+070F), Kaithi number sign
/// (U+110BD), etc. — and dropping those would corrupt legitimate text. Only
/// codepoints that are genuinely invisible AND have no legitimate role inside a
/// credential token belong here. (Variation selectors and other combining marks
/// are `General_Category=Mark` and are handled by [`is_combining_mark`].)
///
/// The set is derived from the Unicode `Default_Ignorable_Code_Point` property
/// (DerivedCoreProperties) intersected with "renders to nothing AND has no
/// legitimate role inside a credential token", MINUS the codepoints already
/// owned by [`is_combining_mark`] (the `Mark`-category members: CGJ U+034F,
/// variation selectors U+FE00–FE0F / U+E0100–E01EF, Khmer inherent vowels
/// U+17B4–17B5) and [`is_rtl_override`] (bidi embeddings/overrides U+202A–202E).
/// A few `Mark`-category Mongolian selectors are ALSO listed explicitly below —
/// see the note there for why that intentional overlap is a robustness guard,
/// not a duplication bug.
pub(crate) fn is_zero_width(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}' | // Zero Width Space
        '\u{200C}' | // Zero Width Non-Joiner
        '\u{200D}' | // Zero Width Joiner
        '\u{FEFF}' | // Zero Width No-Break Space (BOM)
        '\u{2060}'..='\u{2064}' | // Word Joiner + invisible operators (function application/times/separator/plus)
        '\u{2065}' | // Reserved, Default_Ignorable (invisible; strip so an attacker can't splice it)
        '\u{180E}' | // Mongolian Vowel Separator (Cf)
        // Mongolian Free Variation Selectors 1–4. FVS1–3 (U+180B–180D) and FVS4
        // (U+180F) are General_Category=Mn, so `is_combining_mark` also catches
        // them WHEN the linked unicode-normalization tables are new enough (FVS4
        // was added in Unicode 14.0). Listing them here makes the invisible-strip
        // fail-safe against a crate lagging behind the Unicode version — an
        // intentional, behavior-identical overlap, not a drifting second source.
        '\u{180B}'..='\u{180D}' |
        '\u{180F}' |
        '\u{061C}' | // Arabic Letter Mark (Bidi_Control, invisible directional mark)
        '\u{200E}' | // Left-to-Right Mark
        '\u{200F}' | // Right-to-Left Mark
        '\u{00AD}' | // Soft Hyphen
        '\u{2066}' | // Left-to-Right Isolate
        '\u{2067}' | // Right-to-Left Isolate
        '\u{2068}' | // First Strong Isolate
        '\u{2069}' | // Pop Directional Isolate
        '\u{206A}'..='\u{206F}' | // Deprecated Cf: inhibit/activate symmetric swapping + Arabic form shaping + national/nominal digit shapes (invisible)
        // Invisible fillers with General_Category=Lo (letters) — NOT combining
        // marks and NOT Cf, so nothing else on the strip path catches them, yet
        // they render as blank/zero-advance and are a classic "looks empty"
        // splice vector.
        '\u{115F}' | // Hangul Choseong Filler
        '\u{1160}' | // Hangul Jungseong Filler
        '\u{3164}' | // Hangul Filler
        '\u{FFA0}' | // Halfwidth Hangul Filler
        '\u{1BCA0}'..='\u{1BCA3}' | // Shorthand Format Controls (Cf): letter/word overlap + up/down step (invisible)
        '\u{1D173}'..='\u{1D17A}' | // Musical symbol beam/tie/slur/phrase begin/end (Cf; invisible formatting)
        '\u{FFF0}'..='\u{FFF8}' | // Reserved, Default_Ignorable (invisible)
        '\u{FFF9}'..='\u{FFFB}' | // Interlinear annotation anchor/separator/terminator (invisible)
        '\u{E0000}'..='\u{E007F}' // Tags block (language tag + tag chars + cancel-tag); invisible
    )
}

fn is_unicode_separator_evasion(ch: char) -> bool {
    matches!(
        ch,
        '\u{0085}' | // Next Line (NEL) — invisible line splitter
        '\u{00A0}' | // No-Break Space — invisible word splitter
        '\u{1680}' | // Ogham Space Mark (Zs) — renders as blank in most fonts
        '\u{2000}'
            ..='\u{200A}' | // En/em/thin/hair and related spaces
        '\u{2028}' | // Line Separator
        '\u{2029}' | // Paragraph Separator
        '\u{202F}' | // Narrow No-Break Space
        '\u{205F}' | // Medium Mathematical Space
        '\u{3000}' // Ideographic Space
    )
}

/// True for any Unicode combining mark — the full `Grapheme_Extend` set
/// (general categories Mn/Mc/Me), not just the U+0300–U+036F Combining
/// Diacritical Marks block.
///
/// Restricting to one block was an evasion hole: a combining mark spliced
/// between credential bytes makes the underlying char sequence stop matching a
/// detector regex (`g\u{1DC0}hp_…` no longer matches `ghp_`), and NFC does not
/// rescue it (a mark with no precomposed base, e.g. U+1DC0, survives `nfc()`).
/// Any block other than U+0300–036F — Supplement (U+1AB0–1AFF), Extended
/// (U+1DC0–1DFF), for-Symbols (U+20D0–20FF), Half Marks (U+FE20–FE2F), or the
/// Cyrillic/Hebrew/Arabic marks — therefore slipped past the strip.
///
/// Delegating to `unicode-normalization` (already a dependency) keeps this in
/// lockstep with the Unicode tables with zero drift. ASCII is never a combining
/// mark, so the `is_ascii` guard skips the table lookup on the common byte
/// range — the per-char cost on the slow (non-ASCII) path stays a perfect-hash
/// lookup, a rounding error.
pub(crate) fn is_combining_mark(ch: char) -> bool {
    !ch.is_ascii() && unicode_normalization::char::is_combining_mark(ch)
}

/// RTL override characters
pub(crate) fn is_rtl_override(ch: char) -> bool {
    matches!(
        ch,
        '\u{202E}' | // Right-to-Left Override
        '\u{202D}' | // Left-to-Right Override
        '\u{202A}' | // Left-to-Right Embedding
        '\u{202B}' | // Right-to-Left Embedding
        '\u{202C}' // Pop Directional Formatting
    )
}
