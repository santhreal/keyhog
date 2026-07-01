//! Keyword and strong-key classification helpers for the generic assignment bridge.

use std::sync::LazyLock;

struct GenericKeywordStemSet {
    stems: Vec<&'static [u8]>,
    by_first: [Vec<usize>; 256],
    has_first: [bool; 256],
}

static GENERIC_KEYWORD_STEMS: LazyLock<GenericKeywordStemSet> = LazyLock::new(|| {
    let stems: Vec<&'static [u8]> = generic_keyword_prefilter_stems()
        .into_iter()
        .map(str::as_bytes)
        .collect();
    let mut by_first: [Vec<usize>; 256] = std::array::from_fn(|_| Vec::new());
    let mut has_first = [false; 256];
    for (idx, stem) in stems.iter().enumerate() {
        if let Some(&first) = stem.first() {
            let lower = first.to_ascii_lowercase();
            let upper = first.to_ascii_uppercase();
            by_first[lower as usize].push(idx);
            has_first[lower as usize] = true;
            if upper != lower {
                by_first[upper as usize].push(idx);
                has_first[upper as usize] = true;
            }
        }
    }
    GenericKeywordStemSet {
        stems,
        by_first,
        has_first,
    }
});

/// Compact keyword spellings into the minimal safe prefilter stems used by the
/// generic assignment bridge.
///
/// The extraction regex still decides whether a line has a valid assignment
/// keyword. This prefilter only decides which lines are worth sending to that
/// regex, so each returned stem must be a recall-preserving substring of one or
/// more regex arms. Unknown added keywords keep their exact spelling, which
/// prevents a keyword-list expansion from becoming invisible to the prefilter.
pub(crate) fn generic_keyword_prefilter_stems() -> Vec<&'static str> {
    let mut stems = Vec::new();
    for keyword in crate::assignment_keywords::assignment_keywords()
        .iter()
        .map(String::as_str)
        // Local vendor-prefixed `<name>_key=` support needs a bare `key`
        // prefilter stem; do not widen the shared no-hit admission gate.
        .chain(std::iter::once("key"))
    {
        let stem = generic_keyword_prefilter_stem(keyword);
        if !stems.contains(&stem) {
            stems.push(stem);
        }
    }
    stems
}

/// Collect zero-based line indexes whose text contains any generic assignment
/// prefilter stem.
///
/// This is the hot-path replacement for a whole-chunk Aho-Corasick prefilter
/// over eight compact stems. It walks the bytes once, maps newlines as it goes,
/// and stops scanning a line after its first stem hit because the generic bridge
/// only needs to decide which lines should run the heavier assignment regex.
pub(crate) fn collect_generic_keyword_lines(text: &str, out: &mut Vec<usize>) {
    let stem_set = &*GENERIC_KEYWORD_STEMS;
    let bytes = text.as_bytes();
    let mut idx = 0usize;
    let mut line_idx = 0usize;
    while idx < bytes.len() {
        if bytes[idx] == b'\n' {
            line_idx += 1;
            idx += 1;
            continue;
        }
        if stem_set.has_first[bytes[idx] as usize] && generic_stem_matches_at(bytes, idx, stem_set)
        {
            out.push(line_idx);
            match memchr::memchr(b'\n', &bytes[idx..]) {
                Some(rel) => {
                    idx += rel + 1;
                    line_idx += 1;
                }
                None => break,
            }
            continue;
        }
        idx += 1;
    }
}

/// Collect zero-based line indexes from trusted generic-stem match positions.
///
/// The GPU region path supplies these positions only when its literal haystack
/// is byte-identical to the preprocessed text, so this helper performs mapping
/// and deduplication only. Text scanning stays in [`collect_generic_keyword_lines`].
pub(crate) fn collect_generic_keyword_lines_from_positions(
    line_offsets: &[usize],
    positions: &[u32],
    out: &mut Vec<usize>,
) {
    out.clear();
    if line_offsets.is_empty() {
        return;
    }
    for &pos in positions {
        let pos = pos as usize;
        let line_idx = line_offsets
            .partition_point(|&line_start| line_start <= pos)
            .saturating_sub(1);
        if line_idx < line_offsets.len() {
            out.push(line_idx);
        }
    }
    out.sort_unstable();
    out.dedup();
}

#[inline]
fn generic_stem_matches_at(bytes: &[u8], start: usize, stem_set: &GenericKeywordStemSet) -> bool {
    for &stem_idx in &stem_set.by_first[bytes[start] as usize] {
        let stem = stem_set.stems[stem_idx];
        let end = start + stem.len();
        if end <= bytes.len() && bytes[start..end].eq_ignore_ascii_case(stem) {
            return true;
        }
    }
    false
}

pub(crate) fn generic_keyword_prefilter_stem(keyword: &'static str) -> &'static str {
    if keyword.contains("secret") {
        "secret"
    } else if keyword.contains("pass") {
        "pass"
    } else if keyword.contains("pwd") {
        "pwd"
    } else if keyword.contains("token") {
        "token"
    } else if keyword.contains("webhook") {
        "webhook"
    } else if keyword.contains("key") {
        "key"
    } else if keyword.contains("auth") {
        "auth"
    } else if keyword.contains("credential") {
        "credential"
    } else {
        keyword
    }
}

/// Normalize assignment-key spellings used by detector TOML keywords and by the
/// generic bridge's captured LHS (`SEGMENT_WRITE_KEY`, `segment-write-key`,
/// `segment.write.key`) into one comparable token.
pub(crate) fn normalize_assignment_keyword(keyword: &str) -> Option<String> {
    let mut normalized = String::with_capacity(keyword.len());
    let mut last_was_sep = false;
    for byte in keyword.bytes() {
        if byte.is_ascii_alphanumeric() {
            normalized.push(byte.to_ascii_lowercase() as char);
            last_was_sep = false;
        } else if matches!(byte, b'_' | b'-' | b'.') && !normalized.is_empty() && !last_was_sep {
            normalized.push('_');
            last_was_sep = true;
        }
    }
    if normalized.ends_with('_') {
        normalized.pop();
    }
    (!normalized.is_empty()).then_some(normalized)
}

/// True for assignment-key names whose suffix claims a credential slot, not a
/// bare service marker like `segment`.
pub(crate) fn normalized_assignment_keyword_has_secret_suffix(normalized: &str) -> bool {
    matches!(
        normalized.rsplit('_').next(),
        Some("key" | "secret" | "token" | "password" | "passwd" | "pwd")
    ) || normalized.ends_with("key")
        || normalized.ends_with("secret")
        || normalized.ends_with("token")
        || normalized.ends_with("password")
}

/// True iff the bridge captured a complete 32/48-byte hex key under a strong
/// cryptographic keyword. Other placeholder and hash-shape gates still run.
pub(crate) fn is_strong_keyword_anchored_hex_key(keyword: &str, value: &str) -> bool {
    if !matches!(value.len(), 32 | 48) {
        return false;
    }
    if !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    // Canonicalize the captured keyword: case-fold and drop `_`/`-`/`.` so
    // `API_KEY`, `api-key`, `encryption_key`, `clientSecret` all normalize to a
    // single token, then match the STRONG cryptographic-key family ONLY.
    // Deliberately EXCLUDES the weaker / more ambiguous bridge anchors
    // (`token`, `pass*`, `auth*`, `credential`, `license_key`, `passphrase`),
    // whose hex captures are not as cleanly real on CredData.
    if STRONG_HEX_KEY_COMPACT_EXACT
        .iter()
        .any(|exact| compact_keyword_eq(keyword, exact, is_assignment_compact_separator))
    {
        return true;
    }
    // Vendor-prefixed `*_key` / `*_secret` anchors are strong except known weak
    // product/license names.
    if compact_keyword_eq(keyword, b"licensekey", is_assignment_compact_separator) {
        return false;
    }
    compact_keyword_ends_with(keyword, b"key", is_assignment_compact_separator)
        || compact_keyword_ends_with(keyword, b"secret", is_assignment_compact_separator)
}

const STRONG_HEX_KEY_COMPACT_EXACT: &[&[u8]] = &[
    b"secret",
    b"apikey",
    b"privatekey",
    b"encryptionkey",
    b"signingkey",
    b"accesskey",
    b"clientsecret",
    b"appsecret",
    b"masterkey",
];

/// True for a generic assignment where the key is a strong credential anchor
/// and the value is an encoded printable text secret rather than a binary/base64
/// data envelope. This lets `password: <base64("SuperSecret...")>` reach the
/// scorer while keeping random protobuf/base64 blobs suppressed.
pub(crate) fn is_strong_keyword_anchored_encoded_text_secret(keyword: &str, value: &str) -> bool {
    if value.contains('.') || value.len() < 24 {
        return false;
    }
    let Some(normalized) = normalize_assignment_keyword(keyword) else {
        return false;
    };
    let strong_anchor = normalized_assignment_keyword_has_secret_suffix(&normalized)
        || ENCODED_TEXT_SECRET_ANCHORS
            .iter()
            .any(|anchor| compact_keyword_eq(&normalized, anchor, is_normalized_compact_separator));
    strong_anchor && crate::decode_structure::decodes_to_printable_text(value)
}

const ENCODED_TEXT_SECRET_ANCHORS: &[&[u8]] = &[
    b"password",
    b"passwd",
    b"pwd",
    b"passphrase",
    b"token",
    b"secret",
    b"credential",
];

pub(crate) fn is_assignment_compact_separator(byte: u8) -> bool {
    matches!(byte, b'_' | b'-' | b'.')
}

fn is_normalized_compact_separator(byte: u8) -> bool {
    byte == b'_'
}

pub(crate) fn compact_keyword_eq(
    keyword: &str,
    needle: &[u8],
    is_separator: fn(u8) -> bool,
) -> bool {
    let mut bytes = keyword
        .bytes()
        .filter(|byte| !is_separator(*byte))
        .map(|byte| byte.to_ascii_lowercase());
    for &expected in needle {
        if bytes.next() != Some(expected) {
            return false;
        }
    }
    bytes.next().is_none()
}

pub(crate) fn compact_keyword_ends_with(
    keyword: &str,
    suffix: &[u8],
    is_separator: fn(u8) -> bool,
) -> bool {
    let mut suffix_index = suffix.len();
    for byte in keyword
        .bytes()
        .rev()
        .filter(|byte| !is_separator(*byte))
        .map(|byte| byte.to_ascii_lowercase())
    {
        if suffix_index == 0 {
            return true;
        }
        suffix_index -= 1;
        if byte != suffix[suffix_index] {
            return false;
        }
    }
    suffix_index == 0
}
