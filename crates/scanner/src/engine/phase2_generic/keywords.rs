//! Keyword and strong-key classification helpers for the generic assignment bridge.

use std::sync::LazyLock;

/// Detector-corpus-specific line prefilter compiled once with the scanner.
/// Keeping this beside the generated assignment regex prevents custom or
/// reduced detector corpora from being filtered by the embedded corpus.
#[derive(Debug)]
pub(crate) struct GenericKeywordStemSet {
    stems: Vec<Box<str>>,
    by_first: [Vec<usize>; 256],
    has_first: [bool; 256],
}

impl GenericKeywordStemSet {
    pub(crate) fn compile<'a>(keywords: impl IntoIterator<Item = &'a str>) -> Self {
        let mut stems = Vec::<Box<str>>::new();
        for keyword in keywords {
            let stem = generic_keyword_prefilter_stem(keyword);
            if !stems.iter().any(|existing| existing.as_ref() == stem) {
                stems.push(stem.into());
            }
        }
        let mut by_first: [Vec<usize>; 256] = std::array::from_fn(|_| Vec::new());
        let mut has_first = [false; 256];
        for (idx, stem) in stems.iter().enumerate() {
            if let Some(&first) = stem.as_bytes().first() {
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
        Self {
            stems,
            by_first,
            has_first,
        }
    }

    pub(crate) fn literals(&self) -> impl ExactSizeIterator<Item = &str> {
        self.stems.iter().map(AsRef::as_ref)
    }

    #[inline]
    pub(crate) fn is_match(&self, bytes: &[u8]) -> bool {
        for (index, &byte) in bytes.iter().enumerate() {
            if self.has_first[byte as usize] && generic_stem_matches_at(bytes, index, self) {
                return true;
            }
        }
        false
    }
}

/// Canonical detector-corpus inputs for generic assignment extraction and its
/// CPU/GPU line prefilters. Compiling these together prevents a custom detector
/// keyword from reaching the regex while remaining absent from VYRE evidence.
#[derive(Debug)]
pub(crate) struct GenericAssignmentKeywordPlan {
    matcher: regex::Regex,
    stems: GenericKeywordStemSet,
}

impl GenericAssignmentKeywordPlan {
    pub(crate) fn compile(detectors: &[keyhog_core::DetectorSpec]) -> Result<Self, String> {
        let keywords = crate::assignment_keywords::derive_assignment_keywords(detectors)?;
        let vendor_suffixes =
            crate::assignment_keywords::derive_generic_vendor_suffixes(detectors)?;
        let tail_suffixes =
            crate::assignment_keywords::derive_generic_assignment_tail_suffixes(detectors)?;
        let mut max_len = None;
        for detector in detectors
            .iter()
            .filter(|detector| detector.owns_entropy_policy())
        {
            let detector_max_len = detector.max_len.ok_or_else(|| {
                format!(
                    "generic entropy owner {:?} omits max_len; declare it in the detector TOML",
                    detector.id
                )
            })?;
            max_len = Some(max_len.map_or(detector_max_len, |current: usize| {
                current.max(detector_max_len)
            }));
        }
        let max_len = max_len.ok_or_else(|| {
            "assignment keywords require at least one generic entropy owner".to_string()
        })?;
        let alternation = super::generic_keyword_alternation_from(&keywords, &vendor_suffixes);
        let matcher =
            super::compile_generic_re_with_policy(&alternation, max_len, &tail_suffixes).map_err(
                |error| {
                    format!(
                        "cannot compile the detector-owned generic assignment bridge: {error}. Fix the phase-2 generic detector keywords, suffixes, and max_len values"
                    )
                },
            )?;
        let stems = GenericKeywordStemSet::compile(
            keywords
                .iter()
                .map(String::as_str)
                .chain(vendor_suffixes.iter().map(String::as_str)),
        );
        Ok(Self { matcher, stems })
    }

    pub(crate) fn matcher(&self) -> &regex::Regex {
        &self.matcher
    }

    pub(crate) fn stems(&self) -> &GenericKeywordStemSet {
        &self.stems
    }

    pub(crate) fn stem_literals(&self) -> impl ExactSizeIterator<Item = &str> {
        self.stems.literals()
    }
}

/// Collect zero-based line indexes whose text contains any generic assignment
/// prefilter stem.
///
/// This is the hot-path replacement for a whole-chunk Aho-Corasick prefilter
/// over eight compact stems. It walks the bytes once, maps newlines as it goes,
/// and stops scanning a line after its first stem hit because the generic bridge
/// only needs to decide which lines should run the heavier assignment regex.
pub(crate) fn collect_generic_keyword_lines_with(
    stem_set: &GenericKeywordStemSet,
    text: &str,
    out: &mut Vec<usize>,
) {
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
        // `partition_point` returns `0..=len`; `saturating_sub(1)` maps it into
        // `0..=len-1` (the early return guarantees `len >= 1`), so every result
        // is an in-range line index.
        let line_idx = line_offsets
            .partition_point(|&line_start| line_start <= pos)
            .saturating_sub(1);
        out.push(line_idx);
    }
    out.sort_unstable();
    out.dedup();
}

#[inline]
fn generic_stem_matches_at(bytes: &[u8], start: usize, stem_set: &GenericKeywordStemSet) -> bool {
    for &stem_idx in &stem_set.by_first[bytes[start] as usize] {
        let stem = stem_set.stems[stem_idx].as_bytes();
        let end = start + stem.len();
        if end <= bytes.len() && bytes[start..end].eq_ignore_ascii_case(stem) {
            return true;
        }
    }
    false
}

pub(crate) fn generic_keyword_prefilter_stem(keyword: &str) -> &str {
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
        } else if is_assignment_compact_separator(byte) && !normalized.is_empty() && !last_was_sep {
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
    matches!(normalized.rsplit('_').next(), Some("passwd" | "pwd"))
        || normalized.ends_with("key")
        || normalized.ends_with("secret")
        || normalized.ends_with("token")
        || normalized.ends_with("password")
}

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
        || encoded_text_secret_anchors().iter().any(|anchor| {
            compact_keyword_eq(
                &normalized,
                anchor.as_bytes(),
                is_normalized_compact_separator,
            )
        });
    strong_anchor && crate::decode_structure::decodes_to_printable_text(value)
}

/// The encoded-printable-text credential anchor vocabulary, loaded from Tier-B
/// `rules/encoded-text-secret-anchors.toml` (compact lowercase, no separators).
/// ONE home for the list. Fails CLOSED (panic) on invalid embedded data.
pub(crate) fn encoded_text_secret_anchors() -> &'static [String] {
    &ENCODED_TEXT_SECRET_ANCHORS
}

static ENCODED_TEXT_SECRET_ANCHORS: LazyLock<Vec<String>> = LazyLock::new(|| {
    match parse_encoded_text_secret_anchors(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/rules/encoded-text-secret-anchors.toml"
    ))) {
        Ok(anchors) => anchors,
        Err(error) => panic!(
            "rules/encoded-text-secret-anchors.toml is invalid: {error}. Fix the bundled Tier-B \
             encoded-text secret-anchor vocabulary; refusing to run without the encoded-text \
             classifier truth."
        ),
    }
});

/// Shared section shape for the compact-anchor Tier-B files.
#[derive(serde::Deserialize)]
struct AnchorSection {
    anchors: Vec<String>,
}

#[derive(serde::Deserialize)]
struct EncodedTextSecretAnchorFile {
    encoded_text_secret_anchors: AnchorSection,
}

/// Parse + validate the encoded-text secret anchors from raw TOML. Compact
/// lowercase tokens only (no separators), matching the normalized keyword form.
pub(crate) fn parse_encoded_text_secret_anchors(raw: &str) -> Result<Vec<String>, String> {
    let parsed: EncodedTextSecretAnchorFile = toml::from_str(raw)
        .map_err(|error| format!("invalid encoded-text-secret-anchors.toml: {error}"))?;
    crate::tier_b_list::parse_token_list(
        parsed.encoded_text_secret_anchors.anchors,
        &crate::tier_b_list::ListPolicy {
            what: "encoded-text secret anchor",
            require_lowercase: true,
            separators: b"",
        },
    )
}

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

#[cfg(test)]
mod position_line_mapping_tests {
    use super::collect_generic_keyword_lines_from_positions;

    #[test]
    fn maps_positions_to_line_indexes_sorted_deduped() {
        // Three lines starting at byte 0, 10, 25.
        let line_offsets = [0usize, 10, 25];
        let positions = [0u32, 5, 10, 24, 25, 30];
        let mut out = Vec::new();
        collect_generic_keyword_lines_from_positions(&line_offsets, &positions, &mut out);
        assert_eq!(out, vec![0, 1, 2]);
    }

    #[test]
    fn positions_within_one_line_dedup_to_that_line() {
        let line_offsets = [0usize, 10, 25];
        let positions = [10u32, 12, 20, 24];
        let mut out = Vec::new();
        collect_generic_keyword_lines_from_positions(&line_offsets, &positions, &mut out);
        assert_eq!(out, vec![1]);
    }

    #[test]
    fn empty_line_offsets_yields_empty() {
        let mut out = vec![7, 8, 9];
        collect_generic_keyword_lines_from_positions(&[], &[3u32], &mut out);
        assert!(out.is_empty());
    }
}

#[cfg(test)]
mod strong_anchor_tests {
    use super::{
        encoded_text_secret_anchors, is_strong_keyword_anchored_encoded_text_secret,
        parse_encoded_text_secret_anchors,
    };

    // base64 of "ThisIsAPlaintextSecretValueForTests" (decodes to printable ASCII).
    const PRINTABLE_B64: &str = "VGhpc0lzQVBsYWludGV4dFNlY3JldFZhbHVlRm9yVGVzdHM=";

    #[test]
    fn encoded_text_secret_anchor_vocab_is_the_expected_list() {
        assert_eq!(
            encoded_text_secret_anchors(),
            &[
                "password",
                "passwd",
                "pwd",
                "passphrase",
                "token",
                "secret",
                "credential",
            ]
        );
    }

    // ── is_strong_keyword_anchored_encoded_text_secret ─────────────────────

    #[test]
    fn list_only_anchor_lifts_encoded_printable_text() {
        // `credential` earns the lift ONLY via the migrated Tier-B anchor list (it
        // has no `key`/`secret`/`token` suffix), so this exercises the list path.
        assert!(is_strong_keyword_anchored_encoded_text_secret(
            "credential",
            PRINTABLE_B64
        ));
        // `password` (a list anchor AND a suffix) also lifts.
        assert!(is_strong_keyword_anchored_encoded_text_secret(
            "passphrase",
            PRINTABLE_B64
        ));
    }

    #[test]
    fn non_anchor_keyword_does_not_lift_encoded_text() {
        // Adversarial twin: same decodable value, but the key is not a credential
        // anchor (no lift).
        assert!(!is_strong_keyword_anchored_encoded_text_secret(
            "hostname",
            PRINTABLE_B64
        ));
    }

    #[test]
    fn dotted_or_short_values_short_circuit_before_decode() {
        // A `.` in the value (JWT-like segmenting) and a sub-24-char value both bail
        // before the decode check, regardless of anchor.
        assert!(!is_strong_keyword_anchored_encoded_text_secret(
            "password",
            "aGVsbG8.d29ybGQ="
        ));
        assert!(!is_strong_keyword_anchored_encoded_text_secret(
            "password", "c2hvcnQ="
        ));
    }

    #[test]
    fn encoded_text_secret_anchor_parser_round_trips_and_validates() {
        let out = parse_encoded_text_secret_anchors(
            "[encoded_text_secret_anchors]\nanchors = [\"token\", \"secret\"]\n",
        )
        .unwrap();
        assert_eq!(out, vec!["token", "secret"]);
        assert!(parse_encoded_text_secret_anchors(
            "[encoded_text_secret_anchors]\nanchors = [\"Token\"]\n"
        )
        .unwrap_err()
        .contains("lowercase"));
    }
}
