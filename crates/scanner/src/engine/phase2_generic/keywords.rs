//! Keyword and strong-key classification helpers for the generic assignment bridge.

use std::sync::LazyLock;

/// Detector-corpus-specific line prefilter compiled once with the scanner.
/// Keeping this beside the generated assignment regex prevents custom or
/// reduced detector corpora from being filtered by the embedded corpus.
#[derive(Debug)]
pub(crate) struct GenericKeywordStemSet {
    stems: Box<[Box<str>]>,
    by_first_offsets: [u16; 257],
    by_first_data: Box<[u16]>,
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
        assert!(
            stems.len() <= u16::MAX as usize,
            "generic keyword stem count exceeds u16::MAX"
        );
        let mut counts = [0usize; 256];
        for stem in &stems {
            if let Some(&first) = stem.as_bytes().first() {
                let lower = first.to_ascii_lowercase();
                let upper = first.to_ascii_uppercase();
                counts[lower as usize] += 1;
                if upper != lower {
                    counts[upper as usize] += 1;
                }
            }
        }
        let mut by_first_offsets = [0u16; 257];
        let mut total = 0usize;
        for i in 0..256 {
            by_first_offsets[i] =
                u16::try_from(total).expect("generic keyword stem entry offset exceeds u16::MAX");
            total += counts[i];
        }
        by_first_offsets[256] =
            u16::try_from(total).expect("generic keyword stem entry total exceeds u16::MAX");

        let mut by_first_data = vec![0u16; total];
        let mut cursors = by_first_offsets;
        for (idx, stem) in stems.iter().enumerate() {
            let stem_idx = u16::try_from(idx).expect("generic keyword stem index exceeds u16::MAX");
            if let Some(&first) = stem.as_bytes().first() {
                let lower = first.to_ascii_lowercase();
                let upper = first.to_ascii_uppercase();
                let pos = cursors[lower as usize] as usize;
                by_first_data[pos] = stem_idx;
                cursors[lower as usize] += 1;
                if upper != lower {
                    let pos = cursors[upper as usize] as usize;
                    by_first_data[pos] = stem_idx;
                    cursors[upper as usize] += 1;
                }
            }
        }
        Self {
            stems: stems.into_boxed_slice(),
            by_first_offsets,
            by_first_data: by_first_data.into_boxed_slice(),
        }
    }

    #[inline]
    pub(crate) fn stems_for_byte(&self, byte: u8) -> &[u16] {
        let start = self.by_first_offsets[byte as usize] as usize;
        let end = self.by_first_offsets[byte as usize + 1] as usize;
        &self.by_first_data[start..end]
    }

    #[inline]
    pub(crate) fn has_first_byte(&self, byte: u8) -> bool {
        self.by_first_offsets[byte as usize] != self.by_first_offsets[byte as usize + 1]
    }

    pub(crate) fn literals(&self) -> impl ExactSizeIterator<Item = &str> {
        self.stems.iter().map(AsRef::as_ref)
    }

    #[inline]
    pub(crate) fn is_match(&self, bytes: &[u8]) -> bool {
        for (index, &byte) in bytes.iter().enumerate() {
            if self.has_first_byte(byte) && generic_stem_matches_at(bytes, index, self) {
                return true;
            }
        }
        false
    }

    #[inline]
    pub(crate) fn has_assignment_delimiter_after_stem(&self, line: &[u8]) -> bool {
        assignment_stem_before_delimiter(self, line).is_some()
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

    pub(crate) fn hydrate_from<T: crate::assignment_keywords::DetectorPlanAssignmentSource>(
        detectors: &[T],
    ) -> Result<Self, String> {
        let keywords = crate::assignment_keywords::derive_assignment_keywords_from_plan(detectors)?;
        let vendor_suffixes =
            crate::assignment_keywords::derive_generic_suffixes_from_plan(detectors, false)?;
        let tail_suffixes =
            crate::assignment_keywords::derive_generic_suffixes_from_plan(detectors, true)?;
        let max_len = detectors
            .iter()
            .filter(|detector| detector.owns_entropy_policy())
            .map(|detector| {
                detector.max_len().ok_or_else(|| {
                    format!(
                        "generic entropy owner {:?} omits max_len; declare it in the detector TOML",
                        detector.id()
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .ok_or_else(|| {
                "assignment keywords require at least one generic entropy owner".to_string()
            })?;
        let alternation = super::generic_keyword_alternation_from(&keywords, &vendor_suffixes);
        let matcher = super::compile_generic_re_with_policy(&alternation, max_len, &tail_suffixes)
            .map_err(|error| {
                format!("cannot compile hydrated generic assignment bridge: {error}")
            })?;
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

/// Collect zero-based line indexes whose text contains a generic assignment
/// prefilter stem followed by an assignment delimiter.
///
/// The regex cannot match without `=` or `:` after its keyword. Enforcing that
/// necessary condition here keeps broad stems such as `pass` out of the heavier
/// extraction path when they occur only in ordinary text.
pub(crate) fn collect_generic_keyword_lines_with(
    stem_set: &GenericKeywordStemSet,
    text: &str,
    out: &mut Vec<u32>,
) {
    let mut line_idx = 0u32;
    for line in text.as_bytes().split(|byte| *byte == b'\n') {
        if assignment_stem_before_delimiter(stem_set, line).is_some() {
            out.push(line_idx);
        }
        let Some(next_line) = line_idx.checked_add(1) else {
            return;
        };
        line_idx = next_line;
    }
}

/// Collect one trusted generic-assignment stem byte position per matching line.
///
/// Autoroute classifies byte-distinct payload representatives before CPU
/// dispatch. Persisting these positions lets every exact duplicate reuse that
/// scan; the generic bridge maps them back to line ids and still performs its
/// ordinary regex extraction and path-sensitive adjudication per chunk.
pub(crate) fn collect_generic_keyword_positions_with(
    stem_set: &GenericKeywordStemSet,
    text: &str,
    out: &mut Vec<u32>,
) {
    let mut line_start = 0usize;
    for line in text.as_bytes().split(|byte| *byte == b'\n') {
        if let Some(relative) = assignment_stem_before_delimiter(stem_set, line) {
            let Ok(position) = u32::try_from(line_start + relative) else {
                return;
            };
            out.push(position);
        }
        let Some(next_start) = line_start.checked_add(line.len().saturating_add(1)) else {
            return;
        };
        line_start = next_start;
    }
}
/// Collect zero-based line indexes from trusted generic-stem match positions.
///
/// The GPU region path supplies these positions only when its literal haystack
/// is byte-identical to the preprocessed text, so this helper performs mapping
/// and deduplication only.
pub(crate) fn collect_generic_keyword_lines_from_positions(
    line_index: &crate::context::LineContextIndex,
    positions: &[u32],
    out: &mut Vec<u32>,
) {
    out.clear();
    if line_index.is_empty() {
        return;
    }
    for &pos in positions {
        let line_idx = line_index.line_index_for_offset(pos as usize);
        let Ok(line_id) = u32::try_from(line_idx) else {
            return;
        };
        out.push(line_id);
    }
    out.sort_unstable();
    out.dedup();
}

#[inline]
fn assignment_stem_before_delimiter(
    stem_set: &GenericKeywordStemSet,
    line: &[u8],
) -> Option<usize> {
    let last_delimiter = memchr::memrchr2(b'=', b':', line)?;
    for (index, &byte) in line[..=last_delimiter].iter().enumerate() {
        if stem_set.has_first_byte(byte) && generic_stem_matches_at(line, index, stem_set) {
            return Some(index);
        }
    }
    None
}

#[inline]
fn generic_stem_matches_at(bytes: &[u8], start: usize, stem_set: &GenericKeywordStemSet) -> bool {
    for &stem_idx in stem_set.stems_for_byte(bytes[start]) {
        let stem = stem_set.stems[stem_idx as usize].as_bytes();
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
    strong_anchor && crate::decode_structure::decodes_to_printable_text_with_strong_anchor(value)
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

// The keyword cases live in `tests/unit/phase2_generic_keywords_cases.rs`,
// kept in-crate by the `#[path]` include because they pin private keyword
// tables rather than any public surface.
#[cfg(test)]
#[path = "../../../tests/unit/phase2_generic_keywords_cases.rs"]
mod position_line_mapping_tests;

// The table suite lives in `tests/unit/phase2_generic_keyword_tables.rs`,
// kept in-crate by the `#[path]` include for the same reason.
#[cfg(test)]
#[path = "../../../tests/unit/phase2_generic_keyword_tables.rs"]
mod strong_anchor_tests;
const MAX_IDLE_KEYWORD_LINE_BUFFERS: usize = 4;
static KEYWORD_LINES_POOL: parking_lot::Mutex<Vec<Vec<u32>>> = parking_lot::Mutex::new(Vec::new());

fn normalize_keyword_lines_scratch(lines: &mut Vec<u32>) {
    lines.clear();
    if lines.capacity().saturating_mul(std::mem::size_of::<u32>())
        > crate::engine::MAX_RETAINED_WORKER_SCRATCH_BYTES
    {
        *lines = Vec::new();
    }
}

pub(crate) fn take_keyword_lines_scratch() -> Vec<u32> {
    // LAW10: no idle buffer means a fresh empty scratch vector with identical matching behavior.
    KEYWORD_LINES_POOL.lock().pop().unwrap_or_default()
}

pub(crate) fn release_keyword_lines_scratch(mut lines: Vec<u32>) {
    normalize_keyword_lines_scratch(&mut lines);
    if lines.capacity() == 0 {
        return;
    }
    let mut pool = KEYWORD_LINES_POOL.lock();
    if pool.len() < MAX_IDLE_KEYWORD_LINE_BUFFERS {
        pool.push(lines);
    }
}

#[cfg(test)]
pub(crate) fn retained_keyword_line_bytes_after_for_test(requested_bytes: usize) -> usize {
    let elements = requested_bytes.div_ceil(std::mem::size_of::<u32>());
    let mut lines = Vec::with_capacity(elements);
    normalize_keyword_lines_scratch(&mut lines);
    lines.capacity().saturating_mul(std::mem::size_of::<u32>())
}
