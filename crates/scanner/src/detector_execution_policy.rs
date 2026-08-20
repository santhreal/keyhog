//! Cache-local detector facts used by candidate execution and emission.
//!
//! Detector TOMLs remain authoritative. Scanner construction copies their hot
//! scalar facts and compacts public-identifier markers once so emitters never
//! traverse the flexible detector schema per candidate.

use keyhog_core::{DetectorSpec, Severity};

// Small detector vocabularies are cheaper as flat bytes than as one retained automaton each.
const LINEAR_KEYWORD_LIMIT: usize = 8;

#[derive(Debug)]
struct FlatKeywords {
    bytes: Box<[u8]>,
    ends: Box<[u32]>,
}

impl FlatKeywords {
    fn compile(detector_id: &str, keywords: &[String]) -> Result<Self, String> {
        let byte_count = keywords.iter().try_fold(0usize, |total, keyword| {
            total.checked_add(keyword.len()).ok_or_else(|| {
                format!("detector {detector_id:?} keyword bytes exceed addressable memory")
            })
        })?;
        if byte_count > u32::MAX as usize {
            return Err(format!(
                "detector {detector_id:?} keyword bytes exceed the compact u32 index"
            ));
        }

        let mut bytes = Vec::with_capacity(byte_count);
        let mut ends = Vec::with_capacity(keywords.len());
        for keyword in keywords {
            bytes.extend_from_slice(keyword.as_bytes());
            ends.push(bytes.len() as u32);
        }
        Ok(Self {
            bytes: bytes.into_boxed_slice(),
            ends: ends.into_boxed_slice(),
        })
    }

    #[inline]
    fn is_match(&self, haystack: &[u8]) -> bool {
        let mut start = 0usize;
        for &end in &self.ends {
            let end = end as usize;
            if memchr::memmem::find(haystack, &self.bytes[start..end]).is_some() {
                return true;
            }
            start = end;
        }
        false
    }
}

#[derive(Debug)]
enum CompiledDetectorKeywordMatcher {
    None,
    One(Box<[u8]>),
    Few(FlatKeywords),
    Many(aho_corasick::AhoCorasick),
}

impl CompiledDetectorKeywordMatcher {
    fn compile(detector: &DetectorSpec) -> Result<Self, String> {
        Self::compile_parts(detector.id.as_str(), &detector.keywords)
    }

    fn compile_parts(detector_id: &str, keywords: &[String]) -> Result<Self, String> {
        if let Some(empty_index) = keywords.iter().position(String::is_empty) {
            return Err(format!(
                "detector {detector_id:?} keyword {empty_index} is empty; remove it or declare a non-empty detector-owned context literal"
            ));
        }
        match keywords {
            [] => Ok(Self::None),
            [keyword] => Ok(Self::One(keyword.as_bytes().into())),
            keywords if keywords.len() <= LINEAR_KEYWORD_LIMIT => {
                FlatKeywords::compile(detector_id, keywords).map(Self::Few)
            }
            keywords => aho_corasick::AhoCorasickBuilder::new()
                .kind(Some(aho_corasick::AhoCorasickKind::ContiguousNFA))
                .build(keywords)
                .map(Self::Many)
                .map_err(|error| {
                    format!("detector {detector_id:?} keyword matcher could not compile: {error}")
                }),
        }
    }

    #[inline]
    fn is_match(&self, haystack: &[u8]) -> bool {
        match self {
            Self::None => false,
            Self::One(keyword) => memchr::memmem::find(haystack, keyword).is_some(),
            Self::Few(keywords) => keywords.is_match(haystack),
            Self::Many(matcher) => matcher.is_match(haystack),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CandidateLengthRejection {
    TooShort,
    TooLong,
}

/// Byte span of one complete generic assignment value, excluding its wrapper.
///
/// Generic detector regexes are intentionally cheap trigger/extraction
/// patterns. Some have a narrower capture than the detector-owned ceiling, and
/// an ASCII capture can also stop at Unicode or punctuation inside a quoted
/// value. This span is the authoritative whole-value view used before applying
/// length policy, so no producer can report such a prefix as a credential.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WholeAssignmentValue {
    pub(crate) start: usize,
    pub(crate) end: usize,
    /// End of the wrapper, used to skip regex captures nested inside its value.
    pub(crate) covered_end: usize,
}

impl WholeAssignmentValue {
    #[inline]
    pub(crate) fn as_str<'a>(self, data: &'a str) -> &'a str {
        data.get(self.start..self.end)
            .expect("whole assignment spans are canonical UTF-8 byte ranges")
    }

    #[inline]
    pub(crate) const fn is_exact(self, start: usize, end: usize) -> bool {
        self.start == start && self.end == end
    }
}

/// Resolve the whole logical value around a generic detector capture.
///
/// A capture inside a quote belongs to everything inside its matching unescaped
/// wrapper (or through line end when unterminated). Unquoted values extend
/// through non-delimiter bytes, including UTF-8 and encoded escape syntax. The
/// byte scan is allocation-free and deliberately returns byte offsets because
/// detector `min_len`/`max_len` are UTF-8 byte policies.
pub(crate) fn whole_assignment_value(
    data: &str,
    candidate_start: usize,
    candidate_end: usize,
) -> WholeAssignmentValue {
    let bytes = data.as_bytes();
    // Synthetic-source mappings are byte offsets and can point between UTF-8
    // bytes or beyond the original buffer; canonicalize once before byte scans.
    let candidate_start = crate::engine::floor_char_boundary(data, candidate_start);
    let candidate_end = crate::engine::ceil_char_boundary(data, candidate_end).max(candidate_start);
    let mut active_quote = None;
    let mut escaped = false;
    // Both pieces of state reset unconditionally at `\n` and `\r`, so the state
    // at `candidate_start` depends only on the bytes since the preceding line
    // break. Starting at byte 0 instead made this O(chunk length) per candidate
    // and therefore quadratic in candidates per chunk: on a real source tree it
    // was 19% of total scan time. Starting at the line makes it O(line length)
    // with a byte-identical result.
    let mut cursor = memchr::memrchr2(b'\n', b'\r', &bytes[..candidate_start])
        .map_or(0, |line_break| line_break + 1);
    while cursor < candidate_start {
        let byte = bytes[cursor];
        if matches!(byte, b'\n' | b'\r') {
            active_quote = None;
            escaped = false;
        } else if matches!(byte, b'"' | b'\'' | b'`') && !escaped {
            active_quote = match active_quote {
                Some((quote, _)) if quote == byte => None,
                None => Some((byte, cursor)),
                current => current,
            };
        }
        if byte == b'\\' {
            escaped = !escaped;
        } else {
            escaped = false;
        }
        cursor += 1;
    }

    if let Some((quote, opening)) = active_quote {
        // A decoded replacement is spliced into its source wrapper so scanners
        // retain surrounding evidence. That can produce text such as
        // `blob = "secret=VALUE"`: the outer quote belongs to `blob`, while the
        // candidate belongs to the nested `secret=` assignment. Expanding that
        // candidate back to the outer quote would report `secret=VALUE` instead
        // of the same `VALUE` span reported from direct plaintext.
        let nested_assignment = bytes[opening + 1..candidate_start]
            .iter()
            .any(|byte| matches!(byte, b'=' | b':'));
        if !nested_assignment {
            while cursor < bytes.len() {
                let byte = bytes[cursor];
                if matches!(byte, b'\n' | b'\r') {
                    break;
                }
                if byte == quote && !escaped {
                    return WholeAssignmentValue {
                        start: opening + 1,
                        end: cursor,
                        covered_end: cursor + 1,
                    };
                }
                if byte == b'\\' {
                    escaped = !escaped;
                } else {
                    escaped = false;
                }
                cursor += 1;
            }
            return WholeAssignmentValue {
                start: opening + 1,
                end: cursor,
                covered_end: cursor,
            };
        }
    }

    let mut end = candidate_end;
    while let Some(&byte) = bytes.get(end) {
        if byte.is_ascii_whitespace()
            || matches!(byte, b',' | b';' | b')' | b']' | b'}' | b'"' | b'\'' | b'`')
        {
            break;
        }
        end += 1;
    }
    WholeAssignmentValue {
        start: candidate_start,
        end,
        covered_end: end,
    }
}

/// Canonical detector-owned candidate length policy shared by every producer.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CompiledDetectorLengthPolicy {
    pub(crate) min_len: Option<usize>,
    pub(crate) max_len: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CompiledRequiredDetectorLengthPolicy {
    pub(crate) min_len: usize,
    pub(crate) max_len: usize,
}

impl CompiledDetectorLengthPolicy {
    pub(crate) const fn compile(detector: &DetectorSpec) -> Self {
        Self {
            min_len: detector.min_len,
            max_len: detector.max_len,
        }
    }

    #[inline]
    pub(crate) fn rejection(self, candidate_len: usize) -> Option<CandidateLengthRejection> {
        if self.min_len.is_some_and(|min_len| candidate_len < min_len) {
            Some(CandidateLengthRejection::TooShort)
        } else if self.max_len.is_some_and(|max_len| candidate_len > max_len) {
            Some(CandidateLengthRejection::TooLong)
        } else {
            None
        }
    }

    pub(crate) fn require_bounded(
        self,
        detector_id: &str,
    ) -> Result<CompiledRequiredDetectorLengthPolicy, String> {
        let min_len = self.min_len.ok_or_else(|| {
            format!(
                "detector {detector_id:?} owns entropy detection but omits min_len; declare the complete policy in its detector TOML"
            )
        })?;
        let max_len = self.max_len.ok_or_else(|| {
            format!(
                "detector {detector_id:?} owns entropy detection but omits max_len; declare the complete policy in its detector TOML"
            )
        })?;
        Ok(CompiledRequiredDetectorLengthPolicy { min_len, max_len })
    }
}

#[derive(Debug)]
pub(crate) struct CompiledDetectorExecutionPolicy {
    pub(crate) is_generic: bool,
    pub(crate) length: CompiledDetectorLengthPolicy,
    pub(crate) min_confidence: Option<f64>,
    pub(crate) severity: Severity,
    pub(crate) structural_password_slot: bool,
    keywords: CompiledDetectorKeywordMatcher,
    public_identifier_assignment_markers: Box<[Box<[u8]>]>,
}

impl CompiledDetectorExecutionPolicy {
    pub(crate) fn compile(detector: &DetectorSpec) -> Result<Self, String> {
        Ok(Self {
            // Service is reporting taxonomy, not execution semantics. Anchored
            // HTTP/SQL/URL detectors legitimately report service = "generic"
            // but must not inherit the phase-2 entropy/suppression contract.
            // A detector that owns entropy policy (phase-2 generic or explicit
            // priority) participates in the generic suppression/entropy contract.
            is_generic: detector.owns_entropy_policy(),
            length: CompiledDetectorLengthPolicy::compile(detector),
            min_confidence: detector.min_confidence,
            severity: detector.severity,
            structural_password_slot: detector.structural_password_slot,
            keywords: CompiledDetectorKeywordMatcher::compile(detector)?,
            public_identifier_assignment_markers: detector
                .public_identifier_assignment_markers
                .iter()
                .map(|marker| marker.as_bytes().into())
                .collect(),
        })
    }

    pub(crate) fn hydrate(
        detector_id: &str,
        is_generic: bool,
        min_len: Option<usize>,
        max_len: Option<usize>,
        min_confidence: Option<f64>,
        severity: Severity,
        structural_password_slot: bool,
        keywords: &[String],
        public_identifier_assignment_markers: &[String],
    ) -> Result<Self, String> {
        Ok(Self {
            is_generic,
            length: CompiledDetectorLengthPolicy { min_len, max_len },
            min_confidence,
            severity,
            structural_password_slot,
            keywords: CompiledDetectorKeywordMatcher::compile_parts(detector_id, keywords)?,
            public_identifier_assignment_markers: public_identifier_assignment_markers
                .iter()
                .map(|marker| marker.as_bytes().into())
                .collect(),
        })
    }

    /// True when the candidate's source line carries one of this detector's
    /// declared public-identifier assignment markers.
    #[inline]
    pub(crate) fn line_has_public_identifier_assignment(&self, line: &[u8]) -> bool {
        self.public_identifier_assignment_markers
            .iter()
            .any(|marker| crate::ascii_ci::ci_find_nonempty(line, marker.as_ref()))
    }

    /// Whether either candidate buffer contains one of this detector's exact
    /// TOML keywords. Keyword bytes are compiled once; the common passthrough
    /// path scans only `chunk_data`.
    #[inline]
    pub(crate) fn keyword_nearby(&self, chunk_data: &[u8], preprocessed: &[u8]) -> bool {
        let same_buffer = chunk_data.len() == preprocessed.len()
            && std::ptr::eq(chunk_data.as_ptr(), preprocessed.as_ptr());
        let text_differs = !same_buffer && preprocessed != chunk_data;
        self.keywords.is_match(chunk_data) || (text_differs && self.keywords.is_match(preprocessed))
    }
}
