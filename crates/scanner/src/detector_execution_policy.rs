//! Cache-local detector facts used by candidate execution and emission.
//!
//! Detector TOMLs remain authoritative. Scanner construction copies their hot
//! scalar facts and compacts public-identifier markers once so emitters never
//! traverse the flexible detector schema per candidate.

use keyhog_core::{DetectorSpec, Severity};

#[derive(Debug)]
enum CompiledDetectorKeywordMatcher {
    None,
    One(Box<[u8]>),
    Multiple(aho_corasick::AhoCorasick),
}

impl CompiledDetectorKeywordMatcher {
    fn compile(detector: &DetectorSpec) -> Result<Self, String> {
        if let Some(empty_index) = detector.keywords.iter().position(String::is_empty) {
            return Err(format!(
                "detector {:?} keyword {empty_index} is empty; remove it or declare a non-empty detector-owned context literal",
                detector.id
            ));
        }
        match detector.keywords.as_slice() {
            [] => Ok(Self::None),
            [keyword] => Ok(Self::One(keyword.as_bytes().into())),
            keywords => aho_corasick::AhoCorasickBuilder::new()
                // A compact NFA avoids hundreds of per-detector dense tables while replacing K full-buffer scans.
                .kind(Some(aho_corasick::AhoCorasickKind::ContiguousNFA))
                .build(keywords)
                .map(Self::Multiple)
                .map_err(|error| {
                    format!(
                        "detector {:?} keyword matcher could not compile: {error}",
                        detector.id
                    )
                }),
        }
    }

    #[inline]
    fn is_match(&self, haystack: &[u8]) -> bool {
        match self {
            Self::None => false,
            Self::One(keyword) => memchr::memmem::find(haystack, keyword).is_some(),
            Self::Multiple(matcher) => matcher.is_match(haystack),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CandidateLengthRejection {
    TooShort,
    TooLong,
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
    #[cfg(any(feature = "entropy", test))]
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
            #[cfg(any(feature = "entropy", test))]
            public_identifier_assignment_markers: detector
                .public_identifier_assignment_markers
                .iter()
                .map(|marker| marker.as_bytes().into())
                .collect(),
        })
    }

    /// True when the candidate's source line carries one of this detector's
    /// declared public-identifier assignment markers.
    #[inline]
    #[cfg(any(feature = "entropy", test))]
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
