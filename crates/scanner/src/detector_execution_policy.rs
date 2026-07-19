//! Cache-local detector facts used by candidate execution and emission.
//!
//! Detector TOMLs remain authoritative. Scanner construction copies their hot
//! scalar facts and compacts public-identifier markers once so emitters never
//! traverse the flexible detector schema per candidate.

use keyhog_core::{DetectorSpec, Severity};

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
    keywords: Box<[Box<[u8]>]>,
    #[cfg(any(feature = "entropy", test))]
    public_identifier_assignment_markers: Box<[Box<[u8]>]>,
}

impl CompiledDetectorExecutionPolicy {
    pub(crate) fn compile(detector: &DetectorSpec) -> Self {
        Self {
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
            keywords: detector
                .keywords
                .iter()
                .map(|keyword| keyword.as_bytes().into())
                .collect(),
            #[cfg(any(feature = "entropy", test))]
            public_identifier_assignment_markers: detector
                .public_identifier_assignment_markers
                .iter()
                .map(|marker| marker.as_bytes().into())
                .collect(),
        }
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
        self.keywords.iter().any(|keyword| {
            memchr::memmem::find(chunk_data, keyword).is_some()
                || (text_differs && memchr::memmem::find(preprocessed, keyword).is_some())
        })
    }
}
