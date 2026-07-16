//! Cache-local detector facts used by candidate execution and emission.
//!
//! Detector TOMLs remain authoritative. Scanner construction copies their hot
//! scalar facts and compacts public-identifier markers once so emitters never
//! traverse the flexible detector schema per candidate.

use keyhog_core::{DetectorSpec, Severity};

#[derive(Debug)]
pub(crate) struct CompiledDetectorExecutionPolicy {
    pub(crate) is_generic: bool,
    pub(crate) min_len: Option<usize>,
    pub(crate) min_confidence: Option<f64>,
    pub(crate) severity: Severity,
    pub(crate) structural_password_slot: bool,
    keywords: Box<[Box<[u8]>]>,
    public_identifier_assignment_markers: Box<[Box<[u8]>]>,
}

impl CompiledDetectorExecutionPolicy {
    fn compile(detector: &DetectorSpec) -> Self {
        Self {
            is_generic: detector.service == "generic",
            min_len: detector.min_len,
            min_confidence: detector.min_confidence,
            severity: detector.severity,
            structural_password_slot: detector.structural_password_slot,
            keywords: detector
                .keywords
                .iter()
                .map(|keyword| keyword.as_bytes().into())
                .collect(),
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

#[derive(Debug)]
pub(crate) struct CompiledDetectorExecutionPolicies {
    by_detector_index: Box<[CompiledDetectorExecutionPolicy]>,
}

impl CompiledDetectorExecutionPolicies {
    pub(crate) fn compile(detectors: &[DetectorSpec]) -> Self {
        Self {
            by_detector_index: detectors
                .iter()
                .map(CompiledDetectorExecutionPolicy::compile)
                .collect(),
        }
    }

    #[inline]
    pub(crate) fn get(&self, detector_index: usize) -> &CompiledDetectorExecutionPolicy {
        &self.by_detector_index[detector_index]
    }
}
