//! Secret-safe provenance retained from candidate production through adjudication.

/// The scanner lane that produced a candidate.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CandidateChannel {
    /// A compiled detector regex, including regexes owned by generic detectors
    /// and generated routing variants. This is not proof of vendor attribution.
    NamedPattern,
    /// The generic credential-key assignment bridge.
    GenericAssignment,
    #[cfg(feature = "entropy")]
    /// Detector-owned entropy fallback discovery.
    Entropy,
    /// A caller-constructed match with no scanner producer.
    Unattributed,
}

/// Canonical position of a pattern in the active detector corpus.
///
/// The active detector digest binds detector ordering and pattern contents.
/// Generated homoglyph and backend routing variants retain this same identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PatternRef {
    pub(crate) detector_index: usize,
    pub(crate) pattern_index: u32,
}

/// Compact provenance carried from candidate production through adjudication.
///
/// The flat representation remains 16 bytes on 64-bit targets. Pattern
/// identity, producer channel, typed source role, and parser confidence occupy
/// the padding the original sidecar already paid for. This sidecar is retained
/// for every capped finding and pending ML row, so its layout is a scan-memory
/// contract rather than incidental structure padding.
/// All fields are private. Source and pack compilation reject the reserved
/// sentinel ordinals, so constructors preserve this invariant in release builds.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CandidateProvenance {
    detector_index: usize,
    pattern_index: u32,
    channel: CandidateChannel,
    source_role: keyhog_core::SemanticSourceRole,
    parser_confidence: crate::source_semantics::SemanticParserConfidence,
}

impl CandidateProvenance {
    const NO_DETECTOR: usize = usize::MAX;
    const NO_PATTERN: u32 = u32::MAX;

    pub(crate) const fn named(detector_index: usize, pattern_index: u32) -> Self {
        Self {
            detector_index,
            pattern_index,
            channel: CandidateChannel::NamedPattern,
            source_role: keyhog_core::SemanticSourceRole::Unknown,
            parser_confidence: crate::source_semantics::SemanticParserConfidence::Abstained,
        }
    }

    pub(crate) const fn with_source_semantics(
        mut self,
        evidence: crate::source_semantics::StructuredSourceEvidence,
    ) -> Self {
        self.source_role = evidence.role;
        self.parser_confidence = evidence.confidence;
        self
    }

    pub(crate) const fn generic_assignment() -> Self {
        Self::channel_only(CandidateChannel::GenericAssignment)
    }

    #[cfg(feature = "entropy")]
    pub(crate) const fn entropy() -> Self {
        Self::channel_only(CandidateChannel::Entropy)
    }

    pub(crate) const fn unattributed() -> Self {
        Self::channel_only(CandidateChannel::Unattributed)
    }

    const fn channel_only(channel: CandidateChannel) -> Self {
        Self {
            detector_index: Self::NO_DETECTOR,
            pattern_index: Self::NO_PATTERN,
            channel,
            source_role: keyhog_core::SemanticSourceRole::Unknown,
            parser_confidence: crate::source_semantics::SemanticParserConfidence::Abstained,
        }
    }

    pub(crate) const fn channel(self) -> CandidateChannel {
        self.channel
    }

    pub(crate) const fn source_role(self) -> keyhog_core::SemanticSourceRole {
        self.source_role
    }

    pub(crate) const fn parser_confidence(
        self,
    ) -> crate::source_semantics::SemanticParserConfidence {
        self.parser_confidence
    }

    pub(crate) const fn pattern(self) -> Option<PatternRef> {
        if matches!(self.channel, CandidateChannel::NamedPattern) {
            Some(PatternRef {
                detector_index: self.detector_index,
                pattern_index: self.pattern_index,
            })
        } else {
            None
        }
    }

    pub(crate) const fn is_well_formed(self) -> bool {
        let identity_is_valid = match self.channel {
            CandidateChannel::NamedPattern => {
                self.detector_index != Self::NO_DETECTOR && self.pattern_index != Self::NO_PATTERN
            }
            CandidateChannel::GenericAssignment | CandidateChannel::Unattributed => {
                self.detector_index == Self::NO_DETECTOR && self.pattern_index == Self::NO_PATTERN
            }
            #[cfg(feature = "entropy")]
            CandidateChannel::Entropy => {
                self.detector_index == Self::NO_DETECTOR && self.pattern_index == Self::NO_PATTERN
            }
        };
        let semantics_are_valid = match self.parser_confidence {
            crate::source_semantics::SemanticParserConfidence::Abstained => {
                matches!(self.source_role, keyhog_core::SemanticSourceRole::Unknown)
            }
            crate::source_semantics::SemanticParserConfidence::Parsed => {
                !matches!(self.source_role, keyhog_core::SemanticSourceRole::Unknown)
            }
        };
        identity_is_valid && semantics_are_valid
    }
}
