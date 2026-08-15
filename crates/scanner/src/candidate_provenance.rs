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
    evidence_reason: keyhog_core::EvidenceReasonCode,
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
            evidence_reason: keyhog_core::EvidenceReasonCode::UnsupportedContext,
        }
    }

    pub(crate) fn with_named_evidence(
        mut self,
        semantic: &keyhog_core::DetectorSemanticPolicySpec,
        generic_detector: bool,
        checksum_valid: bool,
        has_companions: bool,
    ) -> Self {
        use keyhog_core::{AnchorSemanticRole, EvidenceReasonCode, RequiredSemanticEvidence};

        let mut strongest_proof = checksum_valid.then_some(EvidenceReasonCode::ChecksumValid);
        let mut missing_required = false;
        for requirement in &semantic.required_evidence {
            match requirement {
                RequiredSemanticEvidence::Checksum => {
                    if checksum_valid {
                        strongest_proof = Some(EvidenceReasonCode::ChecksumValid);
                    } else {
                        missing_required = true;
                    }
                }
                RequiredSemanticEvidence::RequiredCompanion
                | RequiredSemanticEvidence::PrivateKeyCompanion => {
                    if has_companions {
                        strongest_proof = Some(
                            strongest_proof
                                .unwrap_or(EvidenceReasonCode::RequiredCompanion)
                                .max(EvidenceReasonCode::RequiredCompanion),
                        );
                    } else {
                        missing_required = true;
                    }
                }
                RequiredSemanticEvidence::StructuralGrammar => {
                    strongest_proof = Some(
                        strongest_proof
                            .unwrap_or(EvidenceReasonCode::StructuralGrammar)
                            .max(EvidenceReasonCode::StructuralGrammar),
                    );
                }
                RequiredSemanticEvidence::LiveVerification => missing_required = true,
            }
        }
        self.evidence_reason = if missing_required {
            EvidenceReasonCode::RequiredEvidenceMissing
        } else if let Some(reason) = strongest_proof {
            reason
        } else if matches!(
            semantic.anchor_role,
            AnchorSemanticRole::WeakContext | AnchorSemanticRole::Unanchored
        ) {
            EvidenceReasonCode::WeakAnchor
        } else if generic_detector {
            EvidenceReasonCode::GenericDetector
        } else {
            EvidenceReasonCode::UnsupportedContext
        };
        self
    }

    pub(crate) const fn with_checksum_proof(mut self, checksum_valid: bool) -> Self {
        if checksum_valid {
            self.evidence_reason = keyhog_core::EvidenceReasonCode::ChecksumValid;
        }
        self
    }

    pub(crate) fn with_source_semantics(
        mut self,
        evidence: crate::source_semantics::SourceSemanticEvidence,
        semantic: Option<&keyhog_core::DetectorSemanticPolicySpec>,
    ) -> Self {
        use keyhog_core::{EvidenceReasonCode, EvidenceTier, SemanticSourceRole};

        self.source_role = evidence.role;
        self.parser_confidence = evidence.confidence;
        if matches!(self.evidence_reason.tier(), EvidenceTier::Confirmed) {
            return self;
        }

        let ambiguous_reason = match evidence.role {
            SemanticSourceRole::TestFixture => Some(EvidenceReasonCode::TestFixture),
            SemanticSourceRole::ProseDocumentation => Some(EvidenceReasonCode::Documentation),
            SemanticSourceRole::RegexRuleDefinition => Some(EvidenceReasonCode::RuleDefinition),
            SemanticSourceRole::IdentifierTypeMemberName => Some(EvidenceReasonCode::Identifier),
            SemanticSourceRole::CommandOptionDeclaration => {
                Some(EvidenceReasonCode::OptionDeclaration)
            }
            SemanticSourceRole::GeneratedVendorMaterial => {
                Some(EvidenceReasonCode::GeneratedMaterial)
            }
            SemanticSourceRole::Unknown => Some(EvidenceReasonCode::UnsupportedContext),
            SemanticSourceRole::StructuredAssignmentValue
            | SemanticSourceRole::EnvironmentAssignmentValue
            | SemanticSourceRole::StringLiteral
            | SemanticSourceRole::CommandArgumentValue
            | SemanticSourceRole::HeaderValue
            | SemanticSourceRole::UrlAuthorityUserinfo
            | SemanticSourceRole::ConnectionString
            | SemanticSourceRole::StandaloneToken
            | SemanticSourceRole::PemBlock => None,
        };
        if let Some(reason) = ambiguous_reason {
            self.evidence_reason = reason;
            return self;
        }

        if matches!(self.evidence_reason, EvidenceReasonCode::UnsupportedContext) {
            self.evidence_reason = if semantic.is_some_and(|policy| {
                !policy.allowed_source_roles.is_empty()
                    && !policy.allowed_source_roles.contains(&evidence.role)
            }) {
                EvidenceReasonCode::SourceRoleMismatch
            } else {
                EvidenceReasonCode::VendorPattern
            };
        }
        self
    }

    pub(crate) const fn generic_assignment() -> Self {
        Self::channel_only(
            CandidateChannel::GenericAssignment,
            keyhog_core::EvidenceReasonCode::GenericAssignment,
        )
    }

    #[cfg(feature = "entropy")]
    pub(crate) const fn entropy() -> Self {
        Self::channel_only(
            CandidateChannel::Entropy,
            keyhog_core::EvidenceReasonCode::EntropyOnly,
        )
    }

    pub(crate) const fn unattributed() -> Self {
        Self::channel_only(
            CandidateChannel::Unattributed,
            keyhog_core::EvidenceReasonCode::Unattributed,
        )
    }

    const fn channel_only(
        channel: CandidateChannel,
        evidence_reason: keyhog_core::EvidenceReasonCode,
    ) -> Self {
        Self {
            detector_index: Self::NO_DETECTOR,
            pattern_index: Self::NO_PATTERN,
            channel,
            source_role: keyhog_core::SemanticSourceRole::Unknown,
            parser_confidence: crate::source_semantics::SemanticParserConfidence::Abstained,
            evidence_reason,
        }
    }

    pub(crate) const fn channel(self) -> CandidateChannel {
        self.channel
    }

    pub(crate) const fn source_role(self) -> keyhog_core::SemanticSourceRole {
        self.source_role
    }
    pub(crate) const fn context_class(self) -> keyhog_core::EvidenceReasonCode {
        self.evidence_reason
    }

    pub(crate) const fn parser_confidence(
        self,
    ) -> crate::source_semantics::SemanticParserConfidence {
        self.parser_confidence
    }

    pub(crate) const fn evidence(self) -> keyhog_core::EvidenceVerdict {
        keyhog_core::EvidenceVerdict::from_reason(self.evidence_reason)
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
