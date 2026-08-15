//! Deterministic finding verdicts derived from scanner evidence.

use serde::{de::Error as _, ser::Error as _, Deserialize, Deserializer, Serialize, Serializer};

/// Operator-facing evidence tier for one finding.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceTier {
    /// Ambiguous evidence that remains visible but does not block default CI.
    Review,
    /// Strong provider and source evidence that blocks default CI.
    Likely,
    /// Intrinsic or live proof that blocks every finding policy.
    Confirmed,
}

impl EvidenceTier {
    /// Return the stable output spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Review => "review",
            Self::Likely => "likely",
            Self::Confirmed => "confirmed",
        }
    }

    /// Whether this tier blocks the selected CI policy.
    pub const fn blocks(self, paranoid: bool) -> bool {
        paranoid || !matches!(self, Self::Review)
    }
}

/// Stable reason code that determines a finding's evidence tier.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceReasonCode {
    /// No scanner producer evidence was available.
    Unattributed,
    /// The source syntax was unsupported, malformed, or outside parser bounds.
    UnsupportedContext,
    /// A declared semantic evidence requirement was not proven.
    RequiredEvidenceMissing,
    /// The detector declared only a weak or unanchored context.
    WeakAnchor,
    /// A generic detector pattern produced the candidate.
    GenericDetector,
    /// The generic assignment lane produced the candidate.
    GenericAssignment,
    /// The entropy-only lane produced the candidate.
    EntropyOnly,
    /// The candidate is in a test or example fixture.
    TestFixture,
    /// The candidate is in documentation prose.
    Documentation,
    /// The candidate is inside a regex, scanner rule, or grammar definition.
    RuleDefinition,
    /// The candidate is an identifier, type, or member name.
    Identifier,
    /// The candidate is a command-option declaration rather than its value.
    OptionDeclaration,
    /// The candidate is in generated or vendored material.
    GeneratedMaterial,
    /// Parsed source semantics do not match the detector's declared source roles.
    SourceRoleMismatch,
    /// A provider-specific named pattern matched in a credential-bearing source role.
    VendorPattern,
    /// A detector-owned structural grammar proved the credential shape.
    StructuralGrammar,
    /// Required companion evidence was present.
    RequiredCompanion,
    /// An intrinsic credential checksum validated.
    ChecksumValid,
    /// Live provider verification succeeded.
    LiveVerification,
}

impl EvidenceReasonCode {
    /// Return the tier implied by this reason code.
    pub const fn tier(self) -> EvidenceTier {
        match self {
            Self::VendorPattern => EvidenceTier::Likely,
            Self::StructuralGrammar
            | Self::RequiredCompanion
            | Self::ChecksumValid
            | Self::LiveVerification => EvidenceTier::Confirmed,
            Self::Unattributed
            | Self::UnsupportedContext
            | Self::RequiredEvidenceMissing
            | Self::WeakAnchor
            | Self::GenericDetector
            | Self::GenericAssignment
            | Self::EntropyOnly
            | Self::TestFixture
            | Self::Documentation
            | Self::RuleDefinition
            | Self::Identifier
            | Self::OptionDeclaration
            | Self::GeneratedMaterial
            | Self::SourceRoleMismatch => EvidenceTier::Review,
        }
    }

    /// Return the stable output spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unattributed => "unattributed",
            Self::UnsupportedContext => "unsupported-context",
            Self::RequiredEvidenceMissing => "required-evidence-missing",
            Self::WeakAnchor => "weak-anchor",
            Self::GenericDetector => "generic-detector",
            Self::GenericAssignment => "generic-assignment",
            Self::EntropyOnly => "entropy-only",
            Self::TestFixture => "test-fixture",
            Self::Documentation => "documentation",
            Self::RuleDefinition => "rule-definition",
            Self::Identifier => "identifier",
            Self::OptionDeclaration => "option-declaration",
            Self::GeneratedMaterial => "generated-material",
            Self::SourceRoleMismatch => "source-role-mismatch",
            Self::VendorPattern => "vendor-pattern",
            Self::StructuralGrammar => "structural-grammar",
            Self::RequiredCompanion => "required-companion",
            Self::ChecksumValid => "checksum-valid",
            Self::LiveVerification => "live-verification",
        }
    }
}

/// Scanner lane that produced a finding candidate.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingCandidateChannel {
    /// A detector-owned named pattern.
    Pattern,
    /// The generic credential assignment lane.
    GenericAssignment,
    /// The detector-owned entropy lane.
    Entropy,
    /// A caller-created finding without scanner provenance.
    Unattributed,
}

impl FindingCandidateChannel {
    /// Return the stable output spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pattern => "pattern",
            Self::GenericAssignment => "generic-assignment",
            Self::Entropy => "entropy",
            Self::Unattributed => "unattributed",
        }
    }
}

/// Secret-safe candidate identity retained in public evidence.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FindingProvenance {
    detector_digest: u64,
    pattern_index: u32,
    candidate_channel: FindingCandidateChannel,
    source_role: crate::SemanticSourceRole,
    context_class: EvidenceReasonCode,
}

impl FindingProvenance {
    /// Current persisted provenance schema.
    pub const SCHEMA_VERSION: u8 = 1;

    const fn has_scanner_context(context_class: EvidenceReasonCode) -> bool {
        !matches!(
            context_class,
            EvidenceReasonCode::Unattributed | EvidenceReasonCode::LiveVerification
        )
    }

    const fn fields_are_consistent(self) -> bool {
        match self.candidate_channel {
            FindingCandidateChannel::Pattern
            | FindingCandidateChannel::GenericAssignment
            | FindingCandidateChannel::Entropy => Self::has_scanner_context(self.context_class),
            FindingCandidateChannel::Unattributed => {
                self.detector_digest == 0
                    && self.pattern_index == 0
                    && matches!(self.source_role, crate::SemanticSourceRole::Unknown)
                    && matches!(self.context_class, EvidenceReasonCode::Unattributed)
            }
        }
    }

    /// Construct provenance for a scanner-owned named pattern.
    pub const fn pattern(
        detector_digest: u64,
        pattern_index: u32,
        source_role: crate::SemanticSourceRole,
        context_class: EvidenceReasonCode,
    ) -> Self {
        Self {
            detector_digest,
            pattern_index,
            candidate_channel: FindingCandidateChannel::Pattern,
            source_role,
            context_class,
        }
    }

    /// Construct provenance for the generic assignment lane.
    pub const fn generic_assignment(
        detector_digest: u64,
        source_role: crate::SemanticSourceRole,
        context_class: EvidenceReasonCode,
    ) -> Self {
        Self::lane(
            detector_digest,
            FindingCandidateChannel::GenericAssignment,
            source_role,
            context_class,
        )
    }

    /// Construct provenance for the entropy lane.
    pub const fn entropy(
        detector_digest: u64,
        source_role: crate::SemanticSourceRole,
        context_class: EvidenceReasonCode,
    ) -> Self {
        Self::lane(
            detector_digest,
            FindingCandidateChannel::Entropy,
            source_role,
            context_class,
        )
    }

    const fn lane(
        detector_digest: u64,
        candidate_channel: FindingCandidateChannel,
        source_role: crate::SemanticSourceRole,
        context_class: EvidenceReasonCode,
    ) -> Self {
        Self {
            detector_digest,
            pattern_index: 0,
            candidate_channel,
            source_role,
            context_class,
        }
    }

    /// Construct provenance for a caller-created finding.
    pub const fn unattributed() -> Self {
        Self {
            detector_digest: 0,
            pattern_index: 0,
            candidate_channel: FindingCandidateChannel::Unattributed,
            source_role: crate::SemanticSourceRole::Unknown,
            context_class: EvidenceReasonCode::Unattributed,
        }
    }

    /// Return the active detector-corpus digest.
    pub const fn detector_digest(self) -> Option<u64> {
        if matches!(
            self.candidate_channel,
            FindingCandidateChannel::Unattributed
        ) {
            None
        } else {
            Some(self.detector_digest)
        }
    }

    /// Return the detector-local source pattern ordinal.
    pub const fn pattern_index(self) -> Option<u32> {
        if matches!(self.candidate_channel, FindingCandidateChannel::Pattern) {
            Some(self.pattern_index)
        } else {
            None
        }
    }

    /// Return the candidate producer lane.
    pub const fn candidate_channel(self) -> FindingCandidateChannel {
        self.candidate_channel
    }

    /// Return the parsed source role.
    pub const fn source_role(self) -> crate::SemanticSourceRole {
        self.source_role
    }

    /// Return the pre-verification evidence context.
    pub const fn context_class(self) -> EvidenceReasonCode {
        self.context_class
    }
}

impl Serialize for FindingProvenance {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !self.fields_are_consistent() {
            return Err(S::Error::custom(
                "finding provenance fields are inconsistent with candidate_channel",
            ));
        }
        #[derive(Serialize)]
        struct WireProvenance<'a> {
            schema_version: u8,
            detector_digest: Option<&'a str>,
            pattern_index: Option<u32>,
            candidate_channel: FindingCandidateChannel,
            source_role: crate::SemanticSourceRole,
            context_class: EvidenceReasonCode,
        }

        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut digest_hex = [b'0'; 16];
        let detector_digest = if let Some(digest) = self.detector_digest() {
            for (index, digit) in digest_hex.iter_mut().enumerate() {
                let shift = (15 - index) * 4;
                *digit = HEX[((digest >> shift) & 0x0f) as usize];
            }
            Some(std::str::from_utf8(&digest_hex).map_err(S::Error::custom)?)
        } else {
            None
        };
        WireProvenance {
            schema_version: Self::SCHEMA_VERSION,
            detector_digest,
            pattern_index: self.pattern_index(),
            candidate_channel: self.candidate_channel,
            source_role: self.source_role,
            context_class: self.context_class,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FindingProvenance {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
        where
            D: Deserializer<'de>,
            T: Deserialize<'de>,
        {
            Option::<T>::deserialize(deserializer)
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireProvenance {
            schema_version: u8,
            #[serde(deserialize_with = "required_nullable")]
            detector_digest: Option<String>,
            #[serde(deserialize_with = "required_nullable")]
            pattern_index: Option<u32>,
            candidate_channel: FindingCandidateChannel,
            source_role: crate::SemanticSourceRole,
            context_class: EvidenceReasonCode,
        }

        let wire = WireProvenance::deserialize(deserializer)?;
        if wire.schema_version != Self::SCHEMA_VERSION {
            return Err(D::Error::custom(format!(
                "unsupported finding provenance schema {}; expected {}",
                wire.schema_version,
                Self::SCHEMA_VERSION
            )));
        }
        let detector_digest = wire
            .detector_digest
            .map(|digest| {
                if digest.len() != 16
                    || !digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(D::Error::custom(
                        "finding provenance detector_digest must be 16 lowercase hex digits",
                    ));
                }
                u64::from_str_radix(&digest, 16).map_err(D::Error::custom)
            })
            .transpose()?;
        let has_scanner_context = Self::has_scanner_context(wire.context_class);
        let fields_are_consistent = match wire.candidate_channel {
            FindingCandidateChannel::Pattern => {
                detector_digest.is_some() && wire.pattern_index.is_some() && has_scanner_context
            }
            FindingCandidateChannel::GenericAssignment | FindingCandidateChannel::Entropy => {
                detector_digest.is_some() && wire.pattern_index.is_none() && has_scanner_context
            }
            FindingCandidateChannel::Unattributed => {
                detector_digest.is_none()
                    && wire.pattern_index.is_none()
                    && matches!(wire.source_role, crate::SemanticSourceRole::Unknown)
                    && matches!(wire.context_class, EvidenceReasonCode::Unattributed)
            }
        };
        if !fields_are_consistent {
            return Err(D::Error::custom(
                "finding provenance fields are inconsistent with candidate_channel",
            ));
        }
        Ok(Self {
            detector_digest: detector_digest.unwrap_or(0),
            pattern_index: wire.pattern_index.unwrap_or(0),
            candidate_channel: wire.candidate_channel,
            source_role: wire.source_role,
            context_class: wire.context_class,
        })
    }
}

/// One internally consistent finding verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvidenceVerdict {
    reason_code: EvidenceReasonCode,
    provenance: FindingProvenance,
}

impl EvidenceVerdict {
    /// Construct a verdict from its canonical reason code.
    pub const fn from_reason(reason_code: EvidenceReasonCode) -> Self {
        Self {
            reason_code,
            provenance: FindingProvenance::unattributed(),
        }
    }

    /// Compatibility verdict for a caller-created finding with no producer proof.
    pub const fn review_unattributed() -> Self {
        Self::from_reason(EvidenceReasonCode::Unattributed)
    }

    /// Attach exact secret-safe scanner provenance.
    pub const fn with_provenance(mut self, provenance: FindingProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    /// Replace the final reason while retaining candidate provenance.
    pub const fn with_reason(mut self, reason_code: EvidenceReasonCode) -> Self {
        self.reason_code = reason_code;
        self
    }

    /// Return the derived evidence tier.
    pub const fn tier(self) -> EvidenceTier {
        self.reason_code.tier()
    }

    /// Return the canonical reason code.
    pub const fn reason_code(self) -> EvidenceReasonCode {
        self.reason_code
    }

    /// Return the exact secret-safe candidate provenance.
    pub const fn provenance(self) -> FindingProvenance {
        self.provenance
    }

    /// Select the stronger verdict, with stable reason and provenance tiebreaks.
    pub fn stronger(self, other: Self) -> Self {
        let self_tier = self.tier() as u8;
        let other_tier = other.tier() as u8;
        let same_reason = other_tier == self_tier && other.reason_code == self.reason_code;
        let self_attributed = !matches!(
            self.provenance.candidate_channel(),
            FindingCandidateChannel::Unattributed
        );
        let other_attributed = !matches!(
            other.provenance.candidate_channel(),
            FindingCandidateChannel::Unattributed
        );
        if other_tier > self_tier
            || (other_tier == self_tier && other.reason_code as u8 > self.reason_code as u8)
            || (same_reason && other_attributed && !self_attributed)
            || (same_reason
                && other_attributed == self_attributed
                && other.provenance > self.provenance)
        {
            other
        } else {
            self
        }
    }
}

impl Serialize for EvidenceVerdict {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct WireVerdict {
            tier: EvidenceTier,
            reason_code: EvidenceReasonCode,
            provenance: FindingProvenance,
        }

        WireVerdict {
            tier: self.tier(),
            reason_code: self.reason_code,
            provenance: self.provenance,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EvidenceVerdict {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireVerdict {
            tier: EvidenceTier,
            reason_code: EvidenceReasonCode,
            provenance: FindingProvenance,
        }

        let wire = WireVerdict::deserialize(deserializer)?;
        let verdict = Self::from_reason(wire.reason_code).with_provenance(wire.provenance);
        if verdict.tier() != wire.tier {
            return Err(D::Error::custom(format!(
                "evidence tier {:?} does not match reason code {:?}",
                wire.tier, wire.reason_code
            )));
        }
        Ok(verdict)
    }
}
