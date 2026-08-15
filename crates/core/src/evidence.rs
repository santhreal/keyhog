//! Deterministic finding verdicts derived from scanner evidence.

use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

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

/// One internally consistent finding verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvidenceVerdict {
    reason_code: EvidenceReasonCode,
}

impl EvidenceVerdict {
    /// Construct a verdict from its canonical reason code.
    pub const fn from_reason(reason_code: EvidenceReasonCode) -> Self {
        Self { reason_code }
    }

    /// Compatibility verdict for a caller-created finding with no producer proof.
    pub const fn review_unattributed() -> Self {
        Self::from_reason(EvidenceReasonCode::Unattributed)
    }

    /// Return the derived evidence tier.
    pub const fn tier(self) -> EvidenceTier {
        self.reason_code.tier()
    }

    /// Return the canonical reason code.
    pub const fn reason_code(self) -> EvidenceReasonCode {
        self.reason_code
    }

    /// Select the stronger verdict, with a stable reason-code tiebreak.
    pub const fn stronger(self, other: Self) -> Self {
        let self_tier = self.tier() as u8;
        let other_tier = other.tier() as u8;
        if other_tier > self_tier
            || (other_tier == self_tier && other.reason_code as u8 > self.reason_code as u8)
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
        }

        WireVerdict {
            tier: self.tier(),
            reason_code: self.reason_code,
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
        }

        let wire = WireVerdict::deserialize(deserializer)?;
        let verdict = Self::from_reason(wire.reason_code);
        if verdict.tier() != wire.tier {
            return Err(D::Error::custom(format!(
                "evidence tier {:?} does not match reason code {:?}",
                wire.tier, wire.reason_code
            )));
        }
        Ok(verdict)
    }
}
