use super::{entropy::EntropyShapeStage, generic::GenericValueShapeStage};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StageId {
    DetectorCredentialShapeInvalid,
    WithinHexContext,
    HexDigestFragment,
    ProbabilisticGateNotPromising,
    FalsePositiveContext,
    MissingRequiredCompanion,
    EntropyBelowFloor,
    CamelCaseNoDigit,
    ChecksumInvalid,
    BelowMinConfidence,
    HardSuppressedContext,
    ShapeGate(&'static str),
    GenericKeywordBoundary,
    GenericNamedDetectorOwnedKeyword,
    BareAuthUnstructured,
    GenericValueShape(GenericValueShapeStage),
    GenericBelowMinConfidence,
    EntropyNamedDetectorOwnedAssignment,
    EntropyValueShape(EntropyShapeStage),
}

impl StageId {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::DetectorCredentialShapeInvalid => "detector_credential_shape_invalid",
            Self::WithinHexContext => "within_hex_context",
            Self::HexDigestFragment => "hex_digest_fragment",
            Self::ProbabilisticGateNotPromising => "probabilistic_gate_not_promising",
            Self::FalsePositiveContext => "false_positive_context",
            Self::MissingRequiredCompanion => "missing_required_companion",
            Self::EntropyBelowFloor => "entropy_below_floor",
            Self::CamelCaseNoDigit => "camel_case_no_digit",
            Self::ChecksumInvalid => "checksum_invalid",
            Self::BelowMinConfidence => "below_min_confidence",
            Self::HardSuppressedContext => "hard_suppressed_context",
            Self::ShapeGate(reason) => reason,
            Self::GenericKeywordBoundary => "generic_keyword_boundary",
            Self::GenericNamedDetectorOwnedKeyword => "generic_named_detector_owned_keyword",
            Self::BareAuthUnstructured => "bare_auth_unstructured",
            Self::GenericValueShape(stage) => stage.as_str(),
            Self::GenericBelowMinConfidence => "generic_below_min_confidence",
            Self::EntropyNamedDetectorOwnedAssignment => "entropy_named_detector_owned_assignment",
            Self::EntropyValueShape(stage) => stage.as_str(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StageOutcome {
    Pass,
    Suppress(StageId),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Verdict {
    Suppressed(StageId),
    Reported(Option<f64>),
}

impl Verdict {
    pub(crate) const fn suppressed_stage(self) -> Option<StageId> {
        match self {
            Self::Suppressed(stage_id) => Some(stage_id),
            Self::Reported(_) => None,
        }
    }
}
