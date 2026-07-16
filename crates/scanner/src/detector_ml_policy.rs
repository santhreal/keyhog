//! Compact runtime form of detector-owned ML policy.

use crate::ml_scorer::ml_features::CompiledDetectorMlFeatures;
use keyhog_core::{DetectorMlMode, DetectorMlPolicySpec, DetectorSpec};

/// Enabled model behavior. `Disabled` is eliminated while detector policy is
/// compiled so queued candidates cannot carry an impossible inactive state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActiveMlMode {
    Lift,
    Blend,
    Authoritative,
}

impl ActiveMlMode {
    #[inline]
    fn compile(mode: DetectorMlMode) -> Option<Self> {
        match mode {
            DetectorMlMode::Disabled => None,
            DetectorMlMode::Lift => Some(Self::Lift),
            DetectorMlMode::Blend => Some(Self::Blend),
            DetectorMlMode::Authoritative => Some(Self::Authoritative),
        }
    }
}

/// Cache-local ML policy indexed by compiled detector index.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CompiledDetectorMlPolicy {
    pub(crate) match_mode: Option<ActiveMlMode>,
    pub(crate) entropy_mode: Option<ActiveMlMode>,
    pub(crate) weight: f64,
    pub(crate) context_radius_lines: usize,
    pub(crate) features: CompiledDetectorMlFeatures,
}

impl CompiledDetectorMlPolicy {
    pub(crate) fn compile(detector: &DetectorSpec) -> Self {
        let policy: DetectorMlPolicySpec = detector.ml;
        Self {
            match_mode: ActiveMlMode::compile(policy.match_mode),
            entropy_mode: ActiveMlMode::compile(policy.entropy_mode),
            weight: policy.weight,
            context_radius_lines: policy.context_radius_lines,
            features: CompiledDetectorMlFeatures::compile(detector),
        }
    }
}

impl CompiledDetectorMlPolicy {
    #[inline]
    pub(crate) fn effective_weight(self, config: &crate::types::ScannerConfig) -> f64 {
        config.ml_weight_override.unwrap_or(self.weight)
    }
}
