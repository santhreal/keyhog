use keyhog_core::{DetectorKind, DetectorSpec, EntropyShapeSpec};

/// Fully resolved entropy policy compiled once from an owning detector.
///
/// Active entropy owners must declare every value in their detector TOML. The
/// scan path therefore reads concrete fields and never consults scanner-side
/// defaults or repeatedly unwraps optional schema values per candidate.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CompiledEntropyPolicy {
    pub(crate) entropy_high: f64,
    pub(crate) entropy_low: f64,
    pub(crate) entropy_very_high: f64,
    pub(crate) sensitive_path_entropy_very_high: f64,
    pub(crate) mixed_alnum_floor: f64,
    pub(crate) symbolic_entropy_floor: f64,
    pub(crate) second_half_entropy_floor: f64,
    pub(crate) mixed_alnum_min_len: usize,
    pub(crate) keyword_free_min_len: usize,
    pub(crate) min_len: usize,
    pub(crate) bpe_enabled: bool,
    pub(crate) bpe_max_bytes_per_token: Option<f64>,
    pub(crate) entropy_shape: Option<EntropyShapeSpec>,
}

impl CompiledEntropyPolicy {
    #[inline]
    pub(crate) fn bpe_bound(
        &self,
        scan_fallback: f64,
        operator_override: Option<f64>,
    ) -> Option<f64> {
        self.bpe_enabled.then(|| {
            operator_override
                .or(self.bpe_max_bytes_per_token)
                .unwrap_or(scan_fallback)
        })
    }

    fn required<T: Copy>(
        detector: &DetectorSpec,
        field: &str,
        value: Option<T>,
    ) -> Result<T, String> {
        value.ok_or_else(|| {
            format!(
                "detector {:?} owns entropy detection but omits {field}; declare the complete policy in its detector TOML",
                detector.id
            )
        })
    }

    fn compile(detector: &DetectorSpec) -> Result<Self, String> {
        let _priority = Self::required(
            detector,
            "entropy_policy_priority",
            detector.entropy_policy_priority,
        )?;
        if detector.entropy_floor.is_empty() {
            return Err(format!(
                "detector {:?} owns entropy detection but omits entropy_floor",
                detector.id
            ));
        }
        if detector.kind == DetectorKind::Phase2Generic && detector.max_len.is_none() {
            return Err(format!(
                "detector {:?} owns phase-2 generic detection but omits max_len",
                detector.id
            ));
        }
        let bpe_enabled = Self::required(detector, "bpe_enabled", detector.bpe_enabled)?;
        let bpe_max_bytes_per_token = if bpe_enabled {
            Some(Self::required(
                detector,
                "bpe_max_bytes_per_token (or set bpe_enabled = false)",
                detector.bpe_max_bytes_per_token,
            )?)
        } else {
            None
        };
        let entropy_shape = detector.lower_dash_entropy_shape().ok_or_else(|| {
            format!(
                "detector {:?} owns entropy detection but omits [[detector.entropy_shapes]]; declare its isolated-candidate policy in the detector TOML",
                detector.id
            )
        })?;

        Ok(Self {
            entropy_high: Self::required(detector, "entropy_high", detector.entropy_high)?,
            entropy_low: Self::required(detector, "entropy_low", detector.entropy_low)?,
            entropy_very_high: Self::required(
                detector,
                "entropy_very_high",
                detector.entropy_very_high,
            )?,
            sensitive_path_entropy_very_high: Self::required(
                detector,
                "sensitive_path_entropy_very_high",
                detector.sensitive_path_entropy_very_high,
            )?,
            mixed_alnum_floor: Self::required(
                detector,
                "mixed_alnum_floor",
                detector.mixed_alnum_floor,
            )?,
            symbolic_entropy_floor: Self::required(
                detector,
                "symbolic_entropy_floor",
                detector.symbolic_entropy_floor,
            )?,
            second_half_entropy_floor: Self::required(
                detector,
                "second_half_entropy_floor",
                detector.second_half_entropy_floor,
            )?,
            mixed_alnum_min_len: Self::required(
                detector,
                "mixed_alnum_min_len",
                detector.mixed_alnum_min_len,
            )?,
            keyword_free_min_len: Self::required(
                detector,
                "keyword_free_min_len",
                detector.keyword_free_min_len,
            )?,
            min_len: Self::required(detector, "min_len", detector.min_len)?,
            bpe_enabled,
            bpe_max_bytes_per_token,
            entropy_shape: Some(entropy_shape),
        })
    }
}

#[derive(Debug, Default)]
pub(crate) struct CompiledEntropyPolicies {
    by_detector_index: Vec<Option<CompiledEntropyPolicy>>,
}

impl CompiledEntropyPolicies {
    pub(crate) fn compile(detectors: &[DetectorSpec]) -> Result<Self, String> {
        let mut by_detector_index = Vec::with_capacity(detectors.len());
        for detector in detectors {
            if !detector.owns_entropy_policy() {
                by_detector_index.push(None);
                continue;
            }
            let metadata = detector.entropy_fallback.as_ref().ok_or_else(|| {
                format!(
                    "detector {:?} owns entropy detection but omits [detector.entropy_fallback]",
                    detector.id
                )
            })?;
            if !metadata.has_valid_identity() {
                return Err(format!(
                    "detector {:?} declares invalid entropy_fallback metadata; id must use a lowercase entropy- namespace and name/service must be non-empty",
                    detector.id
                ));
            }
            by_detector_index.push(Some(CompiledEntropyPolicy::compile(detector)?));
        }
        Ok(Self { by_detector_index })
    }

    #[inline]
    pub(crate) fn get(&self, detector_index: usize) -> Option<&CompiledEntropyPolicy> {
        self.by_detector_index
            .get(detector_index)
            .and_then(Option::as_ref)
    }
}
