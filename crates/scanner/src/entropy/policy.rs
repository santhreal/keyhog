use keyhog_core::{DetectorSpec, EntropyShapeSpec};

/// Length-bucketed detector floor compiled into parallel primitive arrays.
/// Runtime lookup performs one binary search and never walks optional TOML
/// fields or substitutes a scanner-owned threshold.
#[derive(Debug)]
pub(crate) struct CompiledEntropyFloorPolicy {
    max_lengths: Box<[usize]>,
    floors: Box<[f64]>,
    catch_all: f64,
    entropy_high: f64,
}

impl CompiledEntropyFloorPolicy {
    pub(crate) fn compile(detector: &DetectorSpec) -> Result<Option<Self>, String> {
        if detector.entropy_floor.is_empty() {
            return Ok(None);
        }
        let entropy_high = detector.entropy_high.ok_or_else(|| {
            format!(
                "detector {:?} declares entropy_floor but omits entropy_high",
                detector.id
            )
        })?;
        let (catch_all_bucket, bounded) = detector
            .entropy_floor
            .split_last()
            .ok_or_else(|| format!("detector {:?} declares an empty entropy_floor", detector.id))?;
        if catch_all_bucket.max_len.is_some() {
            return Err(format!(
                "detector {:?} entropy_floor must end with a catch-all bucket",
                detector.id
            ));
        }
        let mut max_lengths = Vec::with_capacity(bounded.len());
        let mut floors = Vec::with_capacity(bounded.len());
        for bucket in bounded {
            let max_len = bucket.max_len.ok_or_else(|| {
                format!(
                    "detector {:?} entropy_floor contains a catch-all bucket before the end",
                    detector.id
                )
            })?;
            if max_lengths
                .last()
                .is_some_and(|previous| *previous >= max_len)
            {
                return Err(format!(
                    "detector {:?} entropy_floor max_len values must strictly increase",
                    detector.id
                ));
            }
            max_lengths.push(max_len);
            floors.push(bucket.floor);
        }
        Ok(Some(Self {
            max_lengths: max_lengths.into_boxed_slice(),
            floors: floors.into_boxed_slice(),
            catch_all: catch_all_bucket.floor,
            entropy_high,
        }))
    }

    #[inline]
    pub(crate) fn effective_floor(&self, credential_len: usize, operator_threshold: f64) -> f64 {
        let bucket = self
            .max_lengths
            .partition_point(|max_len| credential_len > *max_len);
        let base = self.floors.get(bucket).copied().unwrap_or(self.catch_all);
        if operator_threshold.is_finite() && operator_threshold > self.entropy_high {
            base.max(operator_threshold)
        } else {
            base
        }
    }
}

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
    pub(crate) reject_repeated_blocks: bool,
    pub(crate) allow_alphabetic_credential: bool,
    pub(crate) reject_program_identifiers: bool,
    pub(crate) reject_dash_segmented_alnum: bool,
    pub(crate) mixed_alnum_min_len: usize,
    pub(crate) isolated_mixed_entropy_floor: f64,
    pub(crate) isolated_symbolic_min_len: usize,
    pub(crate) isolated_colon_left_min_len: usize,
    pub(crate) isolated_colon_right_min_len: usize,
    pub(crate) leading_slash_base64_entropy_floor: f64,
    pub(crate) keyword_free_min_len: usize,
    pub(crate) min_len: usize,
    pub(crate) max_len: usize,
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

    pub(crate) fn compile(detector: &DetectorSpec) -> Result<Self, String> {
        let plausibility = detector.plausibility.ok_or_else(|| {
            format!(
                "detector {:?} owns entropy detection but omits [detector.plausibility]",
                detector.id
            )
        })?;
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
            mixed_alnum_floor: plausibility.mixed_alnum_floor,
            symbolic_entropy_floor: plausibility.symbolic_entropy_floor,
            second_half_entropy_floor: plausibility.second_half_entropy_floor,
            reject_repeated_blocks: plausibility.reject_repeated_blocks,
            allow_alphabetic_credential: plausibility.allow_alphabetic_credential,
            reject_program_identifiers: plausibility.reject_program_identifiers,
            reject_dash_segmented_alnum: plausibility.reject_dash_segmented_alnum,
            mixed_alnum_min_len: plausibility.mixed_alnum_min_len,
            isolated_mixed_entropy_floor: plausibility.isolated_mixed_entropy_floor,
            isolated_symbolic_min_len: plausibility.isolated_symbolic_min_len,
            isolated_colon_left_min_len: plausibility.isolated_colon_left_min_len,
            isolated_colon_right_min_len: plausibility.isolated_colon_right_min_len,
            leading_slash_base64_entropy_floor: plausibility.leading_slash_base64_entropy_floor,
            keyword_free_min_len: Self::required(
                detector,
                "keyword_free_min_len",
                detector.keyword_free_min_len,
            )?,
            min_len: Self::required(detector, "min_len", detector.min_len)?,
            max_len: Self::required(detector, "max_len", detector.max_len)?,
            bpe_enabled,
            bpe_max_bytes_per_token,
            entropy_shape: Some(entropy_shape),
        })
    }
}

pub(crate) fn compile_entropy_policy(
    detector: &DetectorSpec,
) -> Result<Option<CompiledEntropyPolicy>, String> {
    if !detector.owns_entropy_policy() {
        return Ok(None);
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
    CompiledEntropyPolicy::compile(detector).map(Some)
}
