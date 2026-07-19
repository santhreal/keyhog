use keyhog_core::{DetectorSpec, EntropyShapeSpec};

/// Reject detector policy that this scanner artifact cannot execute.
///
/// Run this before matcher construction. A detector-declared mechanism is part
/// of the finding contract, so compiling the detector while omitting that
/// mechanism would create a different detector under the same identity.
#[cfg(not(feature = "entropy"))]
pub(crate) fn validate_feature_compatibility(detectors: &[DetectorSpec]) -> Result<(), String> {
    let entropy_detectors = detectors
        .iter()
        .filter(|detector| detector.owns_entropy_policy())
        .map(|detector| detector.id.as_str())
        .collect::<Vec<_>>();
    if entropy_detectors.is_empty() {
        return Ok(());
    }
    let bpe_detectors = detectors
        .iter()
        .filter(|detector| detector.bpe_enabled == Some(true))
        .map(|detector| detector.id.as_str())
        .collect::<Vec<_>>();
    let bpe_detail = if bpe_detectors.is_empty() {
        String::new()
    } else {
        format!(
            "; BPE policy is also enabled for {}",
            bpe_detectors.join(", ")
        )
    };
    Err(format!(
        "scanner was built without the `entropy` feature, but detector entropy policy is enabled for {}{bpe_detail}; rebuild with `--features entropy` or use a detector corpus without entropy policy",
        entropy_detectors.join(", ")
    ))
}

#[cfg(feature = "entropy")]
pub(crate) const fn validate_feature_compatibility(
    _detectors: &[DetectorSpec],
) -> Result<(), String> {
    Ok(())
}

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
        let base = match self.floors.get(bucket) {
            Some(floor) => *floor,
            None => self.catch_all,
        };
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
    #[cfg(feature = "entropy")]
    pub(crate) sensitive_path_entropy_very_high: f64,
    pub(crate) mixed_alnum_floor: f64,
    pub(crate) symbolic_entropy_floor: f64,
    pub(crate) second_half_entropy_floor: f64,
    pub(crate) second_half_min_len: usize,
    pub(crate) unique_chars_min_len: usize,
    pub(crate) min_unique_chars: usize,
    pub(crate) unanchored_hex_max_len: usize,
    pub(crate) identical_char_max_len: usize,
    pub(crate) structured_dotted_min_len: usize,
    pub(crate) reject_repeated_blocks: bool,
    pub(crate) allow_alphabetic_credential: bool,
    pub(crate) reject_program_identifiers: bool,
    pub(crate) reject_source_symbol_identifiers: bool,
    pub(crate) reject_dash_segmented_alnum: bool,
    pub(crate) mixed_alnum_min_len: usize,
    pub(crate) isolated_mixed_entropy_floor: f64,
    pub(crate) isolated_symbolic_min_len: usize,
    pub(crate) isolated_symbolic_min_symbols: usize,
    pub(crate) isolated_symbolic_requires_non_underscore: bool,
    pub(crate) isolated_alpha_only_min_symbols: usize,
    pub(crate) isolated_alpha_only_min_alpha_ratio: f64,
    pub(crate) min_alnum_ratio: f64,
    pub(crate) source_type_name_max_len: usize,
    pub(crate) source_type_name_min_uppercase: usize,
    pub(crate) url_path_high_entropy_min_len: usize,
    pub(crate) isolated_colon_left_min_len: usize,
    pub(crate) isolated_colon_right_min_len: usize,
    pub(crate) leading_slash_base64_entropy_floor: f64,
    pub(crate) leading_slash_base64_min_len: usize,
    pub(crate) keyword_free_operator_margin: Option<f64>,
    pub(crate) keyword_free_min_len: usize,
    pub(crate) min_len: usize,
    pub(crate) max_len: usize,
    #[cfg(feature = "entropy")]
    pub(crate) bpe_max_bytes_per_token: Option<f64>,
    pub(crate) entropy_shape: Option<EntropyShapeSpec>,
}

impl CompiledEntropyPolicy {
    #[inline]
    pub(crate) fn keyword_free_effective_floor(
        &self,
        detector_floor: f64,
        operator_floor: f64,
    ) -> Option<f64> {
        self.keyword_free_operator_margin
            .map(|margin| detector_floor.max(operator_floor + margin))
    }

    #[inline]
    #[cfg(feature = "entropy")]
    pub(crate) fn keyword_free_admission_run_min_len(
        &self,
        operator_floor: f64,
        sensitive_path: bool,
    ) -> Option<usize> {
        let detector_floor = if sensitive_path {
            self.sensitive_path_entropy_very_high
        } else {
            self.entropy_very_high
        };
        let effective_floor = self.keyword_free_effective_floor(detector_floor, operator_floor)?;
        // A value with fewer than 2^floor distinct bytes cannot reach the
        // requested Shannon entropy. The integral power is a conservative
        // necessary bound that avoids per-chunk floating-point exponentiation.
        let entropy_min_len = 1usize << (effective_floor.floor() as u32).min(8);
        Some(self.keyword_free_min_len.max(entropy_min_len))
    }

    #[inline]
    #[cfg(feature = "entropy")]
    pub(crate) fn bpe_bound(&self, operator_override: Option<f64>) -> Option<f64> {
        let detector_bound = self.bpe_max_bytes_per_token?;
        Some(match operator_override {
            Some(bound) => bound,
            None => detector_bound,
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
        let entropy_low = Self::required(detector, "entropy_low", detector.entropy_low)?;
        let entropy_high = Self::required(detector, "entropy_high", detector.entropy_high)?;
        let entropy_very_high =
            Self::required(detector, "entropy_very_high", detector.entropy_very_high)?;
        let sensitive_path_entropy_very_high = Self::required(
            detector,
            "sensitive_path_entropy_very_high",
            detector.sensitive_path_entropy_very_high,
        )?;
        if !entropy_low.is_finite()
            || !entropy_high.is_finite()
            || !entropy_very_high.is_finite()
            || entropy_low < 0.0
            || entropy_low > entropy_high
            || entropy_high > entropy_very_high
            || entropy_very_high <= 0.0
            || entropy_very_high > 8.0
        {
            return Err(format!(
                "detector {:?} entropy thresholds must be finite and ordered as 0.0 <= entropy_low <= entropy_high <= entropy_very_high <= 8.0, with entropy_very_high greater than zero",
                detector.id
            ));
        }
        if !sensitive_path_entropy_very_high.is_finite()
            || sensitive_path_entropy_very_high <= 0.0
            || sensitive_path_entropy_very_high > entropy_very_high
        {
            return Err(format!(
                "detector {:?} sensitive_path_entropy_very_high must be finite, greater than zero, and no higher than entropy_very_high",
                detector.id
            ));
        }
        let owns_keyword_free = detector
            .entropy_roles
            .contains(&keyhog_core::EntropyDetectionRole::KeywordFree);
        let keyword_free_operator_margin = plausibility.keyword_free_operator_margin;
        match (owns_keyword_free, keyword_free_operator_margin) {
            (true, None) => {
                return Err(format!(
                    "detector {:?} claims entropy role `keyword-free` but omits plausibility.keyword_free_operator_margin",
                    detector.id
                ));
            }
            (false, Some(_)) => {
                return Err(format!(
                    "detector {:?} declares plausibility.keyword_free_operator_margin without claiming entropy role `keyword-free`",
                    detector.id
                ));
            }
            (_, Some(margin)) if !margin.is_finite() || !(0.0..=8.0).contains(&margin) => {
                return Err(format!(
                    "detector {:?} plausibility.keyword_free_operator_margin must be finite and in [0.0, 8.0]",
                    detector.id
                ));
            }
            _ => {}
        }
        if bpe_enabled != bpe_max_bytes_per_token.is_some() {
            return Err(format!(
                "detector {:?} must declare a positive BPE bound exactly when BPE is enabled",
                detector.id
            ));
        }
        if bpe_max_bytes_per_token.is_some_and(|bound| !bound.is_finite() || bound <= 0.0) {
            return Err(format!(
                "detector {:?} BPE bound must be finite and greater than zero",
                detector.id
            ));
        }
        let [entropy_shape] = detector.entropy_shapes.as_slice() else {
            return Err(format!(
                "detector {:?} owns entropy detection and must declare exactly one [[detector.entropy_shapes]] entry, found {}",
                detector.id,
                detector.entropy_shapes.len()
            ));
        };

        Ok(Self {
            entropy_high,
            entropy_low,
            entropy_very_high,
            #[cfg(feature = "entropy")]
            sensitive_path_entropy_very_high,
            mixed_alnum_floor: plausibility.mixed_alnum_floor,
            symbolic_entropy_floor: plausibility.symbolic_entropy_floor,
            second_half_entropy_floor: plausibility.second_half_entropy_floor,
            second_half_min_len: plausibility.second_half_min_len,
            unique_chars_min_len: plausibility.unique_chars_min_len,
            min_unique_chars: plausibility.min_unique_chars,
            unanchored_hex_max_len: plausibility.unanchored_hex_max_len,
            identical_char_max_len: plausibility.identical_char_max_len,
            structured_dotted_min_len: plausibility.structured_dotted_min_len,
            reject_repeated_blocks: plausibility.reject_repeated_blocks,
            allow_alphabetic_credential: plausibility.allow_alphabetic_credential,
            reject_program_identifiers: plausibility.reject_program_identifiers,
            reject_source_symbol_identifiers: plausibility.reject_source_symbol_identifiers,
            reject_dash_segmented_alnum: plausibility.reject_dash_segmented_alnum,
            mixed_alnum_min_len: plausibility.mixed_alnum_min_len,
            isolated_mixed_entropy_floor: plausibility.isolated_mixed_entropy_floor,
            isolated_symbolic_min_len: plausibility.isolated_symbolic_min_len,
            isolated_symbolic_min_symbols: plausibility.isolated_symbolic_min_symbols,
            isolated_symbolic_requires_non_underscore: plausibility
                .isolated_symbolic_requires_non_underscore,
            isolated_alpha_only_min_symbols: plausibility.isolated_alpha_only_min_symbols,
            isolated_alpha_only_min_alpha_ratio: plausibility.isolated_alpha_only_min_alpha_ratio,
            min_alnum_ratio: plausibility.min_alnum_ratio,
            source_type_name_max_len: plausibility.source_type_name_max_len,
            source_type_name_min_uppercase: plausibility.source_type_name_min_uppercase,
            url_path_high_entropy_min_len: plausibility.url_path_high_entropy_min_len,
            isolated_colon_left_min_len: plausibility.isolated_colon_left_min_len,
            isolated_colon_right_min_len: plausibility.isolated_colon_right_min_len,
            leading_slash_base64_entropy_floor: plausibility.leading_slash_base64_entropy_floor,
            leading_slash_base64_min_len: plausibility.leading_slash_base64_min_len,
            keyword_free_operator_margin,
            keyword_free_min_len: Self::required(
                detector,
                "keyword_free_min_len",
                detector.keyword_free_min_len,
            )?,
            min_len: Self::required(detector, "min_len", detector.min_len)?,
            max_len: Self::required(detector, "max_len", detector.max_len)?,
            #[cfg(feature = "entropy")]
            bpe_max_bytes_per_token,
            entropy_shape: Some(*entropy_shape),
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
