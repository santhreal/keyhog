//! Canonical fixed-point feature and model ABI shared by CPU and accelerator routes.

use sha2::{Digest, Sha256};
use std::sync::LazyLock;

use crate::ml_scorer::model_arch::{
    EXPERT_COUNT, EXPERT_FC1_B_COUNT, EXPERT_FC1_OUT, EXPERT_FC1_W_COUNT,
    EXPERT_FC2_B_COUNT, EXPERT_FC2_OUT, EXPERT_FC2_W_COUNT, EXPERT_FC3_B_COUNT,
    EXPERT_FC3_W_COUNT, EXPERT_PARAM_COUNT, EXPERTS_OFF, GATE_B_COUNT, GATE_B_OFF,
    GATE_W_COUNT, GATE_W_OFF, INPUT_DIM, TOTAL_F32_COUNT,
};

pub const FEATURE_SCHEMA_VERSION: u16 = 1;
pub const QUANTIZED_MODEL_FORMAT_VERSION: u16 = 1;
pub const QUANTIZED_SCORE_ABI_VERSION: u16 = 1;
pub const FRACTIONAL_BITS: u8 = 7;
pub const SCALE: i32 = 1 << FRACTIONAL_BITS;
pub const MAX_CANDIDATES_PER_BATCH: usize = 1 << 16;
pub const MODEL_BYTES: &[u8] = include_bytes!("../quantized_moe.bin");

const MAGIC: &[u8; 8] = b"KHQMOE\0\x01";
const HEADER_LEN: usize = 60;
const ROUND_TIES_AWAY_FROM_ZERO: u8 = 1;
const MAX_ACTIVATION: i32 = i16::MAX as i32;
const SIGMOID_SATURATION: i32 = 6 * SCALE;
const GATE_DECAY: i32 = 8 * SCALE;

/// Registry order is the serialized feature order. Tests enumerate this value,
/// so adding a model input requires an explicit ABI name rather than a silent width bump.
pub const FEATURE_NAMES: [&str; INPUT_DIM] = [
    "normalized_length", "length_at_least_20", "length_at_least_40",
    "length_at_least_100", "normalized_entropy", "entropy_at_least_low",
    "entropy_at_least_high", "entropy_at_least_very_high", "has_upper",
    "has_lower", "has_digit", "has_symbol", "has_known_prefix",
    "normalized_prefix_length", "openai_prefix", "aws_access_key_prefix",
    "has_assignment", "has_secret_keyword", "has_test_keyword", "comment_context",
    "has_placeholder_keyword", "low_byte_variety", "hex_placeholder", "has_url_scheme",
    "normalized_unique_bytes", "unique_bigram_ratio", "normalized_dot_count",
    "normalized_dash_count", "reserved_28", "reserved_29", "reserved_30", "reserved_31",
    "file_type_config", "file_type_source", "file_type_ci", "file_type_infra",
    "file_type_other", "file_type_binary", "comment_context_extra", "assignment_extra",
    "test_file_context", "decoded_binary_structure", "specific_service_context",
    "active_service_context", "generic_detector", "weak_anchor", "live_verifier",
    "required_companion", "structural_password_slot", "phase2_generic", "entropy_channel",
    "entropy_generic", "entropy_password", "entropy_token", "entropy_api_key",
];

pub const EXPERT_IDS: [u8; EXPERT_COUNT] = [0, 1, 2, 3, 4, 5];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateScoreOwnership {
    Fused,
    Cpu,
}

/// Classify bytes before feature extraction. Invalid UTF-8, empty candidates,
/// and values outside the scanner's bounded chunk ABI never enter a GPU buffer.
pub fn candidate_score_ownership(bytes: &[u8]) -> CandidateScoreOwnership {
    if bytes.is_empty()
        || bytes.len() > crate::types::MAX_SCAN_CHUNK_BYTES
        || std::str::from_utf8(bytes).is_err()
    {
        CandidateScoreOwnership::Cpu
    } else {
        CandidateScoreOwnership::Fused
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuantizedFeatureRow(pub [i16; INPUT_DIM]);

impl QuantizedFeatureRow {
    pub fn from_float(features: &[f32; INPUT_DIM]) -> Result<Self, QuantizedConfidenceError> {
        let mut row = [0i16; INPUT_DIM];
        for (index, (&value, output)) in features.iter().zip(&mut row).enumerate() {
            *output = quantize_f32(value).ok_or(QuantizedConfidenceError::InvalidFeature {
                index,
            })?;
        }
        Ok(Self(row))
    }

    pub fn canonical_bytes(&self) -> [u8; INPUT_DIM * 2] {
        let mut bytes = [0u8; INPUT_DIM * 2];
        for (index, value) in self.0.iter().enumerate() {
            bytes[index * 2..index * 2 + 2].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuantizedScore(pub u16);

impl QuantizedScore {
    pub const fn as_f64(self) -> f64 {
        self.0 as f64 / u16::MAX as f64
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FusedCandidateScore {
    pub candidate_id: u32,
    pub score: QuantizedScore,
}

pub fn validate_fused_output(
    expected_candidates: usize,
    output: Result<Vec<FusedCandidateScore>, QuantizedConfidenceError>,
) -> Result<Vec<QuantizedScore>, QuantizedConfidenceError> {
    if expected_candidates > MAX_CANDIDATES_PER_BATCH {
        return Err(QuantizedConfidenceError::BatchTooLarge {
            candidates: expected_candidates,
            maximum: MAX_CANDIDATES_PER_BATCH,
        });
    }
    let output = output?;
    if output.len() != expected_candidates {
        return Err(QuantizedConfidenceError::ScoreCardinality {
            expected: expected_candidates,
            actual: output.len(),
        });
    }
    let mut scores = Vec::new();
    scores
        .try_reserve_exact(output.len())
        .map_err(|_| QuantizedConfidenceError::BackendFailure(
            "score allocation failed within the candidate bound".into(),
        ))?;
    for (expected_id, candidate) in output.into_iter().enumerate() {
        if candidate.candidate_id != expected_id as u32 {
            return Err(QuantizedConfidenceError::CandidateId {
                expected: expected_id as u32,
                actual: candidate.candidate_id,
            });
        }
        scores.push(candidate.score);
    }
    Ok(scores)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuantizedConfidenceError {
    InvalidFeature { index: usize },
    InvalidModel(&'static str),
    BatchTooLarge { candidates: usize, maximum: usize },
    ScoreCardinality { expected: usize, actual: usize },
    CandidateId { expected: u32, actual: u32 },
    CandidateNotRepresentable,
    BackendFailure(String),
}

impl std::fmt::Display for QuantizedConfidenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFeature { index } => write!(formatter, "confidence feature {index} is outside the quantized ABI"),
            Self::InvalidModel(reason) => write!(formatter, "quantized confidence artifact is invalid: {reason}"),
            Self::BatchTooLarge { candidates, maximum } => write!(formatter, "quantized confidence batch has {candidates} candidates, above the {maximum}-candidate bound"),
            Self::ScoreCardinality { expected, actual } => write!(formatter, "quantized confidence backend returned {actual} scores for {expected} candidates"),
            Self::CandidateId { expected, actual } => write!(formatter, "quantized confidence backend returned candidate ID {actual}, expected {expected}"),
            Self::CandidateNotRepresentable => formatter.write_str("candidate cannot be represented exactly by the quantized confidence ABI"),
            Self::BackendFailure(reason) => write!(formatter, "selected quantized confidence backend failed: {reason}"),
        }
    }
}

impl std::error::Error for QuantizedConfidenceError {}

#[derive(Debug)]
pub struct QuantizedModel {
    params: Box<[i16]>,
    artifact_digest: [u8; 32],
    payload_digest: [u8; 32],
}

impl QuantizedModel {
    pub fn parse(bytes: &[u8]) -> Result<Self, QuantizedConfidenceError> {
        if bytes.len() < HEADER_LEN || &bytes[..8] != MAGIC {
            return Err(QuantizedConfidenceError::InvalidModel("bad magic or truncated header"));
        }
        let u16_at = |offset| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        if u16_at(8) != QUANTIZED_MODEL_FORMAT_VERSION
            || u16_at(10) != FEATURE_SCHEMA_VERSION
            || u16_at(12) as usize != INPUT_DIM
            || u16_at(14) as usize != EXPERT_COUNT
            || u16_at(16) as usize != EXPERT_FC1_OUT
            || u16_at(18) as usize != EXPERT_FC2_OUT
            || bytes[20] != FRACTIONAL_BITS
            || bytes[21] != ROUND_TIES_AWAY_FROM_ZERO
        {
            return Err(QuantizedConfidenceError::InvalidModel("unsupported schema, dimensions, scale, or rounding"));
        }
        if bytes[22..24] != [0, 0] {
            return Err(QuantizedConfidenceError::InvalidModel("reserved header bytes are nonzero"));
        }
        let payload_len = u32::from_le_bytes(bytes[24..28].try_into().map_err(|_| QuantizedConfidenceError::InvalidModel("truncated payload length"))?) as usize;
        let expected_len = TOTAL_F32_COUNT.checked_mul(2).ok_or(QuantizedConfidenceError::InvalidModel("parameter length overflow"))?;
        if payload_len != expected_len || bytes.len() != HEADER_LEN + payload_len {
            return Err(QuantizedConfidenceError::InvalidModel("parameter count or artifact length mismatch"));
        }
        let expected_payload_digest: [u8; 32] = bytes[28..60].try_into().map_err(|_| QuantizedConfidenceError::InvalidModel("truncated payload digest"))?;
        let payload = &bytes[HEADER_LEN..];
        let payload_digest: [u8; 32] = Sha256::digest(payload).into();
        if payload_digest != expected_payload_digest {
            return Err(QuantizedConfidenceError::InvalidModel("payload digest mismatch"));
        }
        let mut params = Vec::new();
        params.try_reserve_exact(TOTAL_F32_COUNT).map_err(|_| QuantizedConfidenceError::InvalidModel("parameter allocation failed"))?;
        for pair in payload.chunks_exact(2) {
            params.push(i16::from_le_bytes([pair[0], pair[1]]));
        }
        Ok(Self {
            params: params.into_boxed_slice(),
            artifact_digest: Sha256::digest(bytes).into(),
            payload_digest,
        })
    }

    pub const fn artifact_digest(&self) -> [u8; 32] { self.artifact_digest }
    pub const fn payload_digest(&self) -> [u8; 32] { self.payload_digest }

    pub fn score(&self, row: &QuantizedFeatureRow) -> QuantizedScore {
        let input = row.0.map(i32::from);
        let mut gate_logits = [0i32; EXPERT_COUNT];
        let gate_weights = &self.params[GATE_W_OFF..GATE_W_OFF + GATE_W_COUNT];
        let gate_bias = &self.params[GATE_B_OFF..GATE_B_OFF + GATE_B_COUNT];
        for expert in 0..EXPERT_COUNT {
            gate_logits[expert] = dense_signed(
                &gate_weights[expert * INPUT_DIM..(expert + 1) * INPUT_DIM],
                gate_bias[expert],
                &input,
            );
        }

        let mut expert_logits = [0i32; EXPERT_COUNT];
        for (expert, output) in expert_logits.iter_mut().enumerate() {
            let base = EXPERTS_OFF + expert * EXPERT_PARAM_COUNT;
            let fc1_w = &self.params[base..base + EXPERT_FC1_W_COUNT];
            let fc1_b_offset = base + EXPERT_FC1_W_COUNT;
            let fc1_b = &self.params[fc1_b_offset..fc1_b_offset + EXPERT_FC1_B_COUNT];
            let h1 = dense_relu::<INPUT_DIM, EXPERT_FC1_OUT>(fc1_w, fc1_b, &input);
            let fc2_w_offset = fc1_b_offset + EXPERT_FC1_B_COUNT;
            let fc2_w = &self.params[fc2_w_offset..fc2_w_offset + EXPERT_FC2_W_COUNT];
            let fc2_b_offset = fc2_w_offset + EXPERT_FC2_W_COUNT;
            let fc2_b = &self.params[fc2_b_offset..fc2_b_offset + EXPERT_FC2_B_COUNT];
            let h2 = dense_relu::<EXPERT_FC1_OUT, EXPERT_FC2_OUT>(fc2_w, fc2_b, &h1);
            let fc3_w_offset = fc2_b_offset + EXPERT_FC2_B_COUNT;
            let fc3_w = &self.params[fc3_w_offset..fc3_w_offset + EXPERT_FC3_W_COUNT];
            let fc3_b_offset = fc3_w_offset + EXPERT_FC3_W_COUNT;
            debug_assert_eq!(EXPERT_FC3_B_COUNT, 1);
            *output = dense_signed(fc3_w, self.params[fc3_b_offset], &h2);
        }
        QuantizedScore(fixed_sigmoid(mix_experts(&gate_logits, &expert_logits)))
    }

    #[cfg(test)]
    pub(crate) fn score_expert_for_test(&self, row: &QuantizedFeatureRow, expert: usize) -> i32 {
        let input = row.0.map(i32::from);
        let base = EXPERTS_OFF + expert * EXPERT_PARAM_COUNT;
        let fc1_b_offset = base + EXPERT_FC1_W_COUNT;
        let h1 = dense_relu::<INPUT_DIM, EXPERT_FC1_OUT>(
            &self.params[base..fc1_b_offset],
            &self.params[fc1_b_offset..fc1_b_offset + EXPERT_FC1_B_COUNT],
            &input,
        );
        let fc2_w_offset = fc1_b_offset + EXPERT_FC1_B_COUNT;
        let fc2_b_offset = fc2_w_offset + EXPERT_FC2_W_COUNT;
        let h2 = dense_relu::<EXPERT_FC1_OUT, EXPERT_FC2_OUT>(
            &self.params[fc2_w_offset..fc2_b_offset],
            &self.params[fc2_b_offset..fc2_b_offset + EXPERT_FC2_B_COUNT],
            &h1,
        );
        let fc3_w_offset = fc2_b_offset + EXPERT_FC2_B_COUNT;
        dense_signed(
            &self.params[fc3_w_offset..fc3_w_offset + EXPERT_FC3_W_COUNT],
            self.params[fc3_w_offset + EXPERT_FC3_W_COUNT],
            &h2,
        )
    }
}

static MODEL: LazyLock<Result<QuantizedModel, QuantizedConfidenceError>> =
    LazyLock::new(|| QuantizedModel::parse(MODEL_BYTES));

pub fn model() -> Result<&'static QuantizedModel, QuantizedConfidenceError> {
    MODEL
        .as_ref()
        .map_err(|_| QuantizedConfidenceError::InvalidModel("embedded artifact was rejected"))
}

pub fn model_artifact_digest() -> [u8; 32] { Sha256::digest(MODEL_BYTES).into() }

pub fn feature_schema_digest() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"keyhog-quantized-feature-schema\0");
    hasher.update(FEATURE_SCHEMA_VERSION.to_le_bytes());
    hasher.update([FRACTIONAL_BITS, ROUND_TIES_AWAY_FROM_ZERO]);
    for name in FEATURE_NAMES {
        hasher.update((name.len() as u16).to_le_bytes());
        hasher.update(name.as_bytes());
    }
    hasher.finalize().into()
}

pub fn score_batch(rows: &[QuantizedFeatureRow]) -> Result<Vec<QuantizedScore>, QuantizedConfidenceError> {
    if rows.len() > MAX_CANDIDATES_PER_BATCH {
        return Err(QuantizedConfidenceError::BatchTooLarge { candidates: rows.len(), maximum: MAX_CANDIDATES_PER_BATCH });
    }
    let model = model()?;
    let mut scores = Vec::new();
    scores.try_reserve_exact(rows.len()).map_err(|_| QuantizedConfidenceError::BatchTooLarge { candidates: rows.len(), maximum: MAX_CANDIDATES_PER_BATCH })?;
    scores.extend(rows.iter().map(|row| model.score(row)));
    Ok(scores)
}

fn quantize_f32(value: f32) -> Option<i16> {
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    let scaled = value * SCALE as f32;
    if !scaled.is_finite() {
        return None;
    }
    let rounded = if scaled >= 0.0 { (scaled + 0.5).floor() } else { (scaled - 0.5).ceil() };
    Some((rounded as i32).clamp(i16::MIN as i32, i16::MAX as i32) as i16)
}

fn round_div_ties_away(numerator: i32, denominator: i32) -> i32 {
    debug_assert!(denominator > 0);
    if numerator >= 0 {
        numerator.saturating_add(denominator / 2) / denominator
    } else {
        numerator.saturating_sub(denominator / 2) / denominator
    }
}

fn dense_signed<const INPUT: usize>(weights: &[i16], bias: i16, input: &[i32; INPUT]) -> i32 {
    let mut acc = i32::from(bias).saturating_mul(SCALE);
    for (&value, &weight) in input.iter().zip(weights) {
        acc = acc.saturating_add(value.saturating_mul(i32::from(weight)));
    }
    round_div_ties_away(acc, SCALE).clamp(i16::MIN as i32, i16::MAX as i32)
}

fn dense_relu<const INPUT: usize, const OUTPUT: usize>(weights: &[i16], bias: &[i16], input: &[i32; INPUT]) -> [i32; OUTPUT] {
    let mut output = [0i32; OUTPUT];
    for row in 0..OUTPUT {
        output[row] = dense_signed(
            &weights[row * INPUT..(row + 1) * INPUT],
            bias[row],
            input,
        ).clamp(0, MAX_ACTIVATION);
    }
    output
}

fn mix_experts(gate_logits: &[i32; EXPERT_COUNT], expert_logits: &[i32; EXPERT_COUNT]) -> i32 {
    let maximum = gate_logits.iter().copied().max().unwrap_or(0);
    let mut weighted_sum = 0i32;
    let mut weight_sum = 0i32;
    for index in 0..EXPERT_COUNT {
        let delta = maximum.saturating_sub(gate_logits[index]);
        let weight = (SCALE.saturating_mul(GATE_DECAY) / GATE_DECAY.saturating_add(delta)).max(1);
        weighted_sum = weighted_sum.saturating_add(expert_logits[index].saturating_mul(weight));
        weight_sum = weight_sum.saturating_add(weight);
    }
    round_div_ties_away(weighted_sum, weight_sum.max(1))
}

fn fixed_sigmoid(logit: i32) -> u16 {
    if logit <= -SIGMOID_SATURATION {
        return 0;
    }
    if logit >= SIGMOID_SATURATION {
        return u16::MAX;
    }
    let magnitude = logit.unsigned_abs() as i32;
    let base = SCALE.saturating_add(magnitude);
    let numerator = if logit < 0 { SCALE } else { SCALE.saturating_add(logit.saturating_mul(2)) };
    let denominator = base.saturating_mul(2);
    let scaled = numerator.saturating_mul(i32::from(u16::MAX));
    round_div_ties_away(scaled, denominator).clamp(0, i32::from(u16::MAX)) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_model_round_trips_and_registry_covers_every_input_and_expert() {
        let parsed = QuantizedModel::parse(MODEL_BYTES).expect("embedded model");
        assert_eq!(FEATURE_NAMES.len(), INPUT_DIM);
        assert_eq!(EXPERT_IDS.len(), EXPERT_COUNT);
        assert_eq!(parsed.artifact_digest(), model_artifact_digest());
        let row = QuantizedFeatureRow([0; INPUT_DIM]);
        for expert in EXPERT_IDS { let _ = parsed.score_expert_for_test(&row, expert as usize); }
    }

    #[test]
    fn generated_feature_and_expert_union_matches_integer_golden() {
        let model = model().expect("embedded model");
        let mut rows = Vec::with_capacity(INPUT_DIM + 2);
        rows.push(QuantizedFeatureRow([0; INPUT_DIM]));
        rows.push(QuantizedFeatureRow([SCALE as i16; INPUT_DIM]));
        for feature in 0..FEATURE_NAMES.len() {
            let mut row = [0i16; INPUT_DIM];
            row[feature] = SCALE as i16;
            rows.push(QuantizedFeatureRow(row));
        }

        let mut score_hasher = Sha256::new();
        let mut expert_hasher = Sha256::new();
        for row in &rows {
            score_hasher.update(model.score(row).0.to_le_bytes());
            for expert in EXPERT_IDS {
                expert_hasher.update(
                    model
                        .score_expert_for_test(row, expert as usize)
                        .to_le_bytes(),
                );
            }
        }
        assert_eq!(
            keyhog_core::hex_encode(&score_hasher.finalize()),
            "b08ec5fd96a9018cf843c9c2dda1a88aa43c5f9f394b8ed15c2283a24255c7fa"
        );
        assert_eq!(
            keyhog_core::hex_encode(&expert_hasher.finalize()),
            "36ac66ff3e22822db082f45a20eab091abac2454a25e8b60cb933356cb67072e"
        );
    }

    #[test]
    fn corrupt_stale_or_noncanonical_artifacts_fail_closed() {
        for offset in [0usize, 8, 10, 12, 20, 22, 24, 28, HEADER_LEN, MODEL_BYTES.len() - 1] {
            let mut corrupt = MODEL_BYTES.to_vec();
            corrupt[offset] ^= 1;
            assert!(QuantizedModel::parse(&corrupt).is_err(), "offset {offset}");
        }
        assert!(QuantizedModel::parse(&MODEL_BYTES[..MODEL_BYTES.len() - 1]).is_err());
    }

    #[test]
    fn saturation_rounding_and_score_boundaries_are_exact() {
        assert_eq!(round_div_ties_away(63, 128), 0);
        assert_eq!(round_div_ties_away(64, 128), 1);
        assert_eq!(round_div_ties_away(-63, 128), 0);
        assert_eq!(round_div_ties_away(-64, 128), -1);
        assert_eq!(fixed_sigmoid(-SIGMOID_SATURATION), 0);
        assert_eq!(fixed_sigmoid(SIGMOID_SATURATION), u16::MAX);
        assert_eq!(fixed_sigmoid(0), 32768);
    }

    #[test]
    fn empty_max_and_over_bound_batches_are_bounded() {
        assert!(score_batch(&[]).expect("empty batch").is_empty());
        let rows = vec![QuantizedFeatureRow([0; INPUT_DIM]); MAX_CANDIDATES_PER_BATCH];
        assert_eq!(score_batch(&rows).expect("maximum batch").len(), MAX_CANDIDATES_PER_BATCH);
        let over = vec![QuantizedFeatureRow([0; INPUT_DIM]); MAX_CANDIDATES_PER_BATCH + 1];
        assert!(matches!(score_batch(&over), Err(QuantizedConfidenceError::BatchTooLarge { .. })));
    }

    #[test]
    fn invalid_float_feature_domain_is_rejected_without_nan_abi() {
        for invalid in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -0.01] {
            let mut features = [0.0; INPUT_DIM];
            features[17] = invalid;
            assert_eq!(QuantizedFeatureRow::from_float(&features), Err(QuantizedConfidenceError::InvalidFeature { index: 17 }));
        }
    }

    #[test]
    fn malformed_utf8_and_empty_candidates_remain_cpu_owned() {
        for candidate in [
            &[][..],
            &[0xff][..],
            &[0xe2, 0x82][..],
            &[b'a', 0x80, b'b'][..],
        ] {
            assert_eq!(
                candidate_score_ownership(candidate),
                CandidateScoreOwnership::Cpu
            );
        }
        assert_eq!(
            candidate_score_ownership("token-\u{10ffff}".as_bytes()),
            CandidateScoreOwnership::Fused
        );
    }

    #[test]
    fn fused_output_rejects_failure_cardinality_and_order_without_fallback() {
        let failure = validate_fused_output(
            1,
            Err(QuantizedConfidenceError::BackendFailure(
                "injected device reset".into(),
            )),
        );
        assert!(matches!(
            failure,
            Err(QuantizedConfidenceError::BackendFailure(_))
        ));
        assert!(matches!(
            validate_fused_output(1, Ok(Vec::new())),
            Err(QuantizedConfidenceError::ScoreCardinality { .. })
        ));
        assert!(matches!(
            validate_fused_output(
                2,
                Ok(vec![
                    FusedCandidateScore {
                        candidate_id: 1,
                        score: QuantizedScore(1),
                    },
                    FusedCandidateScore {
                        candidate_id: 0,
                        score: QuantizedScore(2),
                    },
                ])
            ),
            Err(QuantizedConfidenceError::CandidateId { .. })
        ));
        assert_eq!(
            validate_fused_output(
                2,
                Ok(vec![
                    FusedCandidateScore {
                        candidate_id: 0,
                        score: QuantizedScore(1),
                    },
                    FusedCandidateScore {
                        candidate_id: 1,
                        score: QuantizedScore(2),
                    },
                ])
            )
            .expect("ordered scores"),
            vec![QuantizedScore(1), QuantizedScore(2)]
        );
    }
}
