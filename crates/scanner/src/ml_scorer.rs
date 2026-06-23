//! ML-based secret scoring with a tiny mixture-of-experts network.
//!
//! Architecture: gate Linear(D,6) → Softmax plus 6 experts of
//! Linear(D,32) → ReLU → Linear(32,16) → ReLU → Linear(16,1), then
//! a weighted logit sum followed by Sigmoid, where `D = NUM_FEATURES` (42).
//! Model weights are embedded in `ml_weights.rs` as little-endian f32 values.
//! Inference: typically under ~100μs per prediction on the test hardware
//!
//! The 42 input features capture everything our heuristics know: length,
//! entropy, char diversity, known prefixes, context keywords, placeholder
//! patterns, structural signals, coarse file-type cues, and the decode-structure
//! verdict (feature #41, base64/hex → magic-bytes/protobuf), the single feature
//! that drove the base64-of-binary false-flag rate to 0%.

// Submodules live in `ml_scorer/` (native path resolution), matching the
// `foo.rs` + `foo/` layout used across the workspace (e.g. sources/filesystem).
pub(crate) mod ml_weights;

use std::cell::RefCell;

mod ml_features;
#[cfg(test)]
pub(crate) use ml_features::compute_features_public;
pub use ml_features::compute_features_with_config;
pub(crate) use ml_features::NUM_FEATURES;

/// Batch-size crossover for ML scoring. Below this, `batch_ml_inference` scores
/// serially (a fused feature->score loop) because it already runs inside the
/// parallel coalesced/per-chunk scan, where a `par_iter` over a handful of
/// candidates only pays rayon split/join overhead. At or above it, feature
/// extraction parallelizes and the GPU MoE dispatch becomes worthwhile. Single
/// source of truth: the GPU backend's dispatch gate references this same const
/// so the serial/parallel boundary and the GPU-engage boundary can never drift.
#[cfg(any(feature = "gpu", feature = "ml"))]
pub(crate) const GPU_BATCH_THRESHOLD: usize = 64;

/// Number of mixture-of-experts specialists. Each expert sees the same input
/// but learns different aspects (one may specialize in cloud credentials,
/// another in short API keys, etc.). 6 experts balance capacity vs. inference
/// cost, trained via grid search over {4, 6, 8, 12}.
const EXPERT_COUNT: usize = 6;
const EXPERT_HIDDEN_LAYER_1: usize = 32;
const EXPERT_HIDDEN_LAYER_2: usize = 16;

// SINGLE-SOURCE-OF-TRUTH guard. These layer dimensions are mirrored from
// `ml_weights` (their canonical home, where they also drive the `weights.bin`
// buffer offsets) because the forward pass needs them as plain consts for
// const-generic dense-layer sizing. If a retrain changes the architecture in
// `ml_weights`/`weights.bin` but a mirror here is not updated, the forward pass
// would slice the weight buffer with the wrong stride — silent wrong scores or
// an out-of-bounds index in release, where the per-call `debug_assert`s vanish
// and only `all_weights()`'s byte-length `assert` (which checks `weights.bin`
// SIZE, not these strides) fires. These const assertions fail the BUILD on any
// drift, before any test runs, at zero runtime cost.
const _: () = assert!(NUM_FEATURES == ml_weights::INPUT_DIM);
const _: () = assert!(EXPERT_COUNT == ml_weights::EXPERT_COUNT);
const _: () = assert!(EXPERT_HIDDEN_LAYER_1 == ml_weights::EXPERT_FC1_OUT);
const _: () = assert!(EXPERT_HIDDEN_LAYER_2 == ml_weights::EXPERT_FC2_OUT);

/// Score a candidate secret and its surrounding context using default (empty) heuristic lists.
pub(crate) fn score(text: &str, context: &str) -> f64 {
    score_with_config(text, context, &[], &[], &[], &[])
}

/// Score a candidate secret and its surrounding context with provided heuristic lists.
pub(crate) fn score_with_config(
    text: &str,
    context: &str,
    known_prefixes: &[String],
    secret_keywords: &[String],
    test_keywords: &[String],
    placeholder_keywords: &[String],
) -> f64 {
    if text.is_empty() {
        return 0.0;
    }

    thread_local! {
        // FNV-1a keyed cache - ~100x faster than SHA-256 for cache lookups.
        // 256-entry bounded cache covers batch scoring of one file's matches.
        static SCORE_CACHE: RefCell<std::collections::HashMap<u64, f64>> =
            RefCell::new(std::collections::HashMap::with_capacity(64));
    }

    // FNV-1a content key over text + separator + context, folded through the
    // shared allocation-free `util_hash::FnvHasher` (MC-12). The `&[0]`
    // separator round reproduces the previous inline `hash ^= 0; *= prime`
    // exactly, so the key is byte-identical to the old hand-rolled loop.
    let cache_key = {
        let mut h = crate::util_hash::FnvHasher::new();
        h.write(text.as_bytes());
        h.write(&[0]); // separator
        h.write(context.as_bytes());
        h.finish()
    };

    if let Some(score) = SCORE_CACHE.with(|cache| cache.borrow().get(&cache_key).copied()) {
        return score;
    }

    let features = compute_features_with_config(
        text,
        context,
        known_prefixes,
        secret_keywords,
        test_keywords,
        placeholder_keywords,
    );
    let score = forward_pass(&features) as f64;
    SCORE_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.len() >= 256 {
            cache.clear();
        }
        cache.insert(cache_key, score);
    });
    score
}

/// Score pending ML matches on the CPU using the same candidate/context fields
/// the GPU batch path receives.
#[cfg(feature = "ml")]
pub(crate) fn score_pending_matches_with_config(
    pending_matches: &[crate::types::MlPendingMatch],
    known_prefixes: &[String],
    secret_keywords: &[String],
    test_keywords: &[String],
    placeholder_keywords: &[String],
) -> Vec<f64> {
    pending_matches
        .iter()
        .map(|pending| {
            score_with_config(
                pending.credential.as_str(),
                pending.ml_context.as_str(),
                known_prefixes,
                secret_keywords,
                test_keywords,
                placeholder_keywords,
            )
        })
        .collect()
}

/// Borrow the exact pending-match candidate/context pairs used by every model
/// scoring backend.
#[cfg(feature = "ml")]
pub(crate) fn pending_match_score_inputs(
    pending_matches: &[crate::types::MlPendingMatch],
) -> Vec<(&str, &str)> {
    pending_matches
        .iter()
        .map(|pending| (pending.credential.as_str(), pending.ml_context.as_str()))
        .collect()
}

/// Preserve pending-match cardinality before confidence blending. A malformed
/// GPU/backend score vector is a backend failure, not permission to drop queued
/// findings.
#[cfg(feature = "ml")]
pub(crate) fn complete_pending_match_scores_with_config(
    scores: Vec<f64>,
    pending_matches: &[crate::types::MlPendingMatch],
    known_prefixes: &[String],
    secret_keywords: &[String],
    test_keywords: &[String],
    placeholder_keywords: &[String],
) -> Vec<f64> {
    if scores.len() == pending_matches.len() {
        return scores;
    }
    tracing::warn!(
        pending = pending_matches.len(),
        scores = scores.len(),
        "ML score count mismatch; recomputing CPU MoE scores before confidence blending"
    );
    score_pending_matches_with_config(
        pending_matches,
        known_prefixes,
        secret_keywords,
        test_keywords,
        placeholder_keywords,
    )
}

/// Score precomputed model features without recomputing text/context signals.
#[cfg(feature = "ml")]
pub(crate) fn score_features(features: &[f32; NUM_FEATURES]) -> f64 {
    forward_pass(features) as f64
}

/// Return the embedded model version string for diagnostics and CLI output.
pub fn model_version() -> &'static str {
    ml_weights::MODEL_VERSION
}

/// Return a compact embedded model-card summary for diagnostics and CLI output.
pub fn model_card_summary() -> &'static str {
    ml_weights::MODEL_CARD_SUMMARY
}

/// Return the full embedded model-card JSON for provenance-aware tooling.
pub fn model_card_json() -> &'static str {
    ml_weights::MODEL_CARD_JSON
}

/// Forward pass through the MoE model with hardcoded weights.
///
/// Two layered optimizations, both numerically inert:
///
/// 1. **Weight hoist.** The model's weight/bias slices are resolved ONCE per call
///    via [`ml_weights::model`] (a single `OnceLock`-acquire of an already-built
///    `&'static MoeModel`) instead of the prior 37 per-candidate accessor calls,
///    each of which re-acquired the `OnceLock` and re-sliced the flat buffer.
///
/// 2. **Output-stationary dense layers.** The two large expert layers (fc1: 32
///    outputs, fc2: 16) run via [`dense_relu_layer_t`] over COLUMN-major
///    (transposed) weights: for each input the contiguous output row is scaled
///    and accumulated, so the dependency-free inner loop over outputs vectorizes
///    across 8-16 output lanes. Each output still reduces its inputs in index
///    order with separate round(mul)/round(add) (no FMA fusion), so the result is
///    BIT-IDENTICAL to the row-major scalar dot product — vectorizing across
///    outputs never reassociates a single output's sum. The small gate (6) and
///    fc3 (1) layers stay scalar [`dense_row`] (nothing to vectorize across).
///
/// An explicit AVX2+FMA reduction was tried INSTEAD of (2) and REVERTED:
/// `_mm256_fmadd_ps` fuses each multiply-add with a single rounding step and
/// reassociates the sum across 8 lanes, so its result is NOT bit-identical. That
/// sub-ULP divergence pushed borderline ML-gated detectors (twilio-auth-token,
/// africastalking-api-key, appsmith-api-credentials, …) across their
/// `min_confidence` floor and regressed 30+ `contracts_runner` positives/evasions.
/// The confidence model and the GPU parity reference (DET-11) are calibrated
/// against this exact reduction. The output-stationary layout gets the SIMD width
/// WITHOUT the divergence (proved bit-identical in
/// `tests/ml_forward_parity.rs`); do NOT reintroduce FMA fusion or lane
/// reassociation without recalibrating every contract and the GPU parity reference.
fn forward_pass(input: &[f32; NUM_FEATURES]) -> f32 {
    let model = ml_weights::model();
    forward_pass_impl(model, input)
}

/// MoE forward pass over the hoisted model. fc1/fc2 use the output-stationary
/// vectorized kernel ([`dense_relu_layer_t`]); the gate and fc3 stay scalar.
fn forward_pass_impl(model: &ml_weights::MoeModel, input: &[f32; NUM_FEATURES]) -> f32 {
    let gate_probs = softmax(&compute_gate_logits(model, input));
    let mut score_logit = 0.0f32;
    for (expert_idx, gate_prob) in gate_probs.iter().enumerate() {
        score_logit += *gate_prob * expert_logit(&model.experts[expert_idx], input);
    }
    sigmoid(score_logit)
}

fn compute_gate_logits(
    model: &ml_weights::MoeModel,
    input: &[f32; NUM_FEATURES],
) -> [f32; EXPERT_COUNT] {
    debug_assert_eq!(model.gate_weight.len(), NUM_FEATURES * EXPERT_COUNT);
    debug_assert_eq!(model.gate_bias.len(), EXPERT_COUNT);

    let mut gate_logits = [0.0f32; EXPERT_COUNT];
    for (expert_idx, logit) in gate_logits.iter_mut().enumerate() {
        let row = &model.gate_weight[expert_idx * NUM_FEATURES..];
        *logit = dense_row(row, input, model.gate_bias[expert_idx]);
    }
    gate_logits
}

fn expert_logit(expert: &ml_weights::ExpertWeights, input: &[f32; NUM_FEATURES]) -> f32 {
    let h1 = dense_relu_layer_t::<NUM_FEATURES, EXPERT_HIDDEN_LAYER_1>(
        expert.fc1_weight_t,
        expert.fc1_bias,
        input,
    );
    let h2 = dense_relu_layer_t::<EXPERT_HIDDEN_LAYER_1, EXPERT_HIDDEN_LAYER_2>(
        expert.fc2_weight_t,
        expert.fc2_bias,
        &h1,
    );
    dense_row(expert.fc3_weight, &h2, expert.fc3_bias)
}

/// Output-stationary ReLU dense layer over COLUMN-major (transposed) weights:
/// `weights_t[k*OUTPUT + o]` is input `k`'s weight to output `o`
/// (`ml_weights::transpose_static`). For each input `k` we scale its contiguous
/// `OUTPUT`-wide weight row by `input[k]` and accumulate into the `OUTPUT` running
/// sums. The inner loop over outputs has NO loop-carried dependency (each
/// `acc[o]` is independent), so LLVM vectorizes it across the output lanes at
/// opt-level 3 — 8-16 outputs updated per SIMD instruction instead of one scalar
/// MAC at a time.
///
/// BIT-IDENTICAL to the row-major `dense_row` dot product: each `acc[o]` still
/// starts at `bias[o]` and adds `input[k]*w[o][k]` for `k = 0,1,..,INPUT-1` in
/// order, with a separate round-to-f32 on the multiply and on the add (Rust does
/// NOT contract `a*b + c` into a fused multiply-add without fast-math, and we use
/// none), then the SAME `.max(0.0)` ReLU. Vectorizing ACROSS outputs does not
/// reassociate any single output's reduction, so the result equals the scalar
/// path bit-for-bit. The previous AVX2+FMA attempt reassociated lanes and fused
/// the MAC, diverged sub-ULP, and regressed ~30 ML-gated contracts; this layout
/// does not. The equality is proved exhaustively over random weights/inputs in
/// `crates/scanner/tests/ml_forward_parity.rs`.
#[inline]
fn dense_relu_layer_t<const INPUT: usize, const OUTPUT: usize>(
    weights_t: &[f32],
    bias: &[f32],
    input: &[f32; INPUT],
) -> [f32; OUTPUT] {
    let mut acc = [0.0f32; OUTPUT];
    for (o, slot) in acc.iter_mut().enumerate() {
        *slot = bias[o];
    }
    for k in 0..INPUT {
        let x = input[k];
        // One contiguous OUTPUT-wide weight row per input. `zip` bounds the
        // iteration to `min(OUTPUT, row.len())` with no per-element bounds check,
        // and vectorizes across the output lanes.
        let row = &weights_t[k * OUTPUT..k * OUTPUT + OUTPUT];
        for (slot, &w) in acc.iter_mut().zip(row.iter()) {
            *slot += x * w;
        }
    }
    for slot in acc.iter_mut() {
        *slot = slot.max(0.0);
    }
    acc
}

/// Dot product of a weight row with the input vector plus bias.
///
/// `weights` may be longer than `input` (it is a borrow into the flat model
/// buffer starting at the row offset); `zip` bounds the reduction to exactly
/// `INPUT` pairs with no per-element bounds check, and the statically-known
/// `input` length lets the backend autovectorize. The accumulation stays a
/// single left-to-right sequential sum (`i = 0,1,..,INPUT-1`) with a separate
/// round on the multiply and the add (no FMA fusion), so the f32 result is
/// bit-identical to the scalar reference.
#[inline(always)]
fn dense_row<const INPUT: usize>(weights: &[f32], input: &[f32; INPUT], bias: f32) -> f32 {
    let mut sum = bias;
    for (&x, &w) in input.iter().zip(weights.iter()) {
        sum += x * w;
    }
    sum
}

fn sigmoid(value: f32) -> f32 {
    let x = value;
    if x <= -6.0 {
        0.0
    } else if x >= 6.0 {
        1.0
    } else {
        // Fast polynomial/rational evaluation of sigmoid (0.5 + 0.5 * x / (1 + |x|))
        // which avoids expensive transcendental exp() function calls.
        0.5 + 0.5 * x / (1.0 + x.abs())
    }
}

fn softmax(logits: &[f32; EXPERT_COUNT]) -> [f32; EXPERT_COUNT] {
    let max_logit = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mut exps = [0.0f32; EXPERT_COUNT];
    let mut sum = 0.0f32;
    for (idx, logit) in logits.iter().enumerate() {
        let value = (*logit - max_logit).exp();
        exps[idx] = value;
        sum += value;
    }
    for value in &mut exps {
        *value /= sum;
    }
    exps
}
