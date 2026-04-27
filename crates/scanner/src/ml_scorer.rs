//! ML-based secret scoring with a tiny mixture-of-experts network.
//!
//! Architecture: gate Linear(41,6) → Softmax plus 6 experts of
//! Linear(41,32) → ReLU → Linear(32,16) → ReLU → Linear(16,1), then
//! a weighted logit sum followed by Sigmoid. Model weights are embedded in
//! `ml_weights.rs` as little-endian f32 values.
//! Inference: typically under ~100μs per prediction on the test hardware
//!
//! The 41 input features capture everything our heuristics know:
//! length, entropy, char diversity, known prefixes, context keywords,
//! placeholder patterns, structural signals, and coarse file-type cues.

#[path = "ml_weights.rs"]
pub(crate) mod ml_weights;

use std::cell::RefCell;

#[path = "ml_features.rs"]
mod ml_features;
pub(crate) use ml_features::compute_features_with_config;
pub use ml_features::{compute_features_public, NUM_FEATURES};

/// Number of mixture-of-experts specialists. Each expert sees the same input
/// but learns different aspects (one may specialize in cloud credentials,
/// another in short API keys, etc.). 6 experts balance capacity vs. inference
/// cost, trained via grid search over {4, 6, 8, 12}.
const EXPERT_COUNT: usize = 6;
const EXPERT_HIDDEN_LAYER_1: usize = 32;
const EXPERT_HIDDEN_LAYER_2: usize = 16;

/// Score a candidate secret and its surrounding context using default (empty) heuristic lists.
pub fn score(text: &str, context: &str) -> f64 {
    score_with_config(text, context, &[], &[], &[], &[])
}

/// Score a candidate secret and its surrounding context with provided heuristic lists.
pub fn score_with_config(
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
        // FNV-1a keyed cache — ~100x faster than SHA-256 for cache lookups.
        // 256-entry bounded cache covers batch scoring of one file's matches.
        static SCORE_CACHE: RefCell<std::collections::HashMap<u64, f64>> =
            RefCell::new(std::collections::HashMap::with_capacity(64));
    }

    // FNV-1a hash of text + separator + context
    let cache_key = {
        let mut hash: u64 = 0xcbf29ce484222325;
        for &byte in text.as_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash ^= 0; // separator
        hash = hash.wrapping_mul(0x100000001b3);
        for &byte in context.as_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
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

/// Return the embedded model version string for diagnostics and CLI output.
pub fn model_version() -> &'static str {
    ml_weights::MODEL_VERSION
}

/// Forward pass through the MoE model with hardcoded weights.
fn forward_pass(input: &[f32; NUM_FEATURES]) -> f32 {
    let gate_probs = softmax(&compute_gate_logits(input));
    let mut score_logit = 0.0f32;
    for (expert_idx, gate_prob) in gate_probs.iter().enumerate() {
        score_logit += *gate_prob * expert_logit(expert_idx, input);
    }
    sigmoid(score_logit)
}

fn compute_gate_logits(input: &[f32; NUM_FEATURES]) -> [f32; EXPERT_COUNT] {
    let gate_weight = ml_weights::gate_weight();
    let gate_bias = ml_weights::gate_bias();
    debug_assert_eq!(gate_weight.len(), NUM_FEATURES * EXPERT_COUNT);
    debug_assert_eq!(gate_bias.len(), EXPERT_COUNT);

    let mut gate_logits = [0.0f32; EXPERT_COUNT];
    for (expert_idx, logit) in gate_logits.iter_mut().enumerate() {
        let row = &gate_weight[expert_idx * NUM_FEATURES..(expert_idx + 1) * NUM_FEATURES];
        *logit = dense_row(row, input, gate_bias[expert_idx]);
    }
    gate_logits
}

fn expert_logit(expert_idx: usize, input: &[f32; NUM_FEATURES]) -> f32 {
    let h1 = dense_relu_layer::<NUM_FEATURES, EXPERT_HIDDEN_LAYER_1>(
        ml_weights::expert_fc1_weight(expert_idx),
        ml_weights::expert_fc1_bias(expert_idx),
        input,
    );
    let h2 = dense_relu_layer::<EXPERT_HIDDEN_LAYER_1, EXPERT_HIDDEN_LAYER_2>(
        ml_weights::expert_fc2_weight(expert_idx),
        ml_weights::expert_fc2_bias(expert_idx),
        &h1,
    );
    dense_row(
        ml_weights::expert_fc3_weight(expert_idx),
        &h2,
        ml_weights::expert_fc3_bias(expert_idx)[0],
    )
}

fn dense_relu_layer<const INPUT: usize, const OUTPUT: usize>(
    weights: &[f32],
    bias: &[f32],
    input: &[f32; INPUT],
) -> [f32; OUTPUT] {
    let mut hidden = [0.0f32; OUTPUT];
    for (index, slot) in hidden.iter_mut().enumerate() {
        let row = &weights[index * INPUT..(index + 1) * INPUT];
        *slot = dense_row(row, input, bias[index]).max(0.0);
    }
    hidden
}

fn dense_row<const INPUT: usize>(weights: &[f32], input: &[f32; INPUT], bias: f32) -> f32 {
    weights
        .iter()
        .zip(input.iter())
        .fold(bias, |sum, (weight, input_value)| {
            sum + (*input_value * *weight)
        })
}

fn sigmoid(value: f32) -> f32 {
    1.0 / (1.0 + (-value).exp())
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
