//! Differentiable autotuner via #7 differentiable softmax / argmax (#27).
//!
//! Picks workgroup-size / tile-shape / fusion-threshold via gradient
//! descent over a smoothed argmax of cost-model scores. Same softmax
//! primitive that user attention dialects use; here it picks the
//! best dispatch configuration.

use vyre_primitives::math::differentiable::{differentiable_argmax_cpu_into, softmax_cpu_into};

/// Soft-pick the best configuration index given per-config cost
/// scores (lower cost = better). Returns probabilities that sum to 1;
/// at low temperature the argmax dominates.
#[must_use]
pub fn pick_config(costs: &[f64], temperature: f64) -> Vec<f64> {
    let mut neg_costs = Vec::new();
    let mut scaled = Vec::new();
    let mut out = Vec::new();
    pick_config_into(costs, temperature, &mut neg_costs, &mut scaled, &mut out);
    out
}

/// Soft-pick into caller-owned scratch and probability buffers.
pub fn pick_config_into(
    costs: &[f64],
    temperature: f64,
    neg_costs: &mut Vec<f64>,
    scaled: &mut Vec<f64>,
    out: &mut Vec<f64>,
) {
    use crate::observability::{bump, differentiable_autotune_calls};
    bump(&differentiable_autotune_calls);
    // Negate costs so higher input = better config.
    neg_costs.clear();
    neg_costs.reserve(costs.len());
    neg_costs.extend(costs.iter().map(|&c| -c));
    differentiable_argmax_cpu_into(neg_costs, temperature, scaled, out);
}

/// Hard pick the best configuration: take the argmax of cost scores.
#[must_use]
pub fn pick_best_config(costs: &[f64]) -> usize {
    assert!(
        !costs.is_empty(),
        "Fix: pick_best_config requires at least one candidate."
    );
    let mut best = 0usize;
    let mut best_cost = costs[0];
    for (i, &cost) in costs.iter().enumerate().skip(1) {
        if cost.total_cmp(&best_cost).is_lt() {
            best = i;
            best_cost = cost;
        }
    }
    best
}

/// Compute the gradient of the soft-picked cost w.r.t. each config
/// score. Useful for end-to-end training with the cost model. The
/// `temperature` parameter scales softmax sharpness; lower → gradient
/// concentrates on the argmin.
#[must_use]
pub fn config_gradient(costs: &[f64], temperature: f64) -> Vec<f64> {
    let mut neg_costs = Vec::new();
    let mut out = Vec::new();
    config_gradient_into(costs, temperature, &mut neg_costs, &mut out);
    out
}

/// Compute the config-score gradient into caller-owned storage.
pub fn config_gradient_into(
    costs: &[f64],
    temperature: f64,
    neg_costs: &mut Vec<f64>,
    out: &mut Vec<f64>,
) {
    assert!(temperature > 0.0, "temperature must be positive");
    // d softmax / d cost_i = -softmax_i (since costs are negated).
    neg_costs.clear();
    neg_costs.reserve(costs.len());
    neg_costs.extend(costs.iter().map(|&c| -c / temperature));
    softmax_cpu_into(neg_costs, out);
    for value in out.iter_mut() {
        *value = -*value;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-4 * (1.0 + a.abs() + b.abs())
    }

    #[test]
    fn pick_best_config_returns_minimum_cost_idx() {
        let costs = vec![3.0, 1.0, 4.0, 1.5, 9.0];
        assert_eq!(pick_best_config(&costs), 1); // cost 1.0
    }

    #[test]
    fn pick_config_low_temp_concentrates_on_best() {
        let costs = vec![5.0, 1.0, 5.0];
        let probs = pick_config(&costs, 0.01);
        assert!(probs[1] > 0.99);
        assert!(probs[0] < 0.01);
        assert!(probs[2] < 0.01);
    }

    #[test]
    fn pick_config_high_temp_uniform() {
        let costs = vec![1.0, 5.0, 9.0];
        let probs = pick_config(&costs, 1000.0);
        // High temperature flattens the distribution near uniform.
        // Tolerance loosened: cost spread/temperature is small, but
        // not zero, so probs ≈ 1/3 ± O(0.01).
        for p in probs {
            assert!((p - 1.0 / 3.0).abs() < 0.01);
        }
    }

    #[test]
    fn pick_config_into_reuses_buffers() {
        let costs = vec![5.0, 1.0, 5.0];
        let mut scratch = Vec::with_capacity(8);
        let mut scaled = Vec::with_capacity(8);
        let mut out = Vec::with_capacity(8);
        let scratch_ptr = scratch.as_ptr();
        let scaled_ptr = scaled.as_ptr();
        let out_ptr = out.as_ptr();
        pick_config_into(&costs, 0.01, &mut scratch, &mut scaled, &mut out);
        assert!(out[1] > 0.99);
        assert_eq!(scratch.as_ptr(), scratch_ptr);
        assert_eq!(scaled.as_ptr(), scaled_ptr);
        assert_eq!(out.as_ptr(), out_ptr);
    }

    #[test]
    fn config_gradient_sum_is_negative_one() {
        let costs = vec![1.0, 2.0, 3.0];
        let grads = config_gradient(&costs, 1.0);
        let total: f64 = grads.iter().sum();
        assert!(approx_eq(total, -1.0)); // -Σ softmax = -1
    }

    #[test]
    fn config_gradient_into_reuses_buffers() {
        let costs = vec![1.0, 2.0, 3.0];
        let mut scratch = Vec::with_capacity(8);
        let mut out = Vec::with_capacity(8);
        let scratch_ptr = scratch.as_ptr();
        let out_ptr = out.as_ptr();
        config_gradient_into(&costs, 1.0, &mut scratch, &mut out);
        let total: f64 = out.iter().sum();
        assert!(approx_eq(total, -1.0));
        assert_eq!(scratch.as_ptr(), scratch_ptr);
        assert_eq!(out.as_ptr(), out_ptr);
    }
}
