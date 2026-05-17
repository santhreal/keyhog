//! Probabilistic dispatch cost model via #10 sum_product_circuit (#28).
//!
//! Models per-Program runtime as a probabilistic circuit. Calibrated
//! intervals come from #41 conformal prediction over historical
//! latency samples. Output feeds #22 megakernel scheduler as soft
//! constraints.

use vyre_primitives::graph::sum_product_circuit::sum_product_evaluate_cpu;
use vyre_primitives::math::conformal::conformal_threshold_cpu;

/// Predict expected runtime for a Program using a sum-product circuit
/// over its features. Returns (point_estimate, conformal_upper_bound).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn predict_runtime(
    feature_circuit_kinds: &[u32],
    feature_circuit_offsets: &[u32],
    feature_circuit_counts: &[u32],
    feature_circuit_children: &[u32],
    feature_circuit_weights: &[f64],
    feature_values: &[f64],
    historical_residuals: &[u32],
    alpha: f64,
) -> (f64, u32) {
    use crate::observability::{bump, cost_model_calls};
    bump(&cost_model_calls);
    let topo: Vec<u32> = (0..feature_circuit_kinds.len() as u32).collect();
    let result = sum_product_evaluate_cpu(
        feature_circuit_kinds,
        feature_circuit_offsets,
        feature_circuit_counts,
        feature_circuit_children,
        feature_circuit_weights,
        feature_values,
        &topo,
    );
    let point_estimate = *result.last().unwrap_or(&0.0);
    let upper_bound = conformal_threshold_cpu(historical_residuals, alpha);
    (point_estimate, upper_bound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_primitives::graph::sum_product_circuit::{KIND_LEAF, KIND_PRODUCT, KIND_SUM};

    #[test]
    fn predict_returns_point_plus_conformal_interval() {
        let kinds = vec![KIND_LEAF, KIND_LEAF, KIND_SUM];
        let offsets = vec![0, 0, 0];
        let counts = vec![0, 0, 2];
        let children = vec![0, 1];
        let weights = vec![0.5, 0.5];
        let values = vec![10.0, 20.0, 0.0];
        let residuals = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let (point, upper) = predict_runtime(
            &kinds, &offsets, &counts, &children, &weights, &values, &residuals, 0.1,
        );
        // 0.5·10 + 0.5·20 = 15
        assert!((point - 15.0).abs() < 1e-10);
        // Upper bound = 90th percentile of residuals = 10
        assert_eq!(upper, 10);
    }

    #[test]
    fn product_node_predict_works() {
        let kinds = vec![KIND_LEAF, KIND_LEAF, KIND_PRODUCT];
        let offsets = vec![0, 0, 0];
        let counts = vec![0, 0, 2];
        let children = vec![0, 1];
        let weights = vec![0.0, 0.0];
        let values = vec![3.0, 5.0, 0.0];
        let residuals = vec![1u32];
        let (point, _) = predict_runtime(
            &kinds, &offsets, &counts, &children, &weights, &values, &residuals, 0.5,
        );
        assert!((point - 15.0).abs() < 1e-10);
    }
}
