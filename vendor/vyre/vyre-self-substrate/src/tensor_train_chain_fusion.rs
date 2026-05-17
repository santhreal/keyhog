//! Tensor-train chain fusion analyzer (#6 substrate).
//!
//! Frames a sequence of Regions as a Tensor Train where:
//! - Each Region $R_i$ is a TT-core $G_i$.
//! - The bond dimension $r_i$ is the rank (element count) of the
//!   shared buffer between $R_i$ and $R_{i+1}$.
//! - The contraction $G_1 \cdot G_2 \cdot \dots \cdot G_n$ computes
//!   the "fusion pressure" or "total shared volume" across the chain.
//!
//! This module uses `vyre-primitives::math::tensor_train::tt_contract_step`
//! (the same Program shipped to users) to analyze Vyre's own IR.

use vyre_primitives::math::tensor_train::tt_contract_step_cpu;

/// Compute the "fusion pressure" of a chain of Regions connected by
/// shared buffers of the given ranks.
///
/// The pressure is modeled as a TT contraction of unit-cores. A small
/// pressure suggests a tight chain with low intermediate state, making
/// it an ideal candidate for fusion into a single kernel.
#[must_use]
pub fn fusion_pressure(shared_buffer_ranks: &[u32]) -> f64 {
    use crate::observability::{bump, tensor_train_chain_fusion_calls};
    bump(&tensor_train_chain_fusion_calls);
    if shared_buffer_ranks.is_empty() {
        return 0.0;
    }

    // Initial accumulator for r_0 = 1.
    let mut acc = vec![1.0];

    for &r_next in shared_buffer_ranks {
        let r_prev = acc.len() as u32;
        // Skip zero-rank buffers as they indicate no dataflow.
        if r_next == 0 {
            continue;
        }

        // Use a "unit core" - all ones.
        // acc_out[b] = Σ_a acc_in[a] · core[a, b] = Σ_a 1 · 1 = r_prev.
        // Result: acc_out is a vector of length r_next containing r_prev.
        let core_slice = vec![1.0; (r_prev * r_next) as usize];
        acc = tt_contract_step_cpu(&acc, &core_slice, r_prev, r_next);
    }

    // Final contraction to scalar (last bond is 1).
    let r_last = acc.len() as u32;
    let core_last = vec![1.0; r_last as usize];
    let result = tt_contract_step_cpu(&acc, &core_last, r_last, 1);

    result[0]
}

/// Decide whether to fuse a chain based on its TT fusion pressure.
///
/// A chain should be fused if its total intermediate volume (pressure)
/// is below the threshold relative to the number of regions.
#[must_use]
pub fn should_fuse_chain(shared_buffer_ranks: &[u32], threshold_per_link: f64) -> bool {
    if shared_buffer_ranks.is_empty() {
        return false;
    }
    let pressure = fusion_pressure(shared_buffer_ranks);
    let n = shared_buffer_ranks.len() as f64;
    // Logarithmic scale because TT contraction of unit cores is multiplicative.
    // log(r1 * r2 * ... * rn) = Σ log(ri)
    // We compare average log-rank against the threshold.
    let avg_log_rank = pressure.ln() / n;
    avg_log_rank <= threshold_per_link.ln()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-10 * (1.0 + a.abs() + b.abs())
    }

    #[test]
    fn pressure_of_single_link_is_rank() {
        let ranks = vec![64];
        assert!(approx_eq(fusion_pressure(&ranks), 64.0));
    }

    #[test]
    fn pressure_is_multiplicative_product() {
        // r0=1, r1=4, r2=8 -> result = 1 * 4 * 8 = 32.
        let ranks = vec![4, 8];
        assert!(approx_eq(fusion_pressure(&ranks), 32.0));
    }

    #[test]
    fn large_ranks_produce_high_pressure() {
        let ranks = vec![1024, 1024];
        assert!(approx_eq(fusion_pressure(&ranks), 1024.0 * 1024.0));
    }

    #[test]
    fn should_fuse_small_chain() {
        let ranks = vec![8, 8, 8];
        // ln(8*8*8)/3 = ln(8)
        assert!(should_fuse_chain(&ranks, 16.0));
        assert!(!should_fuse_chain(&ranks, 4.0));
    }

    #[test]
    fn parity_with_raw_product() {
        let ranks = vec![2, 3, 5, 7];
        let pressure = fusion_pressure(&ranks);
        let expected = (2 * 3 * 5 * 7) as f64;
        assert!(approx_eq(pressure, expected));
    }
}
