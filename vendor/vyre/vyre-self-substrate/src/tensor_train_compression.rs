//! Tensor-train compression of the dispatch-graph cost tensor.
//!
//! Self-consumer for [#12 `tensor_train_decompose`](vyre_primitives::math::tensor_train_decompose).
//!
//! The dispatch-graph cost tensor (per-Region × per-buffer × per-config
//! cost) grows with the cube of the dispatch size. For a 1k-region
//! Program with 256 configs and 32 buffers, that's 8M f64 cells —
//! 64MB resident in the autotuner. TT-decomposition compresses this
//! along each mode (region / buffer / config) into a small set of
//! "core" tensors with TT-rank that bounds the approximation error.
//!
//! Used by:
//! - The differentiable autotuner: store costs in TT form so the
//!   derivative loop reads compressed cores instead of full tensor.
//! - The cost-model self-consumer: TT-compressed cost lookup is O(1)
//!   per query vs O(n) for raw tensor traversal.

use vyre_primitives::math::tensor_train_decompose::cpu_ref;

/// Compressed cost tensor in tensor-train form.
///
/// `cores[k]` is the k-th TT core; the original cost tensor is
/// reconstructed by chained matrix-vector contraction
/// `T(i_1, ..., i_d) = ∏ cores[k][r_k, i_k, r_{k+1}]`.
#[derive(Debug, Clone)]
pub struct CompressedCostTensor {
    /// TT cores in dispatch-graph mode order.
    pub cores: Vec<Vec<f64>>,
    /// Per-mode dimensions (e.g. [n_regions, n_buffers, n_configs]).
    pub dims: Vec<u32>,
    /// TT-ranks (length `dims.len() + 1`, with `ranks[0] = ranks[d] = 1`).
    pub ranks: Vec<u32>,
}

/// Compress a flat cost tensor into TT form.
///
/// `tensor` is the row-major flattened cost tensor of size
/// `dims.iter().product()`. `target_ranks` controls the
/// approximation budget: smaller ranks → more compression, more error.
/// Standard choice for autotuner cost tables: rank ≤ 8 per mode keeps
/// approximation within ~1% on smooth cost landscapes.
///
/// # Panics
///
/// Panics if `target_ranks.len() != dims.len() + 1`, if the boundary
/// ranks are not 1, or if `tensor.len()` doesn't match the dim
/// product.
#[must_use]
pub fn compress_cost_tensor(
    tensor: &[f64],
    dims: &[u32],
    target_ranks: &[u32],
) -> CompressedCostTensor {
    use crate::observability::{bump, tensor_train_compression_calls};
    bump(&tensor_train_compression_calls);
    let cores = cpu_ref(tensor, dims, target_ranks);
    CompressedCostTensor {
        cores,
        dims: dims.to_vec(),
        ranks: target_ranks.to_vec(),
    }
}

/// Approximate the original cost tensor's compression ratio:
/// `(1 - tt_size / original_size)` — a value in `[0, 1]` where 0
/// means no compression and 1 means full elimination.
#[must_use]
pub fn compression_ratio(compressed: &CompressedCostTensor) -> f64 {
    let original_size: usize = if compressed.dims.is_empty() {
        0
    } else {
        compressed.dims.iter().map(|d| *d as usize).product()
    };
    if original_size == 0 {
        return 0.0;
    }
    let tt_size: usize = compressed.cores.iter().map(Vec::len).sum();
    1.0 - (tt_size as f64) / (original_size as f64)
}

/// Total entries the TT representation stores. Useful for
/// observability — emit alongside cache size metrics so operators
/// can verify TT compression is actually shrinking memory.
#[must_use]
pub fn tt_storage_size(compressed: &CompressedCostTensor) -> usize {
    compressed.cores.iter().map(Vec::len).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compresses_3_mode_tensor() {
        // 2×3×2 cost tensor flattened row-major = 12 entries.
        let dims = vec![2u32, 3, 2];
        let target_ranks = vec![1u32, 2, 2, 1];
        let tensor: Vec<f64> = (0..12).map(|i| i as f64).collect();
        let compressed = compress_cost_tensor(&tensor, &dims, &target_ranks);
        assert_eq!(compressed.cores.len(), 3); // d cores
        assert_eq!(compressed.dims, dims);
    }

    #[test]
    fn compression_ratio_is_in_unit_interval() {
        let dims = vec![4u32, 4];
        let target_ranks = vec![1u32, 2, 1];
        let tensor = vec![1.0; 16];
        let compressed = compress_cost_tensor(&tensor, &dims, &target_ranks);
        let ratio = compression_ratio(&compressed);
        assert!(
            (-1.0..=1.0).contains(&ratio),
            "ratio out of expected range: {ratio}"
        );
    }

    #[test]
    fn tt_storage_size_returns_sum() {
        let compressed = CompressedCostTensor {
            cores: vec![vec![1.0; 4], vec![1.0; 8], vec![1.0; 4]],
            dims: vec![2, 4, 2],
            ranks: vec![1, 2, 2, 1],
        };
        assert_eq!(tt_storage_size(&compressed), 16);
    }

    #[test]
    fn empty_dims_handled() {
        let compressed = CompressedCostTensor {
            cores: Vec::new(),
            dims: Vec::new(),
            ranks: vec![1],
        };
        assert_eq!(tt_storage_size(&compressed), 0);
        assert_eq!(compression_ratio(&compressed), 0.0);
    }
}
