//! Polyhedral / affine fusion via #1 semiring_gemm on the affine
//! dependency adjacency (#19 substrate).
//!
//! Treat affine-loop dependencies between Region children as a
//! sparse boolean matrix; closure under `Semiring::BoolOr` reveals
//! transitive dependencies. Fusion candidates = pairs (i, j) where
//! NEITHER reaches the other transitively (independent, fusable).
//!
//! Composes #26 reachability_closure for the transitive-closure step.

use super::dataflow_fixpoint::reachability_closure_into;

/// Reusable buffers for polyhedral fusion analysis.
#[derive(Debug, Default)]
pub struct PolyhedralFusionScratch {
    closure: Vec<u32>,
    next: Vec<u32>,
    mask: Vec<u32>,
}

impl PolyhedralFusionScratch {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn mask_ptr(&self) -> *const u32 {
        self.mask.as_ptr()
    }
}

/// Identify fusable Region pairs: pairs (i, j) with no transitive
/// dependency between them. Returns a flat `n × n` mask where `1`
/// means "fusable" and `0` means "ordering matters."
#[must_use]
pub fn fusable_pairs(adj: &[u32], n: u32, max_iters: u32) -> Vec<u32> {
    let mut scratch = PolyhedralFusionScratch::new();
    fusable_pairs_into(adj, n, max_iters, &mut scratch).to_vec()
}

/// Identify fusable Region pairs using caller-owned scratch.
#[must_use]
pub fn fusable_pairs_into<'a>(
    adj: &[u32],
    n: u32,
    max_iters: u32,
    scratch: &'a mut PolyhedralFusionScratch,
) -> &'a [u32] {
    use crate::observability::{bump, polyhedral_fusion_calls};
    bump(&polyhedral_fusion_calls);
    let n_us = n as usize;
    reachability_closure_into(adj, n, max_iters, &mut scratch.closure, &mut scratch.next);
    scratch.mask.clear();
    scratch.mask.resize(n_us * n_us, 0);
    for i in 0..n_us {
        for j in 0..n_us {
            if i == j {
                continue;
            }
            if scratch.closure[i * n_us + j] == 0 && scratch.closure[j * n_us + i] == 0 {
                scratch.mask[i * n_us + j] = 1;
            }
        }
    }
    &scratch.mask
}

/// Score a fusion: count how many child pairs are independently
/// fusable. Higher score = more fusion opportunities.
#[must_use]
pub fn fusion_score(adj: &[u32], n: u32, max_iters: u32) -> u32 {
    let mut scratch = PolyhedralFusionScratch::new();
    fusion_score_into(adj, n, max_iters, &mut scratch)
}

/// Score a fusion using caller-owned scratch.
#[must_use]
pub fn fusion_score_into(
    adj: &[u32],
    n: u32,
    max_iters: u32,
    scratch: &mut PolyhedralFusionScratch,
) -> u32 {
    let mask = fusable_pairs_into(adj, n, max_iters, scratch);
    mask.iter().sum()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::identity_op, clippy::erasing_op)]
    use super::*;

    #[test]
    fn fully_independent_regions_all_fusable() {
        // Three Regions, no edges → all pairs fusable.
        let adj = vec![0u32; 9];
        let mask = fusable_pairs(&adj, 3, 5);
        // Off-diagonal entries should all be 1.
        for i in 0..3 {
            for j in 0..3 {
                if i == j {
                    assert_eq!(mask[i * 3 + j], 0);
                } else {
                    assert_eq!(mask[i * 3 + j], 1);
                }
            }
        }
    }

    #[test]
    fn fully_dependent_chain_no_fusable_pairs() {
        // Chain 0 → 1 → 2: every pair has a directional dependency.
        let adj = vec![0, 1, 0, 0, 0, 1, 0, 0, 0];
        let mask = fusable_pairs(&adj, 3, 5);
        // No fusable pairs; all entries should be 0.
        for v in mask {
            assert_eq!(v, 0);
        }
    }

    #[test]
    fn fusion_score_disjoint_higher_than_chain() {
        let disjoint = vec![0u32; 9];
        let chain = vec![0, 1, 0, 0, 0, 1, 0, 0, 0];
        let score_disjoint = fusion_score(&disjoint, 3, 5);
        let score_chain = fusion_score(&chain, 3, 5);
        assert!(score_disjoint > score_chain);
        // Three regions, all 6 off-diagonal pairs fusable.
        assert_eq!(score_disjoint, 6);
        assert_eq!(score_chain, 0);
    }

    #[test]
    fn partial_dependency_partial_fusion() {
        // 0 → 1 only; 0 and 2 fusable, 1 and 2 fusable.
        let adj = vec![0, 1, 0, 0, 0, 0, 0, 0, 0];
        let mask = fusable_pairs(&adj, 3, 5);
        // Pairs: (0,1) ordered; (0,2) fusable; (1,2) fusable.
        assert_eq!(mask[0 * 3 + 1], 0); // 0 reaches 1
        assert_eq!(mask[1 * 3 + 0], 0); // symmetric block
        assert_eq!(mask[0 * 3 + 2], 1);
        assert_eq!(mask[2 * 3 + 0], 1);
        assert_eq!(mask[1 * 3 + 2], 1);
        assert_eq!(mask[2 * 3 + 1], 1);
    }

    #[test]
    fn fusable_pairs_into_reuses_mask_storage() {
        let adj = vec![0u32; 9];
        let mut scratch = PolyhedralFusionScratch::new();
        let first = fusable_pairs_into(&adj, 3, 5, &mut scratch).to_vec();
        let ptr = scratch.mask_ptr();
        let second = fusable_pairs_into(&adj, 3, 5, &mut scratch).to_vec();
        assert_eq!(first, second);
        assert_eq!(scratch.mask_ptr(), ptr);
        assert_eq!(fusion_score_into(&adj, 3, 5, &mut scratch), 6);
    }
}
