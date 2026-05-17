//! Multi-step BFS frontier expansion substrate consumer.
//!
//! Wires `vyre_primitives::graph::persistent_bfs::cpu_ref` (zero
//! prior consumers) so the optimizer can compute multi-step
//! reachability in a single primitive call instead of looping
//! `csr_forward_traverse` by hand. The primitive accumulates into
//! `frontier_out` via OR and reports a sticky changed-flag, so the
//! caller knows whether any new nodes were added across all steps.

use vyre_primitives::graph::persistent_bfs::cpu_ref as persistent_bfs_cpu;

/// Run up to `max_iters` BFS steps starting from `frontier_in`,
/// returning the saturated frontier and a sticky changed-flag (1 if
/// any iteration added new bits, 0 if the seed was already
/// saturated). Bumps the dataflow-fixpoint substrate counter.
#[must_use]
pub fn bfs_expand(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
    allow_mask: u32,
    max_iters: u32,
) -> (Vec<u32>, u32) {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    persistent_bfs_cpu(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
        allow_mask,
        max_iters,
    )
}

/// Convenience: compute the forward-reachable set of `seed` under
/// `allow_mask` with a generous iteration budget. Returns just the
/// frontier; callers wanting the changed-flag should use
/// [`bfs_expand`] directly.
#[must_use]
pub fn forward_reach(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    seed: &[u32],
    allow_mask: u32,
) -> Vec<u32> {
    let (out, _changed) = bfs_expand(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        seed,
        allow_mask,
        node_count,
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linear_graph() -> (Vec<u32>, Vec<u32>, Vec<u32>) {
        // 0 -> 1 -> 2 -> 3
        (vec![0, 1, 2, 3, 3], vec![1, 2, 3], vec![1, 1, 1])
    }

    #[test]
    fn expand_chain_saturates() {
        let (off, tgt, msk) = linear_graph();
        let (out, changed) = bfs_expand(4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF, 8);
        assert_eq!(out, vec![0b1111]);
        assert_eq!(changed, 1);
    }

    #[test]
    fn empty_seed_yields_empty_with_no_change() {
        let (off, tgt, msk) = linear_graph();
        let (out, changed) = bfs_expand(4, &off, &tgt, &msk, &[0u32], 0xFFFF_FFFF, 4);
        assert_eq!(out, vec![0u32]);
        assert_eq!(changed, 0);
    }

    #[test]
    fn saturated_seed_reports_no_change() {
        let (off, tgt, msk) = linear_graph();
        let (out, changed) = bfs_expand(4, &off, &tgt, &msk, &[0b1111], 0xFFFF_FFFF, 4);
        assert_eq!(out, vec![0b1111]);
        assert_eq!(changed, 0);
    }

    /// Closure-bar: substrate output equals primitive output exactly.
    #[test]
    fn matches_primitive_directly() {
        let (off, tgt, msk) = linear_graph();
        let seed = vec![0b0001];
        let via_substrate = bfs_expand(4, &off, &tgt, &msk, &seed, 0xFFFF_FFFF, 5);
        let via_primitive = persistent_bfs_cpu(4, &off, &tgt, &msk, &seed, 0xFFFF_FFFF, 5);
        assert_eq!(via_substrate, via_primitive);
    }

    /// Adversarial: max_iters bound is honored even on a chain
    /// longer than the budget. With 1 iter on a 4-chain from {0},
    /// only {0, 1} should be flagged (not the full chain).
    #[test]
    fn max_iters_bound_honored() {
        let (off, tgt, msk) = linear_graph();
        let (out, _) = bfs_expand(4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF, 1);
        assert_eq!(out[0] & 0b1111, 0b0011);
    }

    /// Adversarial: allow_mask with kind bit not present in any
    /// edge must report no change, no expansion.
    #[test]
    fn allow_mask_filters_all_edges() {
        let (off, tgt, msk) = linear_graph();
        let (out, changed) = bfs_expand(4, &off, &tgt, &msk, &[0b0001], 0b0010, 4);
        // No edges of kind 1 → seed only.
        assert_eq!(out, vec![0b0001]);
        assert_eq!(changed, 0);
    }

    /// forward_reach helper saturates with an n-iteration budget on
    /// a chain shorter than n.
    #[test]
    fn forward_reach_saturates_chain() {
        let (off, tgt, msk) = linear_graph();
        let out = forward_reach(4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF);
        assert_eq!(out, vec![0b1111]);
    }

    /// Adversarial: a self-loop must terminate (changed becomes 0
    /// once the seed includes the self-loop node).
    #[test]
    fn self_loop_terminates() {
        // 0 -> 0 (self-loop), 1 isolated.
        let off = vec![0, 1, 1];
        let tgt = vec![0];
        let msk = vec![1];
        let (out, _) = bfs_expand(2, &off, &tgt, &msk, &[0b01], 0xFFFF_FFFF, 50);
        assert_eq!(out, vec![0b01]);
    }
}
