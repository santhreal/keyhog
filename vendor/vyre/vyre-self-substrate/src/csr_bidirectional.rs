//! Region-graph bidirectional one-step reach substrate consumer.
//!
//! Wires `vyre_primitives::graph::csr_bidirectional::cpu_ref` (zero
//! prior consumers) into the dispatch path. One bidirectional BFS
//! step is the right primitive when the optimizer wants the
//! "neighborhood" of a Region — both writers (predecessors) and
//! readers (successors) at once. Used by alias-class merging and
//! the buffer-residency planner.

use vyre_primitives::graph::csr_bidirectional::{
    cpu_ref as csr_bidir_cpu, cpu_ref_into as csr_bidir_cpu_into,
};

/// Compute one bidirectional BFS step over a CSR-encoded Region
/// graph: returns the bitset that includes every node reachable
/// in ≤1 forward edge OR ≤1 backward edge from `frontier_in`,
/// filtered by `allow_mask` over edge kinds.
///
/// `node_count` matches the bitset width; `edge_kind_mask` is
/// per-edge. Bumps the dataflow-fixpoint substrate counter so
/// observability picks up dispatch-time traffic.
#[must_use]
pub fn bidirectional_step(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
    allow_mask: u32,
) -> Vec<u32> {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    csr_bidir_cpu(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
        allow_mask,
    )
}

/// Iterate `bidirectional_step` to fixpoint or `max_iters`. Returns
/// the connected-neighborhood bitset of `seed` under `allow_mask`.
/// Useful for alias-class queries (which Regions touch the same
/// buffer set transitively).
#[must_use]
pub fn bidirectional_closure(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    seed: &[u32],
    allow_mask: u32,
    max_iters: u32,
) -> Vec<u32> {
    let mut current = Vec::new();
    let mut next = Vec::new();
    bidirectional_closure_into(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        seed,
        allow_mask,
        max_iters,
        &mut current,
        &mut next,
    );
    current
}

/// Iterate `bidirectional_step` to fixpoint using caller-owned buffers.
#[allow(clippy::too_many_arguments)]
pub fn bidirectional_closure_into(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    seed: &[u32],
    allow_mask: u32,
    max_iters: u32,
    current: &mut Vec<u32>,
    next: &mut Vec<u32>,
) {
    current.clear();
    current.extend_from_slice(seed);
    next.clear();
    for _ in 0..max_iters {
        {
            use crate::observability::{bump, dataflow_fixpoint_calls};
            bump(&dataflow_fixpoint_calls);
            csr_bidir_cpu_into(
                node_count,
                edge_offsets,
                edge_targets,
                edge_kind_mask,
                current,
                allow_mask,
                next,
            );
        }
        if !merge_or_changed(current, next) {
            return;
        }
    }
}

fn merge_or_changed(current: &mut [u32], next: &[u32]) -> bool {
    debug_assert_eq!(current.len(), next.len());
    let mut changed = false;
    for (dst, src) in current.iter_mut().zip(next.iter()) {
        let merged = *dst | *src;
        changed |= merged != *dst;
        *dst = merged;
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linear_graph() -> (Vec<u32>, Vec<u32>, Vec<u32>) {
        // 0 -> 1 -> 2 -> 3
        (vec![0, 1, 2, 3, 3], vec![1, 2, 3], vec![1, 1, 1])
    }

    #[test]
    fn step_includes_forward_and_backward_neighbors() {
        let (off, tgt, msk) = linear_graph();
        // Seed = {1}. Forward = {2}, backward = {0}. Union ⊇ {0, 2}.
        let out = bidirectional_step(4, &off, &tgt, &msk, &[0b0010], 0xFFFF_FFFF);
        assert!(out[0] & 0b0001 != 0, "0 should be in backward step from 1");
        assert!(out[0] & 0b0100 != 0, "2 should be in forward step from 1");
    }

    #[test]
    fn empty_seed_yields_empty_step() {
        let (off, tgt, msk) = linear_graph();
        let out = bidirectional_step(4, &off, &tgt, &msk, &[0u32], 0xFFFF_FFFF);
        assert_eq!(out, vec![0u32]);
    }

    /// Closure-bar: substrate call equals direct primitive call.
    #[test]
    fn matches_primitive_directly() {
        let (off, tgt, msk) = linear_graph();
        let seed = vec![0b0010];
        let via_substrate = bidirectional_step(4, &off, &tgt, &msk, &seed, 0xFFFF_FFFF);
        let via_primitive = csr_bidir_cpu(4, &off, &tgt, &msk, &seed, 0xFFFF_FFFF);
        assert_eq!(via_substrate, via_primitive);
    }

    /// Adversarial: kind-mask filter must reject edges whose kinds
    /// don't intersect `allow_mask`. The bidirectional step is a
    /// pure successor/predecessor union; with no matching edges,
    /// no neighbors are flagged (the primitive does not retain
    /// the seed in its output).
    #[test]
    fn allow_mask_filters_out_wrong_edge_kinds() {
        let off = vec![0, 1, 1];
        let tgt = vec![1];
        let msk = vec![0b0010]; // edge kind bit 1
        let out = bidirectional_step(2, &off, &tgt, &msk, &[0b01], 0b0001);
        let direct = csr_bidir_cpu(2, &off, &tgt, &msk, &[0b01], 0b0001);
        // Substrate output must match primitive directly.
        assert_eq!(out, direct);
        // And bit 1 (would-be neighbor via a kind-0 edge that doesn't
        // exist) must NOT be set in the result.
        assert_eq!(out[0] & 0b10, 0);
    }

    /// bidirectional_closure on a linear chain {0 -> 1 -> 2 -> 3} with
    /// seed {0} must reach every node within 3 iterations.
    #[test]
    fn closure_reaches_full_chain() {
        let (off, tgt, msk) = linear_graph();
        let out = bidirectional_closure(4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF, 5);
        assert_eq!(out, vec![0b1111]);
    }

    #[test]
    fn closure_into_matches_owned_closure() {
        let (off, tgt, msk) = linear_graph();
        let owned = bidirectional_closure(4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF, 5);
        let mut current = Vec::new();
        let mut next = Vec::new();
        bidirectional_closure_into(
            4,
            &off,
            &tgt,
            &msk,
            &[0b0001],
            0xFFFF_FFFF,
            5,
            &mut current,
            &mut next,
        );
        assert_eq!(current, owned);
    }

    /// Adversarial: closure on disjoint components must not bridge
    /// across components. Seed in component A must not flag B.
    #[test]
    fn closure_does_not_bridge_disjoint_components() {
        // Two-component CSR: 0 -> 1, 2 -> 3 (disjoint).
        let off = vec![0, 1, 1, 2, 2];
        let tgt = vec![1, 3];
        let msk = vec![1, 1];
        let out = bidirectional_closure(4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF, 5);
        // Reaches {0, 1} only.
        assert_eq!(out, vec![0b0011]);
    }

    /// Idempotence: running the step on a saturated bitset returns
    /// the same bitset.
    #[test]
    fn closure_is_idempotent_at_fixpoint() {
        let (off, tgt, msk) = linear_graph();
        let saturated = vec![0b1111];
        let out = bidirectional_step(4, &off, &tgt, &msk, &saturated, 0xFFFF_FFFF);
        // Bidirectional step from saturated set keeps everything set.
        assert_eq!(out, saturated);
    }
}
