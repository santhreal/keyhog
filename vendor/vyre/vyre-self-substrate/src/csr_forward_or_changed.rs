//! In-place expand-with-change-flag substrate consumer.
//!
//! Wires `vyre_primitives::graph::csr_forward_or_changed::cpu_ref`
//! (zero prior consumers) so iterative dataflow loops can detect
//! convergence in a single pass: the primitive returns the next
//! frontier AND a boolean changed-flag. Used by reachability /
//! liveness / reaching-defs fixpoint passes that previously had to
//! diff before/after states by hand.

use vyre_primitives::graph::csr_forward_or_changed::{
    cpu_ref as csr_foc_cpu, cpu_ref_into as csr_foc_cpu_into,
};

/// Run one in-place forward-expand step over the CSR graph and
/// return both the new frontier and a 0/1 changed flag. The
/// primitive's contract: bits added to the frontier flip the flag;
/// no new bits → flag stays 0 → caller's fixpoint loop terminates.
///
/// Bumps the dataflow-fixpoint substrate counter so observability
/// logs every change-detection step.
#[must_use]
pub fn forward_step_with_change_flag(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier: &[u32],
    allow_mask: u32,
) -> (Vec<u32>, u32) {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    csr_foc_cpu(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier,
        allow_mask,
    )
}

/// Iterate `forward_step_with_change_flag` until the change flag
/// reads 0 or `max_iters` is reached. Returns the saturated
/// frontier.
///
/// This is the substrate path for "expand a Region set to its
/// forward-reachable closure" — the same fixpoint loop the
/// optimizer used to write by hand, now driven by the primitive's
/// own change flag.
#[must_use]
pub fn forward_closure_via_change_flag(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    seed: &[u32],
    allow_mask: u32,
    max_iters: u32,
) -> Vec<u32> {
    let mut current = seed.to_vec();
    let mut next = Vec::with_capacity(current.len());
    for _ in 0..max_iters {
        let changed = {
            use crate::observability::{bump, dataflow_fixpoint_calls};
            bump(&dataflow_fixpoint_calls);
            csr_foc_cpu_into(
                node_count,
                edge_offsets,
                edge_targets,
                edge_kind_mask,
                &current,
                allow_mask,
                &mut next,
            )
        };
        if changed == 0 {
            return next;
        }
        std::mem::swap(&mut current, &mut next);
    }
    current
}

/// Iterate `forward_step_with_change_flag` using caller-owned scratch.
#[allow(clippy::too_many_arguments)]
pub fn forward_closure_via_change_flag_into(
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
    for _ in 0..max_iters {
        let changed = {
            use crate::observability::{bump, dataflow_fixpoint_calls};
            bump(&dataflow_fixpoint_calls);
            csr_foc_cpu_into(
                node_count,
                edge_offsets,
                edge_targets,
                edge_kind_mask,
                current,
                allow_mask,
                next,
            )
        };
        if changed == 0 {
            std::mem::swap(current, next);
            return;
        }
        std::mem::swap(current, next);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linear_graph() -> (Vec<u32>, Vec<u32>, Vec<u32>) {
        // 0 -> 1 -> 2 -> 3
        (vec![0, 1, 2, 3, 3], vec![1, 2, 3], vec![1, 1, 1])
    }

    #[test]
    fn step_flips_change_flag_when_new_bits_added() {
        let (off, tgt, msk) = linear_graph();
        let (out, changed) =
            forward_step_with_change_flag(4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF);
        // Seed {0} expands to {0, 1}. New bit added → flag = 1.
        assert!(out[0] & 0b0010 != 0, "1 must be in expanded frontier");
        assert_eq!(changed, 1, "change flag must flip on new bit");
    }

    #[test]
    fn step_clears_change_flag_at_fixpoint() {
        let (off, tgt, msk) = linear_graph();
        // Saturated frontier: every node already set.
        let (_out, changed) =
            forward_step_with_change_flag(4, &off, &tgt, &msk, &[0b1111], 0xFFFF_FFFF);
        assert_eq!(changed, 0, "no new bits → flag stays 0");
    }

    /// Closure-bar: substrate output equals primitive output exactly.
    #[test]
    fn matches_primitive_directly() {
        let (off, tgt, msk) = linear_graph();
        let seed = vec![0b0001];
        let via_substrate = forward_step_with_change_flag(4, &off, &tgt, &msk, &seed, 0xFFFF_FFFF);
        let via_primitive = csr_foc_cpu(4, &off, &tgt, &msk, &seed, 0xFFFF_FFFF);
        assert_eq!(via_substrate, via_primitive);
    }

    /// forward_closure_via_change_flag terminates at fixpoint and
    /// returns the full forward closure. On a chain 0->1->2->3
    /// from {0} → final = {0,1,2,3}.
    #[test]
    fn closure_reaches_full_chain_via_change_flag() {
        let (off, tgt, msk) = linear_graph();
        let out = forward_closure_via_change_flag(4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF, 10);
        assert_eq!(out, vec![0b1111]);
    }

    /// Adversarial: empty seed must yield empty closure with flag 0
    /// on the first iteration (no work).
    #[test]
    fn empty_seed_yields_empty_closure_no_change() {
        let (off, tgt, msk) = linear_graph();
        let (out, changed) =
            forward_step_with_change_flag(4, &off, &tgt, &msk, &[0u32], 0xFFFF_FFFF);
        assert_eq!(out, vec![0u32]);
        assert_eq!(changed, 0);
    }

    /// Adversarial: closure must terminate before max_iters even on
    /// a graph with a self-loop (the change flag is the only
    /// termination signal we trust).
    #[test]
    fn closure_terminates_with_self_loop_under_max_iters() {
        // 0 -> 0 (self-loop), 1 isolated.
        let off = vec![0, 1, 1];
        let tgt = vec![0];
        let msk = vec![1];
        let out = forward_closure_via_change_flag(2, &off, &tgt, &msk, &[0b01], 0xFFFF_FFFF, 50);
        // Self-loop never adds new bits → terminates immediately.
        assert_eq!(out, vec![0b01]);
    }

    /// Adversarial: allow_mask filtering. Edges of the wrong kind
    /// must not propagate; the change flag must register no change.
    #[test]
    fn allow_mask_filters_step() {
        let off = vec![0, 1, 1];
        let tgt = vec![1];
        let msk = vec![0b0010]; // kind bit 1
        let (out, changed) = forward_step_with_change_flag(
            2,
            &off,
            &tgt,
            &msk,
            &[0b01],
            0b0001, // demand kind 0
        );
        // No matching edges → frontier unchanged from seed, no change.
        assert_eq!(out[0] & 0b10, 0);
        assert_eq!(changed, 0);
    }
}
