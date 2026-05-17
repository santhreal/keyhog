//! Region-graph dominance-frontier substrate consumer.
//!
//! Wires `vyre_primitives::graph::dominator_frontier::cpu_ref` (zero
//! consumers prior) into the dispatch path. The dominator tree of a
//! Region graph identifies which Region's writes a Region depends on;
//! the dominance frontier of a Region set tells the optimizer where
//! phi-style merges (or vyre's analogue: per-Region buffer reconcile)
//! must run.
//!
//! # The self-use
//!
//! Vyre's optimizer needs to know, for any seed set of Regions, the
//! Regions where their effects MUST be reconciled. The classic SSA
//! answer is the dominance frontier: where two paths from the seed
//! merge into a node not strictly dominated by any seed. Same query,
//! same primitive, different IR.
//!
//! # Composition
//!
//! [`compute_dominance_frontier`] takes CSR-encoded dominance closure,
//! predecessor lists, and a seed bitset, and returns the frontier
//! bitset. The CSR encoding matches the primitive's contract exactly,
//! so the substrate call is a one-liner that bumps the observability
//! counter and forwards.

use vyre_primitives::graph::dominator_frontier::cpu_ref as dominator_frontier_cpu;

/// Compute the dominance frontier for `seed` over the Region graph
/// described by the CSR dominance closure (`dom_offsets`/`dom_targets`,
/// row `n` = every Region dominated by `n` including `n`) and the CSR
/// predecessor list (`pred_offsets`/`pred_targets`, row `m` = Regions
/// with an edge into `m`). `seed` is the packed-u32 bitset of selected
/// nodes; `node_count` matches the bitset width.
///
/// Returns the frontier bitset: the set of Regions where seed
/// influence must be reconciled. Bumps the substrate-call counter so
/// observability dashboards can see the dispatch is exercising the
/// primitive.
#[must_use]
pub fn compute_dominance_frontier(
    node_count: u32,
    dom_offsets: &[u32],
    dom_targets: &[u32],
    pred_offsets: &[u32],
    pred_targets: &[u32],
    seed: &[u32],
) -> Vec<u32> {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    dominator_frontier_cpu(
        node_count,
        dom_offsets,
        dom_targets,
        pred_offsets,
        pred_targets,
        seed,
    )
}

/// Number of Regions flagged in the frontier bitset. Useful as a
/// dispatch-time telemetry value: a high frontier count on a small
/// seed indicates a wide-merge program shape that fusion passes
/// should leave alone.
#[must_use]
pub fn frontier_size(frontier: &[u32]) -> u32 {
    frontier.iter().map(|w| w.count_ones()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Linear chain 0 -> 1 -> 2 -> 3. Dominance closure: each node
    /// dominates itself and every successor. Predecessors: each
    /// non-zero node has the previous as its sole pred.
    /// Seed = {0}. Expected frontier: empty (every dominator
    /// strictly dominates the merge candidate).
    #[test]
    fn frontier_of_linear_chain_is_empty() {
        // dom CSR: row 0 = {0,1,2,3}; row 1 = {1,2,3}; row 2 = {2,3}; row 3 = {3}
        let dom_offsets = vec![0, 4, 7, 9, 10];
        let dom_targets = vec![0, 1, 2, 3, 1, 2, 3, 2, 3, 3];
        // pred CSR: row 0 = {}; row 1 = {0}; row 2 = {1}; row 3 = {2}
        let pred_offsets = vec![0, 0, 1, 2, 3];
        let pred_targets = vec![0, 1, 2];
        let seed = vec![0b0001];
        let frontier = compute_dominance_frontier(
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &seed,
        );
        assert_eq!(frontier, vec![0u32]);
        assert_eq!(frontier_size(&frontier), 0);
    }

    /// Diamond: 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3.
    /// Dominators: 0 dominates {0,1,2,3}; 1,2 dominate themselves;
    /// 3 dominates itself.
    /// Seed = {1}: 1 dominates a predecessor of 3 (itself), but does
    /// not strictly dominate 3 (0 does, not 1). So frontier = {3}.
    #[test]
    fn frontier_of_diamond_seed_is_merge_node() {
        // dom CSR: 0 -> {0,1,2,3}; 1 -> {1}; 2 -> {2}; 3 -> {3}
        let dom_offsets = vec![0, 4, 5, 6, 7];
        let dom_targets = vec![0, 1, 2, 3, 1, 2, 3];
        // pred CSR: 0 -> {}; 1 -> {0}; 2 -> {0}; 3 -> {1, 2}
        let pred_offsets = vec![0, 0, 1, 2, 4];
        let pred_targets = vec![0, 0, 1, 2];
        let seed = vec![0b0010]; // {1}
        let frontier = compute_dominance_frontier(
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &seed,
        );
        // Expect node 3 in the frontier.
        assert_eq!(frontier, vec![0b1000]);
        assert_eq!(frontier_size(&frontier), 1);
    }

    /// Closure-bar: substrate consumer must produce the same bitset
    /// as a direct primitive call. If the wiring drifts, this
    /// fails before any downstream consumer sees stale frontiers.
    #[test]
    fn matches_primitive_directly() {
        let dom_offsets = vec![0, 4, 5, 6, 7];
        let dom_targets = vec![0, 1, 2, 3, 1, 2, 3];
        let pred_offsets = vec![0, 0, 1, 2, 4];
        let pred_targets = vec![0, 0, 1, 2];
        let seed = vec![0b0011];
        let via_substrate = compute_dominance_frontier(
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &seed,
        );
        let via_primitive = dominator_frontier_cpu(
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &seed,
        );
        assert_eq!(via_substrate, via_primitive);
    }

    /// Adversarial: empty seed must yield an empty frontier. A naive
    /// implementation that ignores the seed bit and walks every
    /// Region would mark the entire bitset.
    #[test]
    fn empty_seed_yields_empty_frontier() {
        let dom_offsets = vec![0, 4, 5, 6, 7];
        let dom_targets = vec![0, 1, 2, 3, 1, 2, 3];
        let pred_offsets = vec![0, 0, 1, 2, 4];
        let pred_targets = vec![0, 0, 1, 2];
        let seed = vec![0u32];
        let frontier = compute_dominance_frontier(
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &seed,
        );
        assert_eq!(frontier, vec![0u32]);
        assert_eq!(frontier_size(&frontier), 0);
    }

    /// Adversarial: seed that strictly dominates the entire graph
    /// must NOT include any node in its frontier (a node n is in
    /// the frontier of seed s only if s does NOT strictly dominate
    /// n).
    #[test]
    fn seed_dominating_everything_has_empty_frontier() {
        // 0 dominates {0,1,2,3}. Seed = {0} -> frontier should be {}.
        let dom_offsets = vec![0, 4, 5, 6, 7];
        let dom_targets = vec![0, 1, 2, 3, 1, 2, 3];
        let pred_offsets = vec![0, 0, 1, 2, 4];
        let pred_targets = vec![0, 0, 1, 2];
        let seed = vec![0b0001];
        let frontier = compute_dominance_frontier(
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &seed,
        );
        assert_eq!(frontier, vec![0u32]);
    }

    /// frontier_size must return the popcount of the bitset.
    #[test]
    fn frontier_size_counts_set_bits() {
        assert_eq!(frontier_size(&[0u32]), 0);
        assert_eq!(frontier_size(&[0b1011u32]), 3);
        assert_eq!(frontier_size(&[0xFFFFFFFFu32, 0b1u32]), 33);
    }
}
