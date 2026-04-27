//! `dominator_frontier` — query the dominance frontier of a node
//! set, packed as a per-node bitset.
//!
//! The dominance frontier of node `n` is the set of nodes `m` such
//! that `n` dominates a predecessor of `m` but does NOT dominate `m`
//! itself. SSA phi placement uses this directly; surgec rules can
//! reach for it via the `vyre.graph.dominator_frontier.v1` ExternCall.
//!
//! Soundness: exact when the supplied dominator-tree CSR is
//! correctly computed (the caller is responsible for that — usually
//! via `vyre-libs::dataflow::ssa::compute_dominators`).

use vyre_foundation::ir::Program;

use crate::graph::csr_forward_traverse::{bitset_words, csr_forward_traverse};
use crate::graph::program_graph::ProgramGraphShape;

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::graph::dominator_frontier";

/// One BFS step over CFG predecessors that are not in the dominator
/// set. Caller iterates until fixpoint.
#[must_use]
pub fn dominator_frontier(shape: ProgramGraphShape, seed: &str, out: &str) -> Program {
    csr_forward_traverse(shape, seed, out, 0xFFFF_FFFF)
}

/// CPU oracle: returns the dominance-frontier bitset for the seed set.
///
/// `dom_offsets` / `dom_targets` encode the dominance closure by dominator:
/// row `n` contains every node dominated by `n`, including `n`.
#[must_use]
pub fn cpu_ref(
    node_count: u32,
    dom_offsets: &[u32],
    dom_targets: &[u32],
    pred_offsets: &[u32],
    pred_targets: &[u32],
    seed: &[u32],
) -> Vec<u32> {
    let words = bitset_words(node_count) as usize;
    let mut frontier = vec![0u32; words];
    for n in 0..node_count {
        let n_word = (n / 32) as usize;
        let n_bit = 1u32 << (n % 32);
        if seed.get(n_word).copied().unwrap_or(0) & n_bit == 0 {
            continue;
        }
        for m in 0..node_count {
            let pred_start = pred_offsets.get(m as usize).copied().unwrap_or(0) as usize;
            let pred_end = pred_offsets
                .get(m as usize + 1)
                .copied()
                .unwrap_or(pred_start as u32) as usize;
            let dominates_a_predecessor = pred_targets[pred_start..pred_end]
                .iter()
                .copied()
                .any(|pred| dominates(dom_offsets, dom_targets, n, pred));
            let strictly_dominates_m = n != m && dominates(dom_offsets, dom_targets, n, m);
            if dominates_a_predecessor && !strictly_dominates_m {
                let m_word = (m / 32) as usize;
                let m_bit = 1u32 << (m % 32);
                frontier[m_word] |= m_bit;
            }
        }
    }
    frontier
}

fn dominates(dom_offsets: &[u32], dom_targets: &[u32], dominator: u32, node: u32) -> bool {
    let start = dom_offsets.get(dominator as usize).copied().unwrap_or(0) as usize;
    let end = dom_offsets
        .get(dominator as usize + 1)
        .copied()
        .unwrap_or(start as u32) as usize;
    dom_targets[start..end].contains(&node)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_seed_yields_empty_frontier() {
        let out = cpu_ref(4, &[0, 0, 0, 0, 0], &[], &[0, 0, 0, 0, 0], &[], &[0]);
        assert_eq!(out, vec![0]);
    }

    #[test]
    fn single_node_with_no_predecessors_has_empty_frontier() {
        // node 0 with no predecessors → df(0) = {}.
        let out = cpu_ref(2, &[0, 0, 0], &[], &[0, 0, 0], &[], &[0b01]);
        assert_eq!(out, vec![0]);
    }

    #[test]
    fn dom_frontier_picks_up_join_node() {
        // CFG: 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3.
        // Predecessors of 3: [1, 2]. 1 dominates itself only, 2 same.
        // df(1) includes 3 because 1 dominates predecessor 1 of 3,
        // but 1 does not dominate 3.
        let pred_offsets = vec![0u32, 0, 1, 2, 4];
        let pred_targets = vec![0u32, 0, 1, 2];
        // Dominator sets: 0 dominates {0,1,2,3}; 1 dominates {1};
        // 2 dominates {2}; 3 dominates {3}.
        let dom_offsets = vec![0u32, 4, 5, 6, 7];
        let dom_targets = vec![0u32, 1, 2, 3, 1, 2, 3];
        let out = cpu_ref(
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &[0b0010],
        );
        assert_eq!(out, vec![0b1000]);
    }

    #[test]
    fn out_of_range_seed_word_safe() {
        let out = cpu_ref(2, &[0, 0, 0], &[], &[0, 0, 0], &[], &[]);
        assert_eq!(out, vec![0]);
    }
}
