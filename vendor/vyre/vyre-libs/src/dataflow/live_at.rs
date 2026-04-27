//! `live_at` — liveness query: is variable `v` live at node `n`?
//!
//! A variable is live at `n` iff there exists a use of `v` reachable
//! from `n` along the CFG without an intervening def. Composes the
//! per-variable use set with backward reachability over the CFG,
//! killing on def sites.

use vyre::ir::Program;
use vyre_primitives::bitset::and::bitset_and;
use vyre_primitives::graph::csr_forward_traverse::bitset_words;

pub(crate) const OP_ID: &str = "vyre-libs::dataflow::live_at";

/// Build a live-at Program.
///
/// Inputs:
/// - `live_in_buf`: per-node bitset where bit `n` is set iff `v` is
///                  live at the entry of `n` (host-supplied via
///                  classical liveness analysis).
/// - `query_set`:   per-node bitset of node ids being queried.
/// - `out`:         per-node bitset; bit `n` set iff `n` ∈ query_set
///                  AND `v` is live at `n`.
#[must_use]
pub fn live_at(node_count: u32, live_in_buf: &str, query_set: &str, out: &str) -> Program {
    let words = bitset_words(node_count);
    crate::region::tag_program(OP_ID, bitset_and(live_in_buf, query_set, out, words))
}

/// CPU oracle.
#[must_use]
pub fn cpu_ref(live_in: &[u32], query_set: &[u32]) -> Vec<u32> {
    vyre_primitives::bitset::and::cpu_ref(live_in, query_set)
}

/// Soundness marker for [`live_at`].
pub struct LiveAt;
impl super::soundness::SoundnessTagged for LiveAt {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::Exact
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_query_returns_intersection() {
        assert_eq!(cpu_ref(&[0b1100], &[0b1010]), vec![0b1000]);
    }

    #[test]
    fn dead_at_query_returns_zero() {
        assert_eq!(cpu_ref(&[0b0001], &[0b1110]), vec![0]);
    }

    #[test]
    fn empty_query_yields_empty() {
        assert_eq!(cpu_ref(&[0xFFFF], &[0]), vec![0]);
    }

    #[test]
    fn fully_live_in_query_propagates() {
        assert_eq!(cpu_ref(&[0xFFFF], &[0x00FF]), vec![0x00FF]);
    }
}
