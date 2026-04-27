//! `scc_query` — strongly-connected-component membership query.
//!
//! Given the SCC label of every node (host-supplied via Tarjan or
//! the GPU SCC primitive), return the set of nodes belonging to the
//! same component as a query target. Used for cycle-detection rules
//! and recursion-aware static analysis.

use vyre::ir::Program;
use vyre_primitives::bitset::and::bitset_and;
use vyre_primitives::graph::csr_forward_traverse::bitset_words;

pub(crate) const OP_ID: &str = "vyre-libs::dataflow::scc_query";

/// Build an SCC-membership Program.
///
/// Inputs:
/// - `same_scc_buf`: per-node bitset where bit `m` is set iff `m`
///                   belongs to the SAME SCC as the query target
///                   (host-built from the SCC label vector).
/// - `query_set`:    per-node bitset of nodes being queried.
/// - `out`:          per-node bitset; bit `n` set iff `n` is in
///                   `query_set` AND in the same SCC as the target.
#[must_use]
pub fn scc_query(node_count: u32, same_scc_buf: &str, query_set: &str, out: &str) -> Program {
    let words = bitset_words(node_count);
    crate::region::tag_program(OP_ID, bitset_and(same_scc_buf, query_set, out, words))
}

/// CPU oracle.
#[must_use]
pub fn cpu_ref(same_scc: &[u32], query_set: &[u32]) -> Vec<u32> {
    vyre_primitives::bitset::and::cpu_ref(same_scc, query_set)
}

/// Soundness marker for [`scc_query`].
pub struct SccQuery;
impl super::soundness::SoundnessTagged for SccQuery {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::Exact
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_scc_query_intersects() {
        assert_eq!(cpu_ref(&[0b1100], &[0b1010]), vec![0b1000]);
    }

    #[test]
    fn no_match_yields_empty() {
        assert_eq!(cpu_ref(&[0b0011], &[0b1100]), vec![0]);
    }

    #[test]
    fn singleton_scc_self_match() {
        assert_eq!(cpu_ref(&[0b0001], &[0b0001]), vec![0b0001]);
    }

    #[test]
    fn distributes_per_word() {
        assert_eq!(
            cpu_ref(&[0xFF00, 0xF00F], &[0x0FF0, 0x0F0F]),
            vec![0x0F00, 0x000F]
        );
    }
}
