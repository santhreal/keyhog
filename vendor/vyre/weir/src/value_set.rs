//! `value_set` — constant-value set: enumerate constants reachable
//! to a node. Used by surgec rules for "magic-number reaches sink"
//! patterns.

use vyre::ir::Program;
use vyre_primitives::bitset::and::bitset_and;
use vyre_primitives::graph::csr_forward_traverse::bitset_words;

pub(crate) const OP_ID: &str = "weir::value_set";

/// Build a value-set query Program.
///
/// Inputs:
/// - `const_in_buf`: per-node bitset where bit `n` is set iff some
///                   constant value reaches the entry of `n`
///                   (host-supplied via constant propagation).
/// - `query_set`:    per-node bitset of nodes being queried.
/// - `out`:          per-node bitset; bit `n` set iff `n` is in
///                   `query_set` AND has a reaching constant.
#[must_use]
pub fn value_set(node_count: u32, const_in_buf: &str, query_set: &str, out: &str) -> Program {
    let words = bitset_words(node_count);
    vyre_harness::region::tag_program(OP_ID, bitset_and(const_in_buf, query_set, out, words))
}

/// CPU oracle.
#[must_use]
pub fn cpu_ref(const_in: &[u32], query_set: &[u32]) -> Vec<u32> {
    vyre_primitives::bitset::and::cpu_ref(const_in, query_set)
}

/// Soundness marker for [`value_set`].
pub struct ValueSet;
impl super::soundness::SoundnessTagged for ValueSet {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::MayOver
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_reach_query() {
        assert_eq!(cpu_ref(&[0b1111], &[0b0011]), vec![0b0011]);
    }

    #[test]
    fn no_constants_yields_empty() {
        assert_eq!(cpu_ref(&[0], &[0xFFFF]), vec![0]);
    }

    #[test]
    fn empty_query_yields_empty() {
        assert_eq!(cpu_ref(&[0xFFFF], &[0]), vec![0]);
    }

    #[test]
    fn distributes_over_words() {
        let r = cpu_ref(&[0xFF00, 0x00FF], &[0x0FF0, 0x0FF0]);
        assert_eq!(r, vec![0x0F00, 0x00F0]);
    }
}
