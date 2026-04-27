//! `control_dependence` — does `b` execute on every path through `a`?
//!
//! Equivalent: `b` is control-dependent on `a` iff `a` does NOT
//! post-dominate `b` AND `a` post-dominates SOME successor of `b`.
//! Encoded as a per-node bitset surgec rules can intersect with
//! sink sets for "guarded vs unguarded" analysis.

use vyre::ir::Program;
use vyre_primitives::bitset::and_not::bitset_and_not;
use vyre_primitives::graph::csr_forward_traverse::bitset_words;

pub(crate) const OP_ID: &str = "vyre-libs::dataflow::control_dependence";

/// Build a control-dependence query Program. Inputs:
/// - `successor_pdom`: per-node bitset where bit `n` is set iff `a`
///                     post-dominates a successor of `n`.
/// - `pdom_n`:         per-node bitset of nodes `a` post-dominates.
/// - `out`:            per-node bitset; bit `n` set iff `n` is
///                     control-dependent on `a` (= `successor_pdom`
///                     AND NOT `pdom_n`).
#[must_use]
pub fn control_dependence(
    node_count: u32,
    successor_pdom: &str,
    pdom_n: &str,
    out: &str,
) -> Program {
    let words = bitset_words(node_count);
    crate::region::tag_program(OP_ID, bitset_and_not(successor_pdom, pdom_n, out, words))
}

/// CPU oracle.
#[must_use]
pub fn cpu_ref(successor_pdom: &[u32], pdom_n: &[u32]) -> Vec<u32> {
    vyre_primitives::bitset::and_not::cpu_ref(successor_pdom, pdom_n)
}

/// Soundness marker for [`control_dependence`].
pub struct ControlDependence;
impl super::soundness::SoundnessTagged for ControlDependence {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::Exact
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classical_control_dep() {
        // succ_pdom = bits 0-3 (a post-dominates a successor of each),
        // pdom_n = bit 0 (a post-dominates n=0). Result: bits 1-3.
        assert_eq!(cpu_ref(&[0b1111], &[0b0001]), vec![0b1110]);
    }

    #[test]
    fn full_pdom_means_no_control_dep() {
        assert_eq!(cpu_ref(&[0xFFFF], &[0xFFFF]), vec![0]);
    }

    #[test]
    fn no_pdom_gives_full_control_dep() {
        assert_eq!(cpu_ref(&[0xFFFF], &[0]), vec![0xFFFF]);
    }

    #[test]
    fn empty_succ_pdom_yields_empty() {
        assert_eq!(cpu_ref(&[0], &[0xFFFF]), vec![0]);
    }
}
