//! `post_dominates` — query the post-dominator tree.
//!
//! Per node `n` and target `t`, write 1 iff `n` post-dominates `t`
//! (every path from `t` to function exit goes through `n`). This is
//! the dual of dominance and is needed for control-dependence
//! analysis + the `csrf_missing_token` rule's path checks.

use vyre::ir::Program;
use vyre_primitives::bitset::and::bitset_and;
use vyre_primitives::graph::csr_forward_traverse::bitset_words;

pub(crate) const OP_ID: &str = "weir::post_dominates";

/// Build a post-dominator query Program.
///
/// Inputs:
/// - `pdom_set`: per-node bitset where bit `m` is set in node `n`'s
///               row iff `n` post-dominates `m` (host-supplied via
///               classical post-dominator construction).
/// - `target_set`: per-node bitset of target nodes being queried.
/// - `out`:        per-node bitset; bit `n` set iff `n` post-
///                 dominates SOME target in `target_set`.
#[must_use]
pub fn post_dominates(node_count: u32, pdom_set: &str, target_set: &str, out: &str) -> Program {
    let words = bitset_words(node_count);
    vyre_harness::region::tag_program(OP_ID, bitset_and(pdom_set, target_set, out, words))
}

/// CPU oracle.
#[must_use]
pub fn cpu_ref(pdom_set: &[u32], target_set: &[u32]) -> Vec<u32> {
    vyre_primitives::bitset::and::cpu_ref(pdom_set, target_set)
}

/// Soundness marker for [`post_dominates`].
pub struct PostDominates;
impl super::soundness::SoundnessTagged for PostDominates {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::Exact
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdom_intersect_target_set() {
        assert_eq!(cpu_ref(&[0b1111], &[0b0011]), vec![0b0011]);
    }

    #[test]
    fn no_pdom_returns_empty() {
        assert_eq!(cpu_ref(&[0], &[0xFFFF]), vec![0]);
    }

    #[test]
    fn empty_target_returns_empty() {
        assert_eq!(cpu_ref(&[0xFFFF], &[0]), vec![0]);
    }

    #[test]
    fn partial_overlap() {
        assert_eq!(cpu_ref(&[0xFF00], &[0x0FF0]), vec![0x0F00]);
    }
}
