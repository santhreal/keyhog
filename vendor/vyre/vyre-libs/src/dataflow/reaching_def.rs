//! `reaching_def` — reaching-definitions query packed as a bitset.
//!
//! Per use site `u`, return the set of definitions that reach `u`
//! (i.e. there's a CFG path from def to use with no intervening def
//! of the same variable). This is the bitset surgec rules read for
//! the `uses_of($def)` predicate's complement direction.

use vyre::ir::Program;
use vyre_primitives::bitset::and::bitset_and;
use vyre_primitives::graph::csr_forward_traverse::bitset_words;

pub(crate) const OP_ID: &str = "vyre-libs::dataflow::reaching_def";

/// Build a reaching-def query Program.
///
/// Inputs:
/// - `gen_kill_in`: per-node bitset of definitions reaching the
///                  entry of each node (host-supplied via classical
///                  reaching-defs analysis).
/// - `use_set`:     per-node bitset of use sites being queried.
/// - `out`:         per-node bitset; bit `n` set iff `n` is a use
///                  AND has a reaching def.
#[must_use]
pub fn reaching_def(node_count: u32, gen_kill_in: &str, use_set: &str, out: &str) -> Program {
    let words = bitset_words(node_count);
    crate::region::tag_program(OP_ID, bitset_and(gen_kill_in, use_set, out, words))
}

/// CPU oracle.
#[must_use]
pub fn cpu_ref(gen_kill_in: &[u32], use_set: &[u32]) -> Vec<u32> {
    vyre_primitives::bitset::and::cpu_ref(gen_kill_in, use_set)
}

/// Soundness marker for [`reaching_def`].
pub struct ReachingDef;
impl super::soundness::SoundnessTagged for ReachingDef {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::Exact
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn use_with_reaching_def_returns_one() {
        assert_eq!(cpu_ref(&[0b1111], &[0b0010]), vec![0b0010]);
    }

    #[test]
    fn use_without_reaching_def_returns_zero() {
        assert_eq!(cpu_ref(&[0b0001], &[0b0010]), vec![0]);
    }

    #[test]
    fn no_uses_returns_empty() {
        assert_eq!(cpu_ref(&[0xFFFF], &[0]), vec![0]);
    }

    #[test]
    fn idempotent_intersection() {
        let a = cpu_ref(&[0xF0F0], &[0x0FF0]);
        let b = cpu_ref(&[0xF0F0], &[0x0FF0]);
        assert_eq!(a, b);
    }
}
