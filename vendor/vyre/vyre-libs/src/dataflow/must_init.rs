//! Must-init analysis: is variable `v` guaranteed initialized before
//! `use`?
//!
//! Composes the dominator tree with the def site set: `v` is must-
//! initialized at `use` iff every CFG path from entry to `use`
//! crosses a definition of `v`. Encoded as: the def set must
//! dominate the use.
//!
//! Output is a per-node bitset where bit `n` is set iff node `n`'s
//! use of the queried variable is must-initialized.
//!
//! Soundness: [`Exact`](super::soundness::Soundness::Exact) when
//! the supplied dominator tree is correct.

use vyre::ir::Program;
use vyre_primitives::bitset::and::bitset_and;
use vyre_primitives::graph::csr_forward_traverse::bitset_words;

pub(crate) const OP_ID: &str = "vyre-libs::dataflow::must_init";

/// Build a must-init Program. `def_dominates` is a host-supplied
/// per-node bitset where bit `n` is set iff some def of the
/// queried variable dominates node `n`. `use_set` is the per-node
/// bitset of use sites. Output: bit `n` set iff `n` is in `use_set`
/// AND in `def_dominates`.
#[must_use]
pub fn must_init(node_count: u32, def_dominates: &str, use_set: &str, out: &str) -> Program {
    let words = bitset_words(node_count);
    crate::region::tag_program(OP_ID, bitset_and(def_dominates, use_set, out, words))
}

/// CPU oracle.
#[must_use]
pub fn cpu_ref(def_dominates: &[u32], use_set: &[u32]) -> Vec<u32> {
    vyre_primitives::bitset::and::cpu_ref(def_dominates, use_set)
}

/// Soundness marker for [`must_init`].
pub struct MustInit;
impl super::soundness::SoundnessTagged for MustInit {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::Exact
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn use_with_dominating_def_is_init() {
        // use at bit 1, def dominates bits 0,1,2
        assert_eq!(cpu_ref(&[0b0111], &[0b0010]), vec![0b0010]);
    }

    #[test]
    fn use_without_dominating_def_is_uninit() {
        assert_eq!(cpu_ref(&[0b0001], &[0b0010]), vec![0]);
    }

    #[test]
    fn no_uses_yields_empty() {
        assert_eq!(cpu_ref(&[0xFFFF_FFFF], &[0]), vec![0]);
    }

    #[test]
    fn idempotent() {
        let r1 = cpu_ref(&[0xF0F0], &[0x0FF0]);
        let r2 = cpu_ref(&[0xF0F0], &[0x0FF0]);
        assert_eq!(r1, r2);
    }
}
