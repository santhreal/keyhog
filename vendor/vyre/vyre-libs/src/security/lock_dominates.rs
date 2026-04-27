//! `lock_dominates` — does an `@lock_acquire_family` call dominate
//! the shared-state access? CWE-362 race-condition gate.

use vyre::ir::Program;
use vyre_primitives::bitset::and::bitset_and;
use vyre_primitives::graph::csr_forward_traverse::bitset_words;

pub(crate) const OP_ID: &str = "vyre-libs::security::lock_dominates";

#[must_use]
/// Build a bitset intersection of lock dominators and shared accesses.
pub fn lock_dominates(
    node_count: u32,
    lock_doms: &str,
    shared_access_set: &str,
    out: &str,
) -> Program {
    let words = bitset_words(node_count);
    crate::region::tag_program(OP_ID, bitset_and(lock_doms, shared_access_set, out, words))
}

#[must_use]
/// CPU oracle for [`lock_dominates`].
pub fn cpu_ref(lock_doms: &[u32], shared_access_set: &[u32]) -> Vec<u32> {
    vyre_primitives::bitset::and::cpu_ref(lock_doms, shared_access_set)
}

/// Soundness marker for [`lock_dominates`].
pub struct LockDominates;
impl weir::soundness::SoundnessTagged for LockDominates {
    fn soundness(&self) -> weir::soundness::Soundness {
        weir::soundness::Soundness::Exact
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_access() {
        assert_eq!(cpu_ref(&[0b1110], &[0b0010]), vec![0b0010]);
    }

    #[test]
    fn unlocked_access() {
        assert_eq!(cpu_ref(&[0b0001], &[0b0010]), vec![0]);
    }

    #[test]
    fn no_accesses() {
        assert_eq!(cpu_ref(&[0xFFFF], &[0]), vec![0]);
    }

    #[test]
    fn empty_lock_set() {
        assert_eq!(cpu_ref(&[0], &[0xFFFF]), vec![0]);
    }
}
