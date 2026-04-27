//! `unchecked_return` — return value used in a sensitive op without
//! a comparison check. CWE-252.
//!
//! Per call-site `c`, write 1 iff `c`'s return value is dereferenced
//! / used in a pointer-arithmetic / passed to a fs op WITHOUT a
//! dominating comparison against null / -1 / error sentinel.

use vyre::ir::Program;
use vyre_primitives::bitset::and_not::bitset_and_not;
use vyre_primitives::graph::csr_forward_traverse::bitset_words;

pub(crate) const OP_ID: &str = "vyre-libs::security::unchecked_return";

#[must_use]
/// Build a bitset subtraction that keeps uses without dominating checks.
pub fn unchecked_return(
    node_count: u32,
    use_set: &str,
    check_dominates: &str,
    out: &str,
) -> Program {
    let words = bitset_words(node_count);
    crate::region::tag_program(OP_ID, bitset_and_not(use_set, check_dominates, out, words))
}

#[must_use]
/// CPU oracle for [`unchecked_return`].
pub fn cpu_ref(use_set: &[u32], check_dominates: &[u32]) -> Vec<u32> {
    vyre_primitives::bitset::and_not::cpu_ref(use_set, check_dominates)
}

/// Soundness marker for [`unchecked_return`].
pub struct UncheckedReturn;
impl weir::soundness::SoundnessTagged for UncheckedReturn {
    fn soundness(&self) -> weir::soundness::Soundness {
        weir::soundness::Soundness::Exact
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn use_without_check_returns_set() {
        assert_eq!(cpu_ref(&[0b1100], &[0b0001]), vec![0b1100]);
    }

    #[test]
    fn use_with_dominating_check_returns_empty() {
        assert_eq!(cpu_ref(&[0b0010], &[0b0010]), vec![0]);
    }

    #[test]
    fn no_uses_returns_empty() {
        assert_eq!(cpu_ref(&[0], &[0xFFFF]), vec![0]);
    }

    #[test]
    fn distributes() {
        assert_eq!(
            cpu_ref(&[0xFFFF, 0x0F0F], &[0x00FF, 0xF000]),
            vec![0xFF00, 0x0F0F]
        );
    }
}
