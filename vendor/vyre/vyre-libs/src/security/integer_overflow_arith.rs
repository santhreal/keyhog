//! `integer_overflow_arith` — does this binary op overflow on
//! attacker input? CWE-190 supporting predicate.
//!
//! Per node `n`, write 1 iff `n` is a binary arithmetic node
//! (mul / add / shl) AND at least one operand is reachable from
//! `@http_input_family` AND there is no dominating overflow check.

use vyre::ir::Program;
use vyre_foundation::execution_plan::fusion::fuse_programs;
use vyre_primitives::bitset::and::bitset_and;
use vyre_primitives::bitset::and_not::bitset_and_not;
use vyre_primitives::graph::csr_forward_traverse::bitset_words;

pub(crate) const OP_ID: &str = "vyre-libs::security::integer_overflow_arith";

/// Build an overflow-check Program: arith_set AND attacker_reach
/// AND NOT overflow_check_dominates.
#[must_use]
pub fn integer_overflow_arith(
    node_count: u32,
    arith_set: &str,
    attacker_reach: &str,
    overflow_check_dominates: &str,
    intermediate: &str,
    out: &str,
) -> Program {
    let words = bitset_words(node_count);
    let attacker_arith = bitset_and(arith_set, attacker_reach, intermediate, words);
    let unguarded = bitset_and_not(intermediate, overflow_check_dominates, out, words);
    let fused = fuse_programs(&[attacker_arith, unguarded])
        .expect("integer_overflow_arith: and+and_not fuse cleanly");
    crate::region::tag_program(OP_ID, fused)
}

/// CPU oracle.
#[must_use]
pub fn cpu_ref(
    arith_set: &[u32],
    attacker_reach: &[u32],
    overflow_check_dominates: &[u32],
) -> Vec<u32> {
    let inter = vyre_primitives::bitset::and::cpu_ref(arith_set, attacker_reach);
    vyre_primitives::bitset::and_not::cpu_ref(&inter, overflow_check_dominates)
}

/// Soundness marker for [`integer_overflow_arith`].
pub struct IntegerOverflowArith;
impl weir::soundness::SoundnessTagged for IntegerOverflowArith {
    fn soundness(&self) -> weir::soundness::Soundness {
        weir::soundness::Soundness::Exact
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unguarded_attacker_arith_fires() {
        // arith {0,1,2,3}, attacker {1,2}, no checks.
        assert_eq!(cpu_ref(&[0b1111], &[0b0110], &[0]), vec![0b0110]);
    }

    #[test]
    fn guarded_does_not_fire() {
        assert_eq!(cpu_ref(&[0b1111], &[0b0110], &[0b0010]), vec![0b0100]);
    }

    #[test]
    fn no_attacker_means_no_finding() {
        assert_eq!(cpu_ref(&[0b1111], &[0], &[0]), vec![0]);
    }

    #[test]
    fn no_arith_means_no_finding() {
        assert_eq!(cpu_ref(&[0], &[0xFFFF], &[0]), vec![0]);
    }
}
