//! `auth_check_dominates` — does an authorization check dominate
//! the sensitive operation? CWE-862 missing-authz gate.
//!
//! Same shape as `sanitizer_dominates` but typed against the
//! `@auth_check_family` label set instead of sanitizers.

use vyre::ir::Program;
use vyre_primitives::bitset::and::bitset_and;
use vyre_primitives::graph::csr_forward_traverse::bitset_words;

pub(crate) const OP_ID: &str = "vyre-libs::security::auth_check_dominates";

#[must_use]
/// Build a bitset intersection of authorization dominators and sensitive operations.
pub fn auth_check_dominates(
    node_count: u32,
    auth_doms: &str,
    sensitive_op_set: &str,
    out: &str,
) -> Program {
    let words = bitset_words(node_count);
    crate::region::tag_program(OP_ID, bitset_and(auth_doms, sensitive_op_set, out, words))
}

#[must_use]
/// CPU oracle for [`auth_check_dominates`].
pub fn cpu_ref(auth_doms: &[u32], sensitive_op_set: &[u32]) -> Vec<u32> {
    vyre_primitives::bitset::and::cpu_ref(auth_doms, sensitive_op_set)
}

/// Soundness marker for [`auth_check_dominates`].
pub struct AuthCheckDominates;
impl weir::soundness::SoundnessTagged for AuthCheckDominates {
    fn soundness(&self) -> weir::soundness::Soundness {
        weir::soundness::Soundness::Exact
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_op_returns_set() {
        assert_eq!(cpu_ref(&[0b1100], &[0b0100]), vec![0b0100]);
    }

    #[test]
    fn unprotected_op_returns_empty() {
        assert_eq!(cpu_ref(&[0b0001], &[0b1110]), vec![0]);
    }

    #[test]
    fn no_sensitive_ops() {
        assert_eq!(cpu_ref(&[0xFFFF], &[0]), vec![0]);
    }

    #[test]
    fn no_auth_checks() {
        assert_eq!(cpu_ref(&[0], &[0xFFFF]), vec![0]);
    }
}
