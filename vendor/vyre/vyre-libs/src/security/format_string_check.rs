//! `format_string_check` — is the format string a literal?
//! CWE-134 supporting predicate.
//!
//! Per format-call site, write 1 iff the first arg is reachable
//! ONLY from string-literal nodes (not from any user-input source).

use vyre::ir::Program;
use vyre_primitives::bitset::and_not::bitset_and_not;
use vyre_primitives::graph::csr_forward_traverse::bitset_words;

pub(crate) const OP_ID: &str = "vyre-libs::security::format_string_check";

#[must_use]
/// Build a bitset subtraction that keeps format arguments not marked non-literal.
pub fn format_string_check(
    node_count: u32,
    format_arg_pts: &str,
    non_literal_set: &str,
    out: &str,
) -> Program {
    let words = bitset_words(node_count);
    crate::region::tag_program(
        OP_ID,
        bitset_and_not(format_arg_pts, non_literal_set, out, words),
    )
}

#[must_use]
/// CPU oracle for [`format_string_check`].
pub fn cpu_ref(format_arg_pts: &[u32], non_literal_set: &[u32]) -> Vec<u32> {
    vyre_primitives::bitset::and_not::cpu_ref(format_arg_pts, non_literal_set)
}

/// Soundness marker for [`format_string_check`].
pub struct FormatStringCheck;
impl weir::soundness::SoundnessTagged for FormatStringCheck {
    fn soundness(&self) -> weir::soundness::Soundness {
        weir::soundness::Soundness::Exact
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_only_returns_full() {
        assert_eq!(cpu_ref(&[0xFFFF], &[0]), vec![0xFFFF]);
    }

    #[test]
    fn user_input_present_subtracts() {
        assert_eq!(cpu_ref(&[0xFFFF], &[0xFF00]), vec![0x00FF]);
    }

    #[test]
    fn fully_user_input_returns_empty() {
        assert_eq!(cpu_ref(&[0xDEAD], &[0xFFFF]), vec![0]);
    }

    #[test]
    fn distributes() {
        assert_eq!(
            cpu_ref(&[0xFFFF, 0x0F0F], &[0xFF00, 0x0000]),
            vec![0x00FF, 0x0F0F]
        );
    }
}
