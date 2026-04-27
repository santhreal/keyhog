//! `buffer_size_check` — is the buffer size compared to user input?
//! CWE-787 supporting predicate.

use vyre::ir::Program;
use vyre_primitives::bitset::and::bitset_and;
use vyre_primitives::graph::csr_forward_traverse::bitset_words;

pub(crate) const OP_ID: &str = "vyre-libs::security::buffer_size_check";

#[must_use]
/// Build a bitset intersection of size-comparison sites and user-input sites.
pub fn buffer_size_check(
    node_count: u32,
    size_compared: &str,
    user_input_set: &str,
    out: &str,
) -> Program {
    let words = bitset_words(node_count);
    crate::region::tag_program(OP_ID, bitset_and(size_compared, user_input_set, out, words))
}

#[must_use]
/// CPU oracle for [`buffer_size_check`].
pub fn cpu_ref(size_compared: &[u32], user_input_set: &[u32]) -> Vec<u32> {
    vyre_primitives::bitset::and::cpu_ref(size_compared, user_input_set)
}

/// Soundness marker for [`buffer_size_check`].
pub struct BufferSizeCheck;
impl weir::soundness::SoundnessTagged for BufferSizeCheck {
    fn soundness(&self) -> weir::soundness::Soundness {
        weir::soundness::Soundness::Exact
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_size_returns_set() {
        assert_eq!(cpu_ref(&[0b1010], &[0b1100]), vec![0b1000]);
    }

    #[test]
    fn unchecked_size_returns_empty() {
        assert_eq!(cpu_ref(&[0b0001], &[0b1110]), vec![0]);
    }

    #[test]
    fn no_user_input_yields_empty() {
        assert_eq!(cpu_ref(&[0xFFFF], &[0]), vec![0]);
    }

    #[test]
    fn full_overlap() {
        assert_eq!(cpu_ref(&[0xDEAD], &[0xDEAD]), vec![0xDEAD]);
    }
}
