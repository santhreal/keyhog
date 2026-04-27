//! `path_canonical` — was the path string canonicalized before
//! reaching the fs op? CWE-22 supporting predicate.

use vyre::ir::Program;
use vyre_primitives::bitset::and::bitset_and;
use vyre_primitives::graph::csr_forward_traverse::bitset_words;

pub(crate) const OP_ID: &str = "vyre-libs::security::path_canonical";

#[must_use]
/// Build a bitset intersection of canonicalizer dominators and filesystem operations.
pub fn path_canonical(
    node_count: u32,
    canonicalizer_dominates: &str,
    fs_op_set: &str,
    out: &str,
) -> Program {
    let words = bitset_words(node_count);
    crate::region::tag_program(
        OP_ID,
        bitset_and(canonicalizer_dominates, fs_op_set, out, words),
    )
}

#[must_use]
/// CPU oracle for [`path_canonical`].
pub fn cpu_ref(canonicalizer_dominates: &[u32], fs_op_set: &[u32]) -> Vec<u32> {
    vyre_primitives::bitset::and::cpu_ref(canonicalizer_dominates, fs_op_set)
}

/// Soundness marker for [`path_canonical`].
pub struct PathCanonical;
impl weir::soundness::SoundnessTagged for PathCanonical {
    fn soundness(&self) -> weir::soundness::Soundness {
        weir::soundness::Soundness::Exact
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalized_op() {
        assert_eq!(cpu_ref(&[0b1110], &[0b0010]), vec![0b0010]);
    }

    #[test]
    fn uncanonicalized_op() {
        assert_eq!(cpu_ref(&[0b0001], &[0b0010]), vec![0]);
    }

    #[test]
    fn no_fs_ops() {
        assert_eq!(cpu_ref(&[0xFFFF], &[0]), vec![0]);
    }

    #[test]
    fn distributes() {
        assert_eq!(
            cpu_ref(&[0xFF00, 0x00FF], &[0xFFFF, 0xFFFF]),
            vec![0xFF00, 0x00FF]
        );
    }
}
