//! `sql_param_bound` — is the SQL string built via parameter
//! binding rather than raw concatenation? CWE-89 supporting
//! predicate.

use vyre::ir::Program;
use vyre_primitives::bitset::and::bitset_and;
use vyre_primitives::graph::csr_forward_traverse::bitset_words;

pub(crate) const OP_ID: &str = "vyre-libs::security::sql_param_bound";

#[must_use]
/// Build a bitset intersection of parameter-binding sites and SQL query sites.
pub fn sql_param_bound(
    node_count: u32,
    param_binding_set: &str,
    sql_query_set: &str,
    out: &str,
) -> Program {
    let words = bitset_words(node_count);
    crate::region::tag_program(
        OP_ID,
        bitset_and(param_binding_set, sql_query_set, out, words),
    )
}

#[must_use]
/// CPU oracle for [`sql_param_bound`].
pub fn cpu_ref(param_binding_set: &[u32], sql_query_set: &[u32]) -> Vec<u32> {
    vyre_primitives::bitset::and::cpu_ref(param_binding_set, sql_query_set)
}

/// Soundness marker for [`sql_param_bound`].
pub struct SqlParamBound;
impl weir::soundness::SoundnessTagged for SqlParamBound {
    fn soundness(&self) -> weir::soundness::Soundness {
        weir::soundness::Soundness::Exact
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameterized_query() {
        assert_eq!(cpu_ref(&[0b1100], &[0b0100]), vec![0b0100]);
    }

    #[test]
    fn raw_concat_query() {
        assert_eq!(cpu_ref(&[0b0001], &[0b0010]), vec![0]);
    }

    #[test]
    fn no_queries() {
        assert_eq!(cpu_ref(&[0xFFFF], &[0]), vec![0]);
    }

    #[test]
    fn distributes() {
        assert_eq!(
            cpu_ref(&[0xFF00, 0xF0F0], &[0x0FF0, 0x0F0F]),
            vec![0x0F00, 0x0000]
        );
    }
}
