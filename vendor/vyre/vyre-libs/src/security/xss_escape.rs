//! `xss_escape` — is the HTML output escape-encoded? CWE-79
//! supporting predicate.

use vyre::ir::Program;
use vyre_primitives::bitset::and::bitset_and;
use vyre_primitives::graph::csr_forward_traverse::bitset_words;

pub(crate) const OP_ID: &str = "vyre-libs::security::xss_escape";

#[must_use]
/// Build a bitset intersection of escape dominators and HTML render sites.
pub fn xss_escape(node_count: u32, escape_dominates: &str, render_set: &str, out: &str) -> Program {
    let words = bitset_words(node_count);
    crate::region::tag_program(OP_ID, bitset_and(escape_dominates, render_set, out, words))
}

#[must_use]
/// CPU oracle for [`xss_escape`].
pub fn cpu_ref(escape_dominates: &[u32], render_set: &[u32]) -> Vec<u32> {
    vyre_primitives::bitset::and::cpu_ref(escape_dominates, render_set)
}

/// Soundness marker for [`xss_escape`].
pub struct XssEscape;
impl weir::soundness::SoundnessTagged for XssEscape {
    fn soundness(&self) -> weir::soundness::Soundness {
        weir::soundness::Soundness::Exact
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaped_render() {
        assert_eq!(cpu_ref(&[0b1100], &[0b0100]), vec![0b0100]);
    }

    #[test]
    fn unescaped_render() {
        assert_eq!(cpu_ref(&[0b0001], &[0b0010]), vec![0]);
    }

    #[test]
    fn no_renders() {
        assert_eq!(cpu_ref(&[0xFFFF], &[0]), vec![0]);
    }

    #[test]
    fn no_escape_dominators() {
        assert_eq!(cpu_ref(&[0], &[0xFFFF]), vec![0]);
    }
}
