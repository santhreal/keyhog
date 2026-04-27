//! `sanitizer_dominates` — does a sanitizer dominate the sink in
//! the CFG? Precision gate for taint rules.
//!
//! Per sink node `n`, write 1 iff some sanitizer node dominates `n`.
//! Composes the dominator-set bitset with the sanitizer family
//! bitset.

use vyre::ir::Program;
use vyre_primitives::bitset::and::bitset_and;
use vyre_primitives::graph::csr_forward_traverse::bitset_words;

pub(crate) const OP_ID: &str = "vyre-libs::security::sanitizer_dominates";

/// Build a sanitizer-dominates Program.
///
/// Inputs:
/// - `sanitizer_doms`: per-node bitset where bit `n` is set iff some
///                     sanitizer-tagged node dominates `n`.
/// - `sink_set`:       per-node bitset of sink sites being queried.
/// - `out`:            per-node bitset; bit `n` set iff `n` is a
///                     sink AND has a dominating sanitizer.
#[must_use]
pub fn sanitizer_dominates(
    node_count: u32,
    sanitizer_doms: &str,
    sink_set: &str,
    out: &str,
) -> Program {
    let words = bitset_words(node_count);
    crate::region::tag_program(OP_ID, bitset_and(sanitizer_doms, sink_set, out, words))
}

/// CPU oracle.
#[must_use]
pub fn cpu_ref(sanitizer_doms: &[u32], sink_set: &[u32]) -> Vec<u32> {
    vyre_primitives::bitset::and::cpu_ref(sanitizer_doms, sink_set)
}

/// Soundness marker for [`sanitizer_dominates`].
pub struct SanitizerDominates;
impl weir::soundness::SoundnessTagged for SanitizerDominates {
    fn soundness(&self) -> weir::soundness::Soundness {
        weir::soundness::Soundness::Exact
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dominated_sink_returns_set() {
        assert_eq!(cpu_ref(&[0b1111], &[0b0010]), vec![0b0010]);
    }

    #[test]
    fn non_dominated_sink_returns_empty() {
        assert_eq!(cpu_ref(&[0b0001], &[0b0010]), vec![0]);
    }

    #[test]
    fn no_sinks_returns_empty() {
        assert_eq!(cpu_ref(&[0xFFFF], &[0]), vec![0]);
    }

    #[test]
    fn distributes_per_word() {
        assert_eq!(
            cpu_ref(&[0xFF00, 0x00FF], &[0x0FF0, 0x0FF0]),
            vec![0x0F00, 0x00F0]
        );
    }
}
