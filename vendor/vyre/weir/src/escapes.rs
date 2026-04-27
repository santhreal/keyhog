//! Escape analysis: does a value escape the function scope?
//!
//! Composes the call graph with the points-to set: a value `v`
//! escapes iff `pts(v)` intersects the set of nodes reachable from
//! a function's return / global / heap-store sites. Exposed as a
//! per-node bitset for surgec rules to read.
//!
//! Soundness: [`MayOver`](super::soundness::Soundness::MayOver) — the
//! points-to is sound (over-approximates), so the escape set is sound.

use vyre::ir::Program;
use vyre_primitives::bitset::and::bitset_and;
use vyre_primitives::graph::csr_forward_traverse::bitset_words;

pub(crate) const OP_ID: &str = "weir::escapes";

/// Build an escape-query Program. Inputs:
/// - `pts_buf`: per-variable points-to bitset (host-supplied).
/// - `escape_set_buf`: per-node bitset of escape sites (return, global, heap-store).
/// - `out`: per-variable bitset, bit set iff that variable's
///          points-to set overlaps the escape set.
#[must_use]
pub fn escapes(node_count: u32, pts_buf: &str, escape_set_buf: &str, out: &str) -> Program {
    let words = bitset_words(node_count);
    vyre_harness::region::tag_program(OP_ID, bitset_and(pts_buf, escape_set_buf, out, words))
}

/// CPU oracle.
#[must_use]
pub fn cpu_ref(pts: &[u32], escape_set: &[u32]) -> Vec<u32> {
    vyre_primitives::bitset::and::cpu_ref(pts, escape_set)
}

/// Marker type for the escape primitive.
pub struct Escapes;

impl super::soundness::SoundnessTagged for Escapes {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::MayOver
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_pts_means_no_escape() {
        assert_eq!(cpu_ref(&[0], &[0xFFFF_FFFF]), vec![0]);
    }

    #[test]
    fn full_pts_in_escape_set_escapes() {
        assert_eq!(cpu_ref(&[0xFFFF], &[0xFFFF]), vec![0xFFFF]);
    }

    #[test]
    fn disjoint_means_no_escape() {
        assert_eq!(cpu_ref(&[0xFF00], &[0x00FF]), vec![0]);
    }

    #[test]
    fn partial_overlap_escapes_partially() {
        assert_eq!(cpu_ref(&[0x0FF0], &[0x00FF]), vec![0x00F0]);
    }
}
