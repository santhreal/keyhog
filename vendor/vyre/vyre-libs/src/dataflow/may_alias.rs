//! `may_alias` — Andersen-style may-alias query packed as a bitset.
//!
//! Given two pointer expressions `p` and `q`, return 1 iff their
//! points-to sets overlap (`pts(p) ∩ pts(q) ≠ ∅`). Implementation:
//! per-node bitset AND of pts(p) and pts(q), then any-reduce.
//!
//! Soundness: [`MayOver`](super::soundness::Soundness::MayOver).

use vyre::ir::Program;
use vyre_foundation::execution_plan::fusion::fuse_programs;
use vyre_primitives::bitset::and::bitset_and;
use vyre_primitives::bitset::any::bitset_any;
use vyre_primitives::graph::csr_forward_traverse::bitset_words;

pub(crate) const OP_ID: &str = "vyre-libs::dataflow::may_alias";

/// Build a may-alias Program. Inputs:
/// - `pts_p`, `pts_q`: per-node points-to bitsets.
/// - `intersect_buf`: scratch.
/// - `out_scalar`: 1 if the points-to sets overlap, else 0.
#[must_use]
pub fn may_alias(
    node_count: u32,
    pts_p: &str,
    pts_q: &str,
    intersect_buf: &str,
    out_scalar: &str,
) -> Program {
    let words = bitset_words(node_count);
    let intersect = bitset_and(pts_p, pts_q, intersect_buf, words);
    let any = bitset_any(intersect_buf, out_scalar, words);
    let fused = fuse_programs(&[intersect, any]).expect("may_alias: and+any fuse cleanly");
    crate::region::tag_program(OP_ID, fused)
}

/// CPU oracle.
#[must_use]
pub fn cpu_ref(pts_p: &[u32], pts_q: &[u32]) -> u32 {
    let inter = vyre_primitives::bitset::and::cpu_ref(pts_p, pts_q);
    u32::from(inter.iter().any(|w| *w != 0))
}

/// Soundness marker for [`may_alias`].
pub struct MayAlias;
impl super::soundness::SoundnessTagged for MayAlias {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::MayOver
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_pts_alias() {
        assert_eq!(cpu_ref(&[0b1010], &[0b0011]), 1);
    }

    #[test]
    fn disjoint_pts_dont_alias() {
        assert_eq!(cpu_ref(&[0b1010], &[0b0101]), 0);
    }

    #[test]
    fn empty_pts_dont_alias() {
        assert_eq!(cpu_ref(&[0], &[0xFFFF]), 0);
    }

    #[test]
    fn identical_pts_alias() {
        assert_eq!(cpu_ref(&[0xDEAD], &[0xDEAD]), 1);
    }
}
