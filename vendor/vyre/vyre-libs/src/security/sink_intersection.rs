//! `sink_intersection` — count how many of a query set are also in
//! a sink-family bitset. Used by rules that want a fractional
//! confidence ("X% of nodes reachable from source landed in sinks").

use vyre::ir::Program;
use vyre_foundation::execution_plan::fusion::fuse_programs;
use vyre_primitives::bitset::and::bitset_and;
use vyre_primitives::bitset::popcount::bitset_popcount;
use vyre_primitives::graph::csr_forward_traverse::bitset_words;

use crate::region::{reparent_program_children, wrap_anonymous};

pub(crate) const OP_ID: &str = "vyre-libs::security::sink_intersection";

/// Build a sink-intersection-count Program. AND query with sink_set,
/// popcount the result, write to out_scalar.
#[must_use]
pub fn sink_intersection(
    node_count: u32,
    query_set: &str,
    sink_set: &str,
    intersect_buf: &str,
    out_scalar: &str,
) -> Program {
    let words = bitset_words(node_count);
    let intersect = bitset_and(query_set, sink_set, intersect_buf, words);
    let count = bitset_popcount(intersect_buf, out_scalar, words);
    let fused =
        fuse_programs(&[intersect, count]).expect("sink_intersection: and+popcount fuse cleanly");
    Program::wrapped(
        fused.buffers().to_vec(),
        fused.workgroup_size(),
        vec![wrap_anonymous(
            OP_ID,
            reparent_program_children(&fused, OP_ID),
        )],
    )
}

/// CPU oracle: count of bits set in `query AND sink`.
#[must_use]
pub fn cpu_ref(query_set: &[u32], sink_set: &[u32]) -> u32 {
    let inter = vyre_primitives::bitset::and::cpu_ref(query_set, sink_set);
    inter.iter().map(|w| w.count_ones()).sum()
}

/// Soundness marker for [`sink_intersection`].
pub struct SinkIntersection;
impl weir::soundness::SoundnessTagged for SinkIntersection {
    fn soundness(&self) -> weir::soundness::Soundness {
        weir::soundness::Soundness::Exact
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_overlap_counts_all_set_bits() {
        assert_eq!(cpu_ref(&[0b1111], &[0b1111]), 4);
    }

    #[test]
    fn no_overlap_returns_zero() {
        assert_eq!(cpu_ref(&[0b1010], &[0b0101]), 0);
    }

    #[test]
    fn partial_overlap_counts_intersection() {
        assert_eq!(cpu_ref(&[0b1110], &[0b0111]), 2);
    }

    #[test]
    fn distributes_across_words() {
        assert_eq!(cpu_ref(&[0xFF00, 0x00FF], &[0xFFFF, 0xFFFF]), 16);
    }
}
