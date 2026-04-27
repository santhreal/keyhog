//! `taint_pollution` — "did taint reach a label-tagged node?"
//!
//! The CodeQL `globalAllowingExtras` shape compressed to one
//! Region. Composes a one-step BFS with intersection against a
//! family-tagged node set, then any-reduce.

use vyre::ir::Program;
use vyre_foundation::execution_plan::fusion::fuse_programs;
use vyre_primitives::bitset::and::bitset_and;
use vyre_primitives::bitset::any::bitset_any;
use vyre_primitives::graph::csr_forward_traverse::{bitset_words, csr_forward_traverse};
use vyre_primitives::graph::program_graph::ProgramGraphShape;

use crate::region::{reparent_program_children, wrap_anonymous};
use crate::security::flows_to::FLOWS_TO_MASK;

pub(crate) const OP_ID: &str = "vyre-libs::security::taint_pollution";

/// Build a one-step taint-pollution Program: source → reach
/// (FLOWS_TO_MASK) → AND with label-tagged sink set → any-reduce.
#[must_use]
pub fn taint_pollution(
    shape: ProgramGraphShape,
    source_buf: &str,
    label_set: &str,
    reach_buf: &str,
    hits_buf: &str,
    out_scalar: &str,
) -> Program {
    let words = bitset_words(shape.node_count);
    let traverse = csr_forward_traverse(shape, source_buf, reach_buf, FLOWS_TO_MASK);
    let intersect = bitset_and(reach_buf, label_set, hits_buf, words);
    let any = bitset_any(hits_buf, out_scalar, words);
    let fused = fuse_programs(&[traverse, intersect, any])
        .expect("taint_pollution: traverse+and+any fuse cleanly");
    Program::wrapped(
        fused.buffers().to_vec(),
        fused.workgroup_size(),
        vec![wrap_anonymous(
            OP_ID,
            reparent_program_children(&fused, OP_ID),
        )],
    )
}

/// CPU oracle.
#[must_use]
pub fn cpu_ref(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    source: &[u32],
    label_set: &[u32],
) -> u32 {
    use vyre_primitives::bitset::and::cpu_ref as and_ref;
    use vyre_primitives::graph::csr_forward_traverse::cpu_ref as fwd_ref;
    let reach = fwd_ref(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        source,
        FLOWS_TO_MASK,
    );
    let hits = and_ref(&reach, label_set);
    u32::from(hits.iter().any(|w| *w != 0))
}

/// Soundness marker for [`taint_pollution`].
pub struct TaintPollution;
impl weir::soundness::SoundnessTagged for TaintPollution {
    fn soundness(&self) -> weir::soundness::Soundness {
        weir::soundness::Soundness::MayOver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_primitives::predicate::edge_kind;

    #[test]
    fn one_hop_to_labeled_returns_one() {
        // 0 -> 1, label = {1}
        let off = vec![0u32, 1, 1];
        let tgt = vec![1u32];
        let msk = vec![edge_kind::ASSIGNMENT];
        assert_eq!(cpu_ref(2, &off, &tgt, &msk, &[0b01], &[0b10]), 1);
    }

    #[test]
    fn no_label_hit_returns_zero() {
        let off = vec![0u32, 1, 1];
        let tgt = vec![1u32];
        let msk = vec![edge_kind::ASSIGNMENT];
        assert_eq!(cpu_ref(2, &off, &tgt, &msk, &[0b01], &[0]), 0);
    }

    #[test]
    fn empty_source_returns_zero() {
        let off = vec![0u32, 1, 1];
        let tgt = vec![1u32];
        let msk = vec![edge_kind::ASSIGNMENT];
        assert_eq!(cpu_ref(2, &off, &tgt, &msk, &[0], &[0xFFFF]), 0);
    }

    #[test]
    fn unreachable_label_returns_zero() {
        // 0 -> 1, label = {0} — source 0 doesn't taint itself.
        let off = vec![0u32, 1, 1];
        let tgt = vec![1u32];
        let msk = vec![edge_kind::ASSIGNMENT];
        assert_eq!(cpu_ref(2, &off, &tgt, &msk, &[0b01], &[0b01]), 0);
    }
}
