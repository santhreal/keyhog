//! DF-2 companion — live variables (backward dataflow dual of
//! reaching-defs).
//!
//! ```text
//!   out[n] = ⋃ in[s] for s ∈ succ(n)
//!   in[n]  = use[n] ∪ (out[n] − def[n])
//! ```
//!
//! Shipped as one backward-CFG step; surgec's fixpoint driver
//! iterates. Reuses the forward-traversal primitive against a
//! reversed ProgramGraph (the caller flips edge direction at
//! materialisation time).
//!
//! Soundness: [`Exact`](super::Soundness::Exact).

use vyre::ir::Program;
use vyre_primitives::graph::csr_forward_traverse::csr_forward_traverse;
use vyre_primitives::graph::program_graph::ProgramGraphShape;

pub(crate) const OP_ID: &str = "vyre-libs::dataflow::live";

#[must_use]
/// Build one backward live-variable propagation step over a reversed graph.
pub fn live_step(shape: ProgramGraphShape, frontier_in: &str, frontier_out: &str) -> Program {
    // Backward analysis on a forward primitive — caller flips edges.
    csr_forward_traverse(shape, frontier_in, frontier_out, 0xFFFF_FFFF)
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || live_step(ProgramGraphShape::new(4, 3), "fin", "fout"),
        test_inputs: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // CFG reversed (backward analysis): 3→2→1→0 in storage.
            vec![vec![
                to_bytes(&[0, 0, 0, 0]),
                to_bytes(&[0, 0, 1, 2, 3]),
                to_bytes(&[0, 1, 2]),
                to_bytes(&[1, 1, 1]),
                to_bytes(&[0, 0, 0, 0]),
                to_bytes(&[0b1000]),
                to_bytes(&[0b1000]),
            ]]
        }),
        expected_output: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0b1100])]]
        }),
    }
}

inventory::submit! {
    crate::harness::ConvergenceContract {
        op_id: OP_ID,
        max_iterations: 64,
    }
}

/// Marker type for the live-variables dataflow primitive.
pub struct Liveness;

impl super::soundness::SoundnessTagged for Liveness {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::Exact
    }
}
