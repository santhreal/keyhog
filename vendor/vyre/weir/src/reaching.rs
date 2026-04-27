//! DF-2 — reaching definitions.
//!
//! Classical forward monotone dataflow over the CFG:
//!
//! ```text
//!   in[n]  = ⋃ out[p]  for p ∈ pred(n)
//!   out[n] = gen[n] ∪ (in[n] − kill[n])
//! ```
//!
//! This is the join of a may-analysis — a definition reaches `n` iff
//! there exists at least one path from the def-site to `n` along which
//! the def is not killed.
//!
//! ## Layering
//!
//! Following the `vyre-libs::security::flows_to` idiom, this module
//! ships ONE dispatch step that a surgec-side fixpoint driver iterates.
//! The full semantics live in the SURGE stdlib at
//! `surgec/rules/stdlib/reaching.srg` (to be authored alongside the
//! first C01/C02 rules that consume DF-2).
//!
//! The step reuses [`csr_forward_traverse`] for the per-edge
//! propagation — reaching-defs on the CFG is a forward reachability
//! problem in bitset space; csr_forward_traverse does exactly that
//! at the edge level, and the surge driver stacks the
//! `gen ∪ (in − kill)` transfer on top as fixpoint pre-union.
//!
//! ## Soundness
//!
//! [`Exact`](super::Soundness::Exact) on a sound CFG. Rules that
//! consume reaching-defs for zero-FP detection must pair it with a
//! filter that confirms each reaching def actually affects the sink
//! (DF-3 points-to closes the aliasing side).

use vyre::ir::Program;
use vyre_primitives::graph::csr_forward_traverse::csr_forward_traverse;
use vyre_primitives::graph::program_graph::ProgramGraphShape;

pub(crate) const OP_ID: &str = "weir::reaching";

/// Build one CFG-forward propagation step for reaching-defs.
///
/// `frontier_in` reads the current `out[n]` bit-sets across all CFG
/// nodes (flat; surge stdlib is responsible for laying it out as
/// `n * defs_per_word` per node). `frontier_out` receives the
/// propagated `in'[n]` after one CFG-edge traversal.
///
/// The `gen[n] ∪ (in[n] − kill[n])` transfer runs on the surge side
/// as a pointwise pre-union step in the fixpoint driver — this keeps
/// the vyre primitive a single traversal call (same shape as
/// `flows_to`), which composes cleanly with
/// `vyre_primitives::bitset` ops for the transfer.
#[must_use]
pub fn reaching_defs_step(
    shape: ProgramGraphShape,
    frontier_in: &str,
    frontier_out: &str,
) -> Program {
    csr_forward_traverse(shape, frontier_in, frontier_out, 0xFFFF_FFFF)
}

inventory::submit! {
    vyre_harness::OpEntry::new(
        OP_ID,
        || reaching_defs_step(ProgramGraphShape::new(4, 4), "fin", "fout"),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // Diamond CFG — four nodes with a join at node 3:
            //   0 → 1 → 3
            //   0 → 2 → 3
            // Reaching-defs start at node 0 with def-set {0b0001}.
            // After one forward step, def 0 has propagated to nodes 1
            // and 2 (but not yet past the join into 3).
            vec![vec![
                to_bytes(&[0, 0, 0, 0]),          // pg_nodes
                to_bytes(&[0, 2, 3, 4, 4]),       // pg_edge_offsets: 0→{1,2}, 1→{3}, 2→{3}, 3→{}
                to_bytes(&[1, 2, 3, 3]),          // pg_edge_targets
                to_bytes(&[1, 1, 1, 1]),          // pg_edge_kind_mask
                to_bytes(&[0, 0, 0, 0]),          // pg_node_tags
                to_bytes(&[0b0001]),              // fin = {def 0 at node 0}
                to_bytes(&[0b0001]),              // fout seed = same
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // Diamond 0→{1,2}→3: one forward step from {0} reaches
            // {0, 1, 2}. A no-op impl that returns the input would
            // only produce {0} and fail.
            vec![vec![to_bytes(&[0b0111])]]
        }),
    )
}

inventory::submit! {
    vyre_harness::ConvergenceContract {
        op_id: OP_ID,
        max_iterations: 64,
    }
}

/// Marker type for the reaching-definitions dataflow primitive.
pub struct ReachingDefs;

impl super::soundness::SoundnessTagged for ReachingDefs {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::Exact
    }
}
