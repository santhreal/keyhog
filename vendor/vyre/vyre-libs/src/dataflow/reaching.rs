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
//! `MayOver` on a sound CFG. Rules that
//! consume reaching-defs for zero-FP detection must pair it with a
//! filter that confirms each reaching def actually affects the sink
//! (DF-3 points-to closes the aliasing side).

use vyre::ir::Program;
use vyre_primitives::graph::csr_forward_traverse::csr_forward_traverse;
use vyre_primitives::graph::program_graph::ProgramGraphShape;
use vyre_primitives::predicate::edge_kind;

pub(crate) const OP_ID: &str = "vyre-libs::dataflow::reaching";
const CFG_EDGE_MASK: u32 = edge_kind::CONTROL;

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
    crate::region::tag_program(
        OP_ID,
        csr_forward_traverse(shape, frontier_in, frontier_out, CFG_EDGE_MASK),
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || reaching_defs_step(ProgramGraphShape::new(4, 4), "fin", "fout"),
        test_inputs: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // Diamond CFG — four nodes with a join at node 3:
            //   0 → 1 → 3
            //   0 → 2 → 3
            // Reaching-defs start at node 0 with def-set {0b0001}.
            // After one forward step, def 0 has propagated to nodes 1
            // and 2 (before the join into 3).
            vec![vec![
                to_bytes(&[0, 0, 0, 0]),          // pg_nodes
                to_bytes(&[0, 2, 3, 4, 4]),       // pg_edge_offsets: 0→{1,2}, 1→{3}, 2→{3}, 3→{}
                to_bytes(&[1, 2, 3, 3]),          // pg_edge_targets
                to_bytes(&[CFG_EDGE_MASK, CFG_EDGE_MASK, CFG_EDGE_MASK, CFG_EDGE_MASK]), // pg_edge_kind_mask
                to_bytes(&[0, 0, 0, 0]),          // pg_node_tags
                to_bytes(&[0b0001]),              // fin = {def 0 at node 0}
                to_bytes(&[0b0001]),              // fout seed = same
            ]]
        }),
        expected_output: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // Diamond 0→{1,2}→3: one forward step from {0} reaches
            // {0, 1, 2}. A no-op impl that returns the input would
            // only produce {0} and fail.
            vec![vec![to_bytes(&[0b0111])]]
        }),
    }
}

inventory::submit! {
    crate::harness::ConvergenceContract {
        op_id: OP_ID,
        max_iterations: 64,
    }
}

/// Marker type for the reaching-definitions dataflow primitive.
pub struct ReachingDefs;

impl super::soundness::SoundnessTagged for ReachingDefs {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::MayOver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_primitives::predicate::edge_kind;

    #[test]
    fn reaching_defs_step_uses_control_edge_mask() {
        let p = reaching_defs_step(ProgramGraphShape::new(4, 4), "fin", "fout");
        assert!(vyre::validate(&p).is_empty());
        assert_eq!(CFG_EDGE_MASK, edge_kind::CONTROL);
        assert_eq!(CFG_EDGE_MASK & edge_kind::ASSIGNMENT, 0);
        assert_eq!(CFG_EDGE_MASK & edge_kind::DOMINANCE, 0);
    }

    #[test]
    fn reaching_defs_step_emits_frontier_buffers() {
        let p = reaching_defs_step(ProgramGraphShape::new(4, 4), "fin", "fout");
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert!(names.contains(&"fin"));
        assert!(names.contains(&"fout"));
    }

    #[test]
    fn reaching_defs_step_shape_is_not_degenerate() {
        let shape = ProgramGraphShape::new(64, 128);
        let p = reaching_defs_step(shape, "fin", "fout");
        let fin_buf = p
            .buffers
            .iter()
            .find(|b| b.name() == "fin")
            .expect("fin buffer");
        assert!(
            fin_buf.count >= 2,
            "bitset_words(64) = 2; count {fin_buf_count} suggests degenerate shape",
            fin_buf_count = fin_buf.count
        );
    }

    #[test]
    fn reaching_defs_soundness_is_mayover() {
        use super::super::soundness::{Soundness, SoundnessTagged};
        assert_eq!(ReachingDefs.soundness(), Soundness::MayOver);
    }

    #[test]
    fn reaching_defs_mixed_edge_kind_mask_filters_non_control() {
        // M8 adversarial: graph with mixed edge kinds, only CONTROL
        // should be traversed. A broken implementation that ignores the
        // mask would reach all successors and fail this test.
        let got = vyre_primitives::graph::csr_forward_traverse::cpu_ref(
            4,
            &[0, 3, 3, 3, 3], // node 0 has 3 outgoing edges
            &[1, 2, 3],       // 0→1, 0→2, 0→3
            &[
                edge_kind::ASSIGNMENT, // 0→1 should be filtered out
                edge_kind::CONTROL,    // 0→2 should pass
                edge_kind::DOMINANCE,  // 0→3 should be filtered out
            ],
            &[0b0001], // frontier = {0}
            edge_kind::CONTROL,
        );
        assert_eq!(
            got,
            vec![0b0100],
            "ASSIGNMENT and DOMINANCE edges must NOT be traversed when mask is CONTROL only"
        );
    }

    #[test]
    fn reaching_defs_fixpoint_converges_on_cycle() {
        // Convergence adversarial: cycle 0→1→2→0. All CONTROL.
        // Seed {0}. Reachability grows monotonically until all 3 nodes.
        let mut frontier = vec![0b0001];
        let words = vyre_primitives::graph::csr_forward_traverse::bitset_words(3) as usize;
        frontier.resize(words, 0);
        let mut iters = 0;
        for _ in 0..128 {
            let next = vyre_primitives::graph::csr_forward_traverse::cpu_ref(
                3,
                &[0, 1, 2, 3],
                &[1, 2, 0],
                &[edge_kind::CONTROL, edge_kind::CONTROL, edge_kind::CONTROL],
                &frontier,
                edge_kind::CONTROL,
            );
            let mut changed = false;
            for i in 0..words {
                let old = frontier[i];
                frontier[i] |= next[i];
                if frontier[i] != old {
                    changed = true;
                }
            }
            iters += 1;
            if !changed {
                break;
            }
        }
        assert!(
            iters > 1,
            "fixpoint on a cycle must take >1 iteration; converged in {iters}"
        );
        assert_eq!(frontier, vec![0b0111], "all nodes in the cycle must be reachable");
    }

    #[test]
    fn reaching_defs_fixpoint_reaches_in_multiple_iterations() {
        // Convergence adversarial: chain 0→1→2→3 plus back-edge 3→1.
        // All CONTROL. Seed {0}. Fixpoint requires >2 iterations.
        let mut frontier = vec![0b0001];
        let words = vyre_primitives::graph::csr_forward_traverse::bitset_words(4) as usize;
        frontier.resize(words, 0);
        let mut iters = 0;
        for _ in 0..128 {
            let next = vyre_primitives::graph::csr_forward_traverse::cpu_ref(
                4,
                &[0, 1, 2, 3, 4],
                &[1, 2, 3, 1],
                &[
                    edge_kind::CONTROL,
                    edge_kind::CONTROL,
                    edge_kind::CONTROL,
                    edge_kind::CONTROL,
                ],
                &frontier,
                edge_kind::CONTROL,
            );
            let mut changed = false;
            for i in 0..words {
                let old = frontier[i];
                frontier[i] |= next[i];
                if frontier[i] != old {
                    changed = true;
                }
            }
            iters += 1;
            if !changed {
                break;
            }
        }
        assert!(
            iters > 2,
            "fixpoint on chain+back-edge must take >2 iterations; converged in {iters}"
        );
        assert_eq!(
            frontier,
            vec![0b1111],
            "all reachable nodes must be in the fixpoint"
        );
    }
}
