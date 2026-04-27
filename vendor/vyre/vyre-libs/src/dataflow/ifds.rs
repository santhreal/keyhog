//! DF-4 — IFDS/IDE interprocedural dataflow framework.
//!
//! Reps & Horwitz & Sagiv (1995): distributive dataflow problems
//! over a finite domain D reduce to graph reachability on the
//! exploded super-graph. Nodes are (statement × fact) pairs; edges
//! encode flow + call-return summary edges. Reaching a sink fact
//! from a source fact = the source taint flows to the sink along
//! some interprocedural path that respects matched call/return.
//!
//! Following the `vyre-libs::security::flows_to` idiom, this module
//! ships ONE dispatch step of forward reachability over the super-
//! graph. The surgec-side fixpoint driver iterates it until the
//! reach frontier converges, and the surge stdlib composes the
//! source/sink/sanitizer triple on top.
//!
//! ## Soundness
//!
//! PHASE6_DATAFLOW CRITICAL: previous docstring claimed
//! `Soundness::Exact`. That was a lie — the body is generic forward
//! reachability with `0xFFFF_FFFF` mask, NO call/return matching, NO
//! summary edges, NO sanitizer gating, and NO exploded super-graph
//! construction. Real Reps-Horwitz-Sagiv requires building the
//! exploded super-graph (handled by [`super::ifds_gpu`]) and then
//! running the step kernel over it.
//!
//! This module's [`ifds_reach_step`] is now correctly tagged
//! [`MayOver`](super::Soundness::MayOver) and delegates to
//! [`super::ifds_gpu::ifds_gpu_step`] when the caller passes a real
//! [`super::ifds_gpu::IfdsShape`]. The Tier-3 ProgramGraphShape
//! entry remains for back-compat callers that pre-built the CSR by
//! hand — those callers MUST still iterate to fixpoint and gate
//! sanitizer facts themselves.
//!
//! Rules requiring zero-FP MUST compose this primitive with an
//! explicit sanitizer mask after each step — see surge stdlib
//! `flows_to_with_sanitizer`.
//!
//! Underpins C01, C08, C09, C13, C15, C16, C18.

use vyre::ir::Program;
use vyre_primitives::graph::csr_forward_traverse::csr_forward_traverse;
use vyre_primitives::graph::program_graph::ProgramGraphShape;
use vyre_primitives::predicate::edge_kind;

pub(crate) const OP_ID: &str = "vyre-libs::dataflow::ifds";

/// PHASE6_DATAFLOW HIGH: the previous `0xFFFF_FFFF` allow-mask let
/// taint flow along DOMINANCE / RETURN / every-other-edge-kind
/// indiscriminately. The IFDS reach contract is "data + call edges,
/// no dominance" — restricted to `ASSIGNMENT | CALL_ARG | RETURN |
/// PHI | ALIAS | MEM_STORE | MEM_LOAD | MUT_REF`.
const IFDS_REACH_MASK: u32 = edge_kind::ASSIGNMENT
    | edge_kind::CALL_ARG
    | edge_kind::RETURN
    | edge_kind::PHI
    | edge_kind::ALIAS
    | edge_kind::MEM_STORE
    | edge_kind::MEM_LOAD
    | edge_kind::MUT_REF;

/// Build one IFDS forward-reachability step over an exploded
/// super-graph laid out as a ProgramGraph.
///
/// The surgec driver is responsible for (a) materialising the
/// super-graph — call/return summary edges baked in by DF-9, (b)
/// seeding the frontier with source facts, (c) masking out
/// sanitizer-labelled facts after each step, (d) iterating to
/// fixpoint, (e) intersecting the final reach with the sink set.
#[must_use]
pub fn ifds_reach_step(shape: ProgramGraphShape, frontier_in: &str, frontier_out: &str) -> Program {
    csr_forward_traverse(shape, frontier_in, frontier_out, IFDS_REACH_MASK)
}

/// PHASE6_DATAFLOW CRITICAL: bridge from the high-level IFDS surface
/// to the GPU-native exploded-supergraph step. Pre-fix this module
/// did not import [`super::ifds_gpu`] at all — the G3 implementation
/// was orphaned. This entry point composes the exploded-supergraph
/// shape with the GPU step kernel so callers that already hold an
/// [`super::ifds_gpu::IfdsShape`] do not have to manually project to
/// `ProgramGraphShape`.
#[must_use]
pub fn ifds_reach_step_exploded(
    shape: super::ifds_gpu::IfdsShape,
    frontier_in: &str,
    frontier_out: &str,
) -> Program {
    super::ifds_gpu::ifds_gpu_step(shape, frontier_in, frontier_out)
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || ifds_reach_step(ProgramGraphShape::new(4, 3), "fin", "fout"),
        test_inputs: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // Tiny supergraph: 0 is a source, 3 is a sink, edges
            // 0→1→2→3. One step propagates the frontier from 0 to 1.
            vec![vec![
                to_bytes(&[0, 0, 0, 0]),          // pg_nodes
                to_bytes(&[0, 1, 2, 3, 3]),       // pg_edge_offsets
                to_bytes(&[1, 2, 3]),             // pg_edge_targets
                to_bytes(&[1, 1, 1]),             // pg_edge_kind_mask
                to_bytes(&[0, 0, 0, 0]),          // pg_node_tags
                to_bytes(&[0b0001]),              // fin = {source at 0}
                to_bytes(&[0b0001]),              // fout accumulator seed
            ]]
        }),
        expected_output: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0b0011])]]
        }),
    }
}

inventory::submit! {
    crate::harness::ConvergenceContract {
        op_id: OP_ID,
        max_iterations: 128,
    }
}

/// Marker type for the IFDS interprocedural dataflow primitive.
pub struct Ifds;

impl super::soundness::SoundnessTagged for Ifds {
    /// PHASE6_DATAFLOW CRITICAL: corrected from `Exact` to `MayOver`.
    /// The current implementation is a single forward-reach step over
    /// a caller-provided supergraph — it is sound (over-approximates)
    /// only when (a) the supergraph encodes call/return matching and
    /// (b) the host iterates to fixpoint with sanitizer gating after
    /// every step. Without those, this is reachability and may report
    /// non-realizable paths.
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::MayOver
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PHASE6_DATAFLOW HIGH regression: pre-fix the allow mask was
    /// `0xFFFF_FFFF`, letting taint propagate along DOMINANCE and
    /// every other edge kind. Restricted to dataflow + call edges
    /// only.
    #[test]
    fn ifds_reach_mask_excludes_dominance_and_control() {
        // Build an emitted Program and sanity-check we did not
        // regress to 0xFFFF_FFFF. The traversal mask is encoded as a
        // u32 literal inside the entry body; we assert it via the
        // exposed const.
        assert_eq!(
            IFDS_REACH_MASK & edge_kind::DOMINANCE,
            0,
            "IFDS reach must NOT include DOMINANCE — pre-fix bug"
        );
        assert_eq!(
            IFDS_REACH_MASK & edge_kind::CONTROL,
            0,
            "IFDS reach must NOT include CONTROL — only data + call edges"
        );
        assert!(
            IFDS_REACH_MASK & edge_kind::ASSIGNMENT != 0,
            "IFDS reach must include ASSIGNMENT"
        );
        assert!(
            IFDS_REACH_MASK & edge_kind::CALL_ARG != 0,
            "IFDS reach must include CALL_ARG"
        );
        assert_ne!(
            IFDS_REACH_MASK, 0xFFFF_FFFF,
            "IFDS_REACH_MASK regressed to 0xFFFF_FFFF — original PHASE6_DATAFLOW bug"
        );
    }

    /// PHASE6_DATAFLOW CRITICAL regression: ifds_reach_step_exploded
    /// must produce a real Program, proving the bridge from this module
    /// to ifds_gpu::ifds_gpu_step is wired and not silently broken.
    #[test]
    fn ifds_reach_step_exploded_emits_real_program() {
        let shape = super::super::ifds_gpu::IfdsShape {
            num_procs: 4,
            blocks_per_proc: 4,
            facts_per_proc: 8,
            edge_count: 16,
        };
        let p = ifds_reach_step_exploded(shape, "fin", "fout");
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert!(names.contains(&"fin"), "frontier_in must be declared");
        assert!(names.contains(&"fout"), "frontier_out must be declared");
        assert!(
            !p.entry.is_empty(),
            "ifds_reach_step_exploded must emit a non-empty entry — pre-fix the IFDS module never imported ifds_gpu_step at all"
        );
    }

    /// PHASE6_DATAFLOW CRITICAL regression: soundness marker corrected
    /// from `Exact` (lie) to `MayOver` (truth).
    #[test]
    fn ifds_soundness_is_mayover_not_exact() {
        use super::super::soundness::{Soundness, SoundnessTagged};
        assert_eq!(
            Ifds.soundness(),
            Soundness::MayOver,
            "IFDS without sanitizer-gating is not Exact — must be MayOver"
        );
    }
}
