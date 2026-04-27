//! `sanitized_by` — Tier-3 sanitizer-gated forward taint step.
//!
//! Semantics:
//!
//! ```text
//!   frontier_clean = frontier_in \ sanitizers_in       (set difference)
//!   frontier_out   = csr_forward_traverse(frontier_clean, FLOWS_TO_MASK)
//! ```
//!
//! Two stages, fused into one Program:
//!
//! 1. `frontier_clean = frontier_in & !sanitizers_in` via the new
//!    `bitset_and_not` primitive — one Region instead of two
//!    (`bitset_not` + `bitset_and`) — fewer scratch buffers, fewer
//!    dispatch-time bind-point allocations.
//! 2. `frontier_out = csr_forward_traverse(frontier_clean, …)`
//!    along genuine dataflow edges only (`FLOWS_TO_MASK`).
//!
//! Pre-fix this composed three primitives via `fuse_programs(...)`
//! and threaded an `__sanitized_by_allow__*` scratch buffer; the new
//! `bitset_and_not` collapses the first two stages into a single
//! Region with no scratch, eliminating one buffer + one dispatch
//! per call.

use vyre::ir::Program;
use vyre_foundation::execution_plan::fusion::fuse_programs;
use vyre_primitives::bitset::and_not::bitset_and_not;
use vyre_primitives::graph::csr_forward_traverse::{bitset_words, csr_forward_traverse};
use vyre_primitives::graph::program_graph::ProgramGraphShape;
use vyre_primitives::predicate::edge_kind;

use crate::region::{reparent_program_children, wrap_anonymous};
use crate::security::flows_to::FLOWS_TO_MASK;

const OP_ID: &str = "vyre-libs::security::sanitized_by";

/// Build one sanitizer-guarded forward-traversal step.
///
/// `sanitizers_in` names the bitset buffer holding the sanitizer
/// nodeset. The emitted Program AND-NOTs the sanitizers against the
/// current frontier before traversing dataflow edges.
///
/// Reduced from three primitives (`bitset_not` + `bitset_and` +
/// `csr_forward_traverse`) to two by composing the first stage as
/// the new `bitset_and_not` (`frontier_clean = frontier_in & !sanitizers_in`
/// in one Region). One fewer scratch buffer, one fewer dispatch.
#[must_use]
pub fn sanitized_by(
    shape: ProgramGraphShape,
    frontier_in: &str,
    sanitizers_in: &str,
    frontier_out: &str,
) -> Program {
    let words = bitset_words(shape.node_count);
    let clean_buf = format!("__sanitized_by_clean__{}", frontier_in);
    let and_not_prog = bitset_and_not(frontier_in, sanitizers_in, &clean_buf, words);
    let traverse = csr_forward_traverse(shape, &clean_buf, frontier_out, FLOWS_TO_MASK);
    let fused = fuse_programs(&[and_not_prog, traverse])
        .expect("sanitized_by: the two component programs must fuse cleanly");
    Program::wrapped(
        fused.buffers().to_vec(),
        fused.workgroup_size(),
        vec![wrap_anonymous(
            OP_ID,
            reparent_program_children(&fused, OP_ID),
        )],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || sanitized_by(ProgramGraphShape::new(4, 3), "fin", "san", "fout"),
        test_inputs: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // Linear 0→1→2→3 with node 1 marked sanitizer.
            vec![vec![
                to_bytes(&[0b0001]),              // 0: fin = {0}
                to_bytes(&[0b0010]),              // 1: san = {1}
                to_bytes(&[0b0000]),              // 2: internal clean scratch
                to_bytes(&[0, 0, 0, 0]),          // 3: pg_nodes
                to_bytes(&[0, 1, 2, 3, 3]),       // 4: pg_edge_offsets
                to_bytes(&[1, 2, 3]),             // 5: pg_edge_targets
                to_bytes(&[
                    edge_kind::ASSIGNMENT,
                    edge_kind::ASSIGNMENT,
                    edge_kind::ASSIGNMENT,
                ]),                               // 6: pg_edge_kind_mask
                to_bytes(&[0, 1, 0, 0]),          // 7: pg_node_tags: node 1 is sanitizer
                to_bytes(&[0b0001]),              // 8: fout accumulator seed = {0}
            ]]
        }),
        expected_output: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // One forward step from {0}: fout accumulator = {0,1}.
            vec![vec![
                to_bytes(&[0b0001]),              // clean_buf = fin & !san
                to_bytes(&[0b0011]),              // fout
            ]]
        }),
    }
}

inventory::submit! {
    // AUDIT_2026-04-24 F-SB-01: raised from 64 to 4096 so taint
    // sanitization on deep call chains doesn't truncate silently;
    // same reasoning as flows_to / taint_flow.
    crate::harness::ConvergenceContract {
        op_id: OP_ID,
        max_iterations: 4096,
    }
}
