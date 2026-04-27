//! `bounded_by_comparison` — Tier-3 shim over
//! [`vyre_primitives::graph::csr_backward_traverse`] with the
//! `DOMINANCE` edge-kind mask.
//!
//! AUDIT_2026-04-24 F-BBC-02 (doc fix): the primitive computes
//! reverse reachability along dominance edges — i.e. the set of
//! dominance-tree *ancestors* of each node in `frontier_in`. The
//! stdlib rule intersects that ancestor set with the bound-check
//! NodeSet. Prior doc text claimed "every access is reachable
//! backward along dominance edges from some bound check," which
//! describes descendant reachability, not ancestor reachability —
//! the directions were swapped. Correct framing: "for each access
//! in `frontier_in`, compute the dominators via ancestor walk,
//! then a bound-check intersects to prove the access is covered
//! by some dominating bound-check."

use vyre::ir::Program;
use vyre_primitives::graph::csr_backward_traverse::csr_backward_traverse;
use vyre_primitives::graph::program_graph::ProgramGraphShape;
use vyre_primitives::predicate::edge_kind;

use crate::region::{reparent_program_children, wrap_anonymous};

const OP_ID: &str = "vyre-libs::security::bounded_by_comparison";

/// Build one reverse-traversal step filtered to dominance edges.
#[must_use]
pub fn bounded_by_comparison(
    shape: ProgramGraphShape,
    frontier_in: &str,
    frontier_out: &str,
) -> Program {
    let primitive = csr_backward_traverse(shape, frontier_in, frontier_out, edge_kind::DOMINANCE);
    Program::wrapped(
        primitive.buffers().to_vec(),
        primitive.workgroup_size(),
        vec![wrap_anonymous(
            OP_ID,
            reparent_program_children(&primitive, OP_ID),
        )],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || bounded_by_comparison(ProgramGraphShape::new(4, 4), "fin", "fout"),
        test_inputs: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // Graph with self-loops on dominance edges: 0→0, 1→1, 2→2, 3→3.
            // Starting frontier {0} is already a fixed point.
            vec![vec![
                to_bytes(&[0, 0, 0, 0]),          // pg_nodes
                to_bytes(&[0, 1, 2, 3, 4]),       // pg_edge_offsets
                to_bytes(&[0, 1, 2, 3]),          // pg_edge_targets
                to_bytes(&[16, 16, 16, 16]),      // pg_edge_kind_mask (DOMINANCE)
                to_bytes(&[0, 0, 0, 0]),          // pg_node_tags
                to_bytes(&[0b0001]),              // fin = {0}
                to_bytes(&[0b0001]),              // fout = {0}
            ]]
        }),
        expected_output: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0b0001])]]
        }),
    }
}

inventory::submit! {
    // AUDIT_2026-04-24 F-BBC-01: raised from 64 to 4096 so deep
    // dominance trees don't silently truncate; same reasoning as
    // dominator_tree.
    crate::harness::ConvergenceContract {
        op_id: OP_ID,
        max_iterations: 4096,
    }
}
