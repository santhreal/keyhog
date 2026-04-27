//! `flows_to` — Tier-3 shim over
//! [`vyre_primitives::graph::csr_forward_traverse`].
//!
//! The taint-reachability semantics (*does taint flow from source
//! NodeSet to sink NodeSet given this ProgramGraph?*) live in the
//! SURGE stdlib at `surgec/rules/stdlib/flows_to.srg`:
//!
//! ```text
//! rec reached = source ∪ csr_forward_traverse(reached, all_edges)
//!   where fixpoint on reached
//! ```
//!
//! vyre-libs ships one dispatch step that surgec's fixpoint driver
//! iterates. Op id stays stable; the dead v2 edges_from/edges_to
//! signature from the inert-stub era has been deleted — the shim
//! now takes only the canonical frontier / sink buffer names.

use vyre::ir::Program;
use vyre_primitives::graph::csr_forward_traverse::csr_forward_traverse;
use vyre_primitives::graph::program_graph::ProgramGraphShape;
use vyre_primitives::predicate::edge_kind;

const OP_ID: &str = "vyre-libs::security::flows_to";

/// Bitmask of edge kinds that represent genuine dataflow edges.
/// Per AUDIT_2026-04-24 F-FT-01 (kimi) a previous `0xFFFF_FFFF`
/// over-approximation caused taint to propagate along CONTROL and
/// DOMINANCE edges, producing massive false-positive noise at
/// internet scale. Restricted now to the set surge's stdlib
/// flows_to.srg explicitly enumerates.
pub const FLOWS_TO_MASK: u32 = edge_kind::ASSIGNMENT
    | edge_kind::CALL_ARG
    | edge_kind::RETURN
    | edge_kind::PHI
    | edge_kind::ALIAS
    | edge_kind::MEM_STORE
    | edge_kind::MEM_LOAD
    | edge_kind::MUT_REF;

/// Build one forward-traversal step along DATAFLOW edges only.
/// `frontier_in` reads the current reached set, `frontier_out`
/// receives the union of nodes reachable in one more dataflow hop.
#[must_use]
pub fn flows_to(shape: ProgramGraphShape, frontier_in: &str, frontier_out: &str) -> Program {
    csr_forward_traverse(shape, frontier_in, frontier_out, FLOWS_TO_MASK)
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || flows_to(ProgramGraphShape::new(4, 3), "fin", "fout"),
        test_inputs: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // Linear chain 0 → 1 → 2 → 3. Starting frontier {0}.
            // `fout` starts as the accumulator frontier so the
            // convergence lens monotonically grows {0,1,2,3}.
            vec![vec![
                to_bytes(&[0, 0, 0, 0]),          // pg_nodes
                to_bytes(&[0, 1, 2, 3, 3]),       // pg_edge_offsets: 0→{1}, 1→{2}, 2→{3}, 3→{}
                to_bytes(&[1, 2, 3]),             // pg_edge_targets
                to_bytes(&[
                    edge_kind::ASSIGNMENT,
                    edge_kind::ASSIGNMENT,
                    edge_kind::ASSIGNMENT,
                ]),                               // pg_edge_kind_mask — all dataflow
                to_bytes(&[0, 0, 0, 0]),          // pg_node_tags
                to_bytes(&[0b0001]),              // fin = {0}
                to_bytes(&[0b0001]),              // fout accumulator seed = {0}
            ]]
        }),
        expected_output: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // One forward-reach step from {0}: the step writes {1}
            // into the accumulator. A no-op that leaves fout at {0}
            // fails this oracle.
            vec![vec![to_bytes(&[0b0011])]]
        }),
    }
}

inventory::submit! {
    // AUDIT_2026-04-24 F-FT-03: max_iterations raised from 64 to
    // 4096 so deep call graphs (Linux kernel-scale code) don't hit
    // a silent truncation ceiling during the closure. The fixpoint
    // driver aborts early whenever the frontier stops growing, so
    // a higher ceiling costs nothing on small graphs; the only
    // case where this matters is a pathologically deep reachability
    // walk, where the old 64-step cap was producing false negatives.
    crate::harness::ConvergenceContract {
        op_id: OP_ID,
        max_iterations: 4096,
    }
}
