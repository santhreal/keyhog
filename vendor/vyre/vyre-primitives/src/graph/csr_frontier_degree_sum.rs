//! `csr_frontier_degree_sum` — total outgoing-edge count of an active
//! BFS frontier on a `super::program_graph::ProgramGraph`.
//!
//! `csr_forward_traverse` launches one thread per *source node*, which
//! catastrophically load-imbalances on power-law graphs (one vertex with
//! 1M neighbors monopolises one thread while everyone else does zero
//! work). Load-balanced expansion launches one thread per *active edge*
//! instead; the host needs this count to launch the exact grid.
//!
//! This primitive computes that count. Given:
//!   - `frontier_in` — a packed bitset over `node_count`, one bit per
//!     active source node.
//!   - `pg_edge_offsets` — the canonical CSR row pointers from
//!     `ProgramGraph`.
//!
//! It emits a single u32 scalar:
//!   - `degree_sum_out[0] = ∑_{v ∈ frontier_in} (edge_offsets[v+1] − edge_offsets[v])`
//!
//! The host reads this scalar between dispatches and uses it to size
//! the next load-balanced expansion kernel. The CPU reference at the
//! bottom of this file documents the contract; the parity harness runs
//! both implementations on the same input.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::graph::program_graph::{ProgramGraphShape, BINDING_PRIMITIVE_START, NAME_EDGE_OFFSETS};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::graph::csr_frontier_degree_sum";

/// Canonical binding index for the input frontier bitset.
pub const BINDING_FRONTIER_IN: u32 = BINDING_PRIMITIVE_START;
/// Canonical binding index for the output degree-sum scalar.
pub const BINDING_DEGREE_SUM_OUT: u32 = BINDING_PRIMITIVE_START + 1;

/// Build the IR `Program` that computes `degree_sum_out[0]` =
/// total outgoing-edge count over the active frontier.
///
/// One thread per node. Each thread:
///   1. Loads its bit from `frontier_in`. If clear, exits.
///   2. Computes its degree as `edge_offsets[gid+1] - edge_offsets[gid]`.
///   3. Atomically adds the degree into `degree_sum_out[0]`.
#[must_use]
pub fn csr_frontier_degree_sum(shape: ProgramGraphShape) -> Program {
    let frontier_in = "frontier_in";
    let degree_sum_out = "degree_sum_out";

    let body = vec![
        Node::let_bind("src", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(Expr::var("src"), Expr::u32(shape.node_count)),
            vec![
                Node::let_bind("word_idx", Expr::shr(Expr::var("src"), Expr::u32(5))),
                Node::let_bind(
                    "bit_mask",
                    Expr::shl(Expr::u32(1), Expr::bitand(Expr::var("src"), Expr::u32(31))),
                ),
                Node::let_bind("src_word", Expr::load(frontier_in, Expr::var("word_idx"))),
                // Only proceed if this source lane is in the active frontier.
                Node::if_then(
                    Expr::ne(
                        Expr::bitand(Expr::var("src_word"), Expr::var("bit_mask")),
                        Expr::u32(0),
                    ),
                    vec![
                        // degree = edge_offsets[src+1] - edge_offsets[src]
                        Node::let_bind("off_lo", Expr::load(NAME_EDGE_OFFSETS, Expr::var("src"))),
                        Node::let_bind(
                            "off_hi",
                            Expr::load(
                                NAME_EDGE_OFFSETS,
                                Expr::add(Expr::var("src"), Expr::u32(1)),
                            ),
                        ),
                        Node::let_bind(
                            "degree",
                            Expr::sub(Expr::var("off_hi"), Expr::var("off_lo")),
                        ),
                        Node::let_bind(
                            "_old",
                            Expr::atomic_add(degree_sum_out, Expr::u32(0), Expr::var("degree")),
                        ),
                    ],
                ),
            ],
        ),
    ];

    let mut buffers = shape.read_only_buffers();
    let frontier_words = crate::bitset::bitset_words(shape.node_count);
    buffers.push(
        BufferDecl::storage(
            frontier_in,
            BINDING_FRONTIER_IN,
            BufferAccess::ReadOnly,
            DataType::U32,
        )
        .with_count(frontier_words),
    );
    buffers.push(
        BufferDecl::storage(
            degree_sum_out,
            BINDING_DEGREE_SUM_OUT,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(1),
    );

    let entry = vec![Node::Region {
        generator: Ident::from(OP_ID),
        source_region: None,
        body: Arc::new(body),
    }];
    Program::wrapped(buffers, [256, 1, 1], entry)
}

/// CPU reference. `frontier_in` is a packed bitset over `node_count`
/// with one bit per source node; `edge_offsets` is the CSR row pointer
/// array of length `node_count + 1`. Returns the total outgoing-edge
/// count over active frontier nodes.
#[must_use]
pub fn csr_frontier_degree_sum_cpu(
    frontier_in: &[u32],
    edge_offsets: &[u32],
    node_count: u32,
) -> u32 {
    let mut total = 0u32;
    for src in 0..node_count {
        let word = (src / 32) as usize;
        let bit = src % 32;
        if frontier_in.get(word).copied().unwrap_or(0) & (1u32 << bit) == 0 {
            continue;
        }
        let lo = edge_offsets.get(src as usize).copied().unwrap_or(0);
        let hi = edge_offsets.get((src + 1) as usize).copied().unwrap_or(lo);
        total = total.saturating_add(hi.saturating_sub(lo));
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_ref_empty_frontier_emits_zero() {
        let frontier = vec![0u32];
        let edge_offsets = vec![0u32, 3, 7, 9, 9, 12]; // 5 nodes, 12 edges
        assert_eq!(csr_frontier_degree_sum_cpu(&frontier, &edge_offsets, 5), 0);
    }

    #[test]
    fn cpu_ref_single_node_frontier_returns_its_degree() {
        // Node 0 in frontier. Its degree = edge_offsets[1] - edge_offsets[0] = 3.
        let frontier = vec![1u32];
        let edge_offsets = vec![0u32, 3, 7, 9, 9, 12];
        assert_eq!(csr_frontier_degree_sum_cpu(&frontier, &edge_offsets, 5), 3);
    }

    #[test]
    fn cpu_ref_full_frontier_sums_all_degrees() {
        // All 5 nodes in frontier.
        let frontier = vec![0b11111u32];
        let edge_offsets = vec![0u32, 3, 7, 9, 9, 12];
        // Degrees: 3, 4, 2, 0, 3 → sum 12.
        assert_eq!(csr_frontier_degree_sum_cpu(&frontier, &edge_offsets, 5), 12);
    }

    #[test]
    fn cpu_ref_handles_isolated_nodes_in_frontier() {
        // Node 3 has 0 outgoing edges. Frontier = just {3}. Sum should be 0.
        let frontier = vec![0b1000u32];
        let edge_offsets = vec![0u32, 3, 7, 9, 9, 12];
        assert_eq!(csr_frontier_degree_sum_cpu(&frontier, &edge_offsets, 5), 0);
    }

    #[test]
    fn cpu_ref_partial_frontier_sums_subset() {
        // Frontier = {0, 2}. Degrees 3 + 2 = 5.
        let frontier = vec![0b00101u32];
        let edge_offsets = vec![0u32, 3, 7, 9, 9, 12];
        assert_eq!(csr_frontier_degree_sum_cpu(&frontier, &edge_offsets, 5), 5);
    }

    #[test]
    fn cpu_ref_multi_word_frontier() {
        // 64 nodes, two-word bitset. Set bits at 0, 31, 32, 63. Degrees 1 each.
        let frontier = vec![
            0b1u32 | (1u32 << 31), // word 0: bits 0 and 31
            0b1u32 | (1u32 << 31), // word 1: bits 0 and 31 (= absolute 32 and 63)
        ];
        let edge_offsets = (0..=64u32).collect::<Vec<_>>();
        // Each node has degree 1 (offsets are [0, 1, 2, ..., 64]).
        // Frontier has 4 active nodes; sum = 4.
        assert_eq!(csr_frontier_degree_sum_cpu(&frontier, &edge_offsets, 64), 4);
    }

    #[test]
    fn build_program_returns_well_formed_program() {
        let shape = ProgramGraphShape::new(64, 128);
        let program = csr_frontier_degree_sum(shape);
        assert!(
            program.buffers().len() >= 6,
            "expects pg buffers + frontier_in + degree_sum_out"
        );
        assert_eq!(program.workgroup_size(), [256, 1, 1]);
    }

    #[test]
    fn op_id_is_canonical_and_stable() {
        // Op ids appear in serialized OpDef metadata + bench attribution;
        // changing it is a wire-format-visible change.
        assert_eq!(OP_ID, "vyre-primitives::graph::csr_frontier_degree_sum");
    }
}
