//! `csr_forward_traverse` — one BFS frontier step over a
//! `super::program_graph::ProgramGraph`.
//!
//! Given an input frontier bitset (`frontier_in`) and a per-edge
//! allow-mask, the primitive emits the next frontier: every node
//! that has at least one predecessor in `frontier_in` reached via
//! an edge whose `edge_kind_mask` intersects the allowed mask.
//!
//! One dispatch is one step. Transitive closure is driven by
//! composing with `super::super::bitset` primitives and
//! `super::super::fixpoint::bitset_fixpoint`.
//!
//! CPU reference + witness ship alongside so the conform harness
//! can exercise the primitive end-to-end without GPU hardware.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::graph::program_graph::{
    ProgramGraphShape, BINDING_PRIMITIVE_START, NAME_EDGE_KIND_MASK, NAME_EDGE_OFFSETS,
    NAME_EDGE_TARGETS,
};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::graph::csr_forward_traverse";

/// Canonical binding index for the input frontier bitset.
pub const BINDING_FRONTIER_IN: u32 = BINDING_PRIMITIVE_START;
/// Canonical binding index for the output frontier bitset.
pub const BINDING_FRONTIER_OUT: u32 = BINDING_PRIMITIVE_START + 1;

/// Number of u32 words needed to hold a bitset over `node_count`
/// nodes (one bit per node, packed 32-per-word, rounded up).
///
/// Delegates to `crate::bitset::bitset_words` so CSR traversal and
/// bitset primitives share one overflow-safe sizing rule.
#[must_use]
pub const fn bitset_words(node_count: u32) -> u32 {
    crate::bitset::bitset_words(node_count)
}

/// Build the IR `Program` for one BFS forward step.
///
/// Each invocation owns one source node `src`. For each outgoing edge
/// whose `edge_kind_mask` intersects `allow_mask`, the program computes
/// `dst = edge_targets[e]` and atomically ORs the destination bit into
/// `frontier_out`. Transitive closure is driven by composing this step
/// with `bitset_fixpoint`.
///
/// Backward-edge iteration would be cheap given a CSC side-car; for
/// forward-only CSR, the atomic-OR path keeps the primitive
/// substrate-neutral without requiring two index layouts.
///
/// `dst` is bounds-checked against `shape.node_count` before
/// `atomic_or` so malformed edge lists cannot write outside the
/// node-indexed `frontier_out` bitset.
#[must_use]
pub fn csr_forward_traverse(
    shape: ProgramGraphShape,
    frontier_in: &str,
    frontier_out: &str,
    allow_mask: u32,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let words = bitset_words(shape.node_count);

    let body = vec![
        Node::let_bind("src", t.clone()),
        Node::let_bind("word_idx", Expr::shr(Expr::var("src"), Expr::u32(5))),
        Node::let_bind(
            "bit_mask",
            Expr::shl(Expr::u32(1), Expr::bitand(Expr::var("src"), Expr::u32(31))),
        ),
        Node::let_bind("src_word", Expr::load(frontier_in, Expr::var("word_idx"))),
        // Only proceed if this source lane is in the input frontier.
        Node::if_then(
            Expr::ne(
                Expr::bitand(Expr::var("src_word"), Expr::var("bit_mask")),
                Expr::u32(0),
            ),
            vec![
                Node::let_bind(
                    "edge_start",
                    Expr::load(NAME_EDGE_OFFSETS, Expr::var("src")),
                ),
                Node::let_bind(
                    "edge_end",
                    Expr::load(NAME_EDGE_OFFSETS, Expr::add(Expr::var("src"), Expr::u32(1))),
                ),
                Node::loop_for(
                    "e",
                    Expr::var("edge_start"),
                    Expr::var("edge_end"),
                    vec![
                        Node::let_bind(
                            "kind_mask",
                            Expr::load(NAME_EDGE_KIND_MASK, Expr::var("e")),
                        ),
                        Node::if_then(
                            Expr::ne(
                                Expr::bitand(Expr::var("kind_mask"), Expr::u32(allow_mask)),
                                Expr::u32(0),
                            ),
                            vec![
                                Node::let_bind(
                                    "dst",
                                    Expr::load(NAME_EDGE_TARGETS, Expr::var("e")),
                                ),
                                Node::if_then(
                                    Expr::lt(Expr::var("dst"), Expr::u32(shape.node_count)),
                                    vec![
                                        Node::let_bind(
                                            "dst_word_idx",
                                            Expr::shr(Expr::var("dst"), Expr::u32(5)),
                                        ),
                                        Node::let_bind(
                                            "dst_bit",
                                            Expr::shl(
                                                Expr::u32(1),
                                                Expr::bitand(Expr::var("dst"), Expr::u32(31)),
                                            ),
                                        ),
                                        Node::let_bind(
                                            "_prev",
                                            Expr::atomic_or(
                                                frontier_out,
                                                Expr::var("dst_word_idx"),
                                                Expr::var("dst_bit"),
                                            ),
                                        ),
                                    ],
                                ),
                            ],
                        ),
                    ],
                ),
            ],
        ),
    ];

    let mut buffers = shape.read_only_buffers();
    buffers.push(
        BufferDecl::storage(
            frontier_in,
            BINDING_FRONTIER_IN,
            BufferAccess::ReadOnly,
            DataType::U32,
        )
        .with_count(words),
    );
    buffers.push(
        BufferDecl::storage(
            frontier_out,
            BINDING_FRONTIER_OUT,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(words),
    );

    Program::wrapped(
        buffers,
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(
                Expr::lt(t.clone(), Expr::u32(shape.node_count)),
                body,
            )]),
        }],
    )
}

/// CPU reference: one forward step. Returns a fresh bitset where bit
/// `v` is set iff any predecessor `u` with `frontier_in` bit set has
/// an edge `u → v` whose `edge_kind_mask[e] & allow_mask != 0`.
#[must_use]
pub fn cpu_ref(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
    allow_mask: u32,
) -> Vec<u32> {
    let words = bitset_words(node_count) as usize;
    let mut out = vec![0u32; words];
    let expected_offsets = node_count as usize + 1;
    assert_eq!(
        edge_offsets.len(),
        expected_offsets,
        "Fix: csr_forward_traverse cpu_ref requires edge_offsets.len() == node_count + 1"
    );
    let edge_count = edge_offsets.last().copied().unwrap_or_default() as usize;
    assert!(
        edge_targets.len() >= edge_count,
        "Fix: csr_forward_traverse cpu_ref requires edge_targets to contain every CSR edge"
    );
    assert!(
        edge_kind_mask.len() >= edge_count,
        "Fix: csr_forward_traverse cpu_ref requires edge_kind_mask to contain every CSR edge"
    );
    for src in 0..node_count {
        let word_idx = (src / 32) as usize;
        let bit_mask = 1u32 << (src % 32);
        if word_idx >= frontier_in.len() {
            continue;
        }
        if (frontier_in[word_idx] & bit_mask) == 0 {
            continue;
        }
        let edge_start = edge_offsets[src as usize] as usize;
        let edge_end = edge_offsets[src as usize + 1] as usize;
        for e in edge_start..edge_end {
            let kind = edge_kind_mask[e];
            if (kind & allow_mask) == 0 {
                continue;
            }
            let dst = edge_targets[e];
            if dst < node_count {
                let dst_word = (dst / 32) as usize;
                let dst_bit = 1u32 << (dst % 32);
                out[dst_word] |= dst_bit;
            }
        }
    }
    out
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || csr_forward_traverse(ProgramGraphShape::new(4, 4), "fin", "fout", 0xFFFF_FFFF),
        Some(|| {
            // Graph: 0→1, 0→2, 1→3, 2→3. Start frontier = {0}.
            // Expected out frontier = {1, 2}.
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0, 0, 0, 0]),          // pg_nodes
                to_bytes(&[0, 2, 3, 4, 4]),       // pg_edge_offsets
                to_bytes(&[1, 2, 3, 3]),          // pg_edge_targets
                to_bytes(&[1, 1, 1, 1]),          // pg_edge_kind_mask
                to_bytes(&[0, 0, 0, 0]),          // pg_node_tags
                to_bytes(&[0b0001]),              // frontier_in = {0}
                to_bytes(&[0]),                   // frontier_out
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // After one forward step starting from {0}: frontier = {1, 2}.
            vec![vec![to_bytes(&[0b0110])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_step_reaches_immediate_successors() {
        // 0→1, 0→2, 1→3, 2→3
        let got = cpu_ref(
            4,
            &[0, 2, 3, 4, 4],
            &[1, 2, 3, 3],
            &[1, 1, 1, 1],
            &[0b0001],
            0xFFFF_FFFF,
        );
        assert_eq!(got, vec![0b0110]);
    }

    #[test]
    fn edge_mask_filters_disallowed_edges() {
        // Same graph but one edge (0→1) has mask 0b10, others 0b01.
        // Allow only 0b01: out frontier should exclude node 1.
        let got = cpu_ref(
            4,
            &[0, 2, 3, 4, 4],
            &[1, 2, 3, 3],
            &[0b10, 0b01, 0b01, 0b01],
            &[0b0001],
            0b01,
        );
        assert_eq!(got, vec![0b0100]);
    }

    #[test]
    fn empty_frontier_produces_empty_output() {
        let got = cpu_ref(
            4,
            &[0, 2, 3, 4, 4],
            &[1, 2, 3, 3],
            &[1, 1, 1, 1],
            &[0],
            0xFFFF_FFFF,
        );
        assert_eq!(got, vec![0]);
    }
}
