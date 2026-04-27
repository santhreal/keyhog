//! `csr_backward_traverse` — reverse BFS frontier step.
//!
//! Mirrors `super::csr_forward_traverse` but propagates along the
//! reverse edge direction: a destination in `frontier_in` lights up
//! every source that points at it. Used by dominator-tree
//! intersection and path_reconstruct frontier inversion.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::graph::csr_forward_traverse::bitset_words;
use crate::graph::program_graph::{
    ProgramGraphShape, BINDING_PRIMITIVE_START, NAME_EDGE_KIND_MASK, NAME_EDGE_OFFSETS,
    NAME_EDGE_TARGETS,
};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::graph::csr_backward_traverse";

/// Canonical binding index for the input frontier bitset.
pub const BINDING_FRONTIER_IN: u32 = BINDING_PRIMITIVE_START;
/// Canonical binding index for the output frontier bitset.
pub const BINDING_FRONTIER_OUT: u32 = BINDING_PRIMITIVE_START + 1;

/// Build the IR `Program`. Each invocation owns one `src` and, if
/// any of its outgoing edges' destinations are set in `frontier_in`
/// AND the edge mask intersects `allow_mask`, sets `src`'s bit in
/// `frontier_out`.
#[must_use]
pub fn csr_backward_traverse(
    shape: ProgramGraphShape,
    frontier_in: &str,
    frontier_out: &str,
    allow_mask: u32,
) -> Program {
    // AUDIT_2026-04-24 F-CBT-03: `dst = edge_targets[e]` is
    // bounds-checked against node_count before loading from
    // frontier_in, so a malformed edge list with dst >= node_count
    // cannot read past the frontier bitset on the GPU. Out-of-range
    // destinations are treated as "bit not set" (no hit), matching
    // the cpu_ref semantics that also drop dst_word >= frontier_in.len().
    let t = Expr::InvocationId { axis: 0 };
    let words = bitset_words(shape.node_count);
    let node_count = shape.node_count;

    let body = vec![
        Node::let_bind("src", t.clone()),
        Node::let_bind(
            "edge_start",
            Expr::load(NAME_EDGE_OFFSETS, Expr::var("src")),
        ),
        Node::let_bind(
            "edge_end",
            Expr::load(NAME_EDGE_OFFSETS, Expr::add(Expr::var("src"), Expr::u32(1))),
        ),
        Node::let_bind("hit", Expr::u32(0)),
        Node::loop_for(
            "e",
            Expr::var("edge_start"),
            Expr::var("edge_end"),
            vec![
                // Skip remaining edge checks once a hit has been found.
                // (The IR has no break; this avoids redundant loads.)
                Node::if_then(
                    Expr::eq(Expr::var("hit"), Expr::u32(0)),
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
                                // AUDIT_2026-04-24 F-CBT-03: guard load on
                                // `dst < node_count` to prevent OOB read on
                                // frontier_in when the edge list is malformed.
                                Node::if_then(
                                    Expr::lt(Expr::var("dst"), Expr::u32(node_count)),
                                    vec![
                                        Node::let_bind(
                                            "dst_word",
                                            Expr::load(
                                                frontier_in,
                                                Expr::shr(Expr::var("dst"), Expr::u32(5)),
                                            ),
                                        ),
                                        Node::let_bind(
                                            "dst_bit",
                                            Expr::shl(
                                                Expr::u32(1),
                                                Expr::bitand(Expr::var("dst"), Expr::u32(31)),
                                            ),
                                        ),
                                        Node::if_then(
                                            Expr::ne(
                                                Expr::bitand(
                                                    Expr::var("dst_word"),
                                                    Expr::var("dst_bit"),
                                                ),
                                                Expr::u32(0),
                                            ),
                                            vec![Node::assign("hit", Expr::u32(1))],
                                        ),
                                    ],
                                ),
                            ],
                        ),
                    ],
                ),
            ],
        ),
        Node::if_then(
            Expr::eq(Expr::var("hit"), Expr::u32(1)),
            vec![
                Node::let_bind("src_word_idx", Expr::shr(Expr::var("src"), Expr::u32(5))),
                Node::let_bind(
                    "src_bit",
                    Expr::shl(Expr::u32(1), Expr::bitand(Expr::var("src"), Expr::u32(31))),
                ),
                Node::let_bind(
                    "_prev",
                    Expr::atomic_or(
                        frontier_out,
                        Expr::var("src_word_idx"),
                        Expr::var("src_bit"),
                    ),
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

/// CPU reference: one reverse step. Returns a bitset where bit `u`
/// is set iff there exists an edge `u → v` with `allow_mask`-matching
/// kind AND `v` is set in `frontier_in`.
#[must_use]
pub fn cpu_ref(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
    allow_mask: u32,
) -> Vec<u32> {
    let words = crate::graph::csr_forward_traverse::bitset_words(node_count) as usize;
    let mut out = vec![0u32; words];
    for src in 0..node_count {
        // AUDIT_2026-04-24 F-CBT-01/02: same silent-masking pattern
        // as csr_forward_traverse::cpu_ref. Replace with explicit
        // expect so malformed CSR fails loudly.
        let edge_start = edge_offsets.get(src as usize).copied().expect(
            "csr_backward_traverse cpu_ref: edge_offsets[src] missing — \
                     malformed CSR; edge_offsets must have node_count + 1 entries",
        ) as usize;
        let edge_end = edge_offsets.get(src as usize + 1).copied().expect(
            "csr_backward_traverse cpu_ref: edge_offsets[src + 1] missing — \
                     malformed CSR",
        ) as usize;
        let mut hit = false;
        for e in edge_start..edge_end {
            let kind = edge_kind_mask.get(e).copied().expect(
                "csr_backward_traverse cpu_ref: edge_kind_mask[e] missing — \
                         malformed CSR; edge_kind_mask and edge_targets must have \
                         the same length",
            );
            if (kind & allow_mask) == 0 {
                continue;
            }
            let dst = edge_targets.get(e).copied().expect(
                "csr_backward_traverse cpu_ref: edge_targets[e] missing — \
                         malformed CSR",
            );
            let dst_word = (dst / 32) as usize;
            let dst_bit = 1u32 << (dst % 32);
            if dst_word < frontier_in.len() && (frontier_in[dst_word] & dst_bit) != 0 {
                hit = true;
                break;
            }
        }
        if hit {
            let src_word = (src / 32) as usize;
            let src_bit = 1u32 << (src % 32);
            if src_word < out.len() {
                out[src_word] |= src_bit;
            }
        }
    }
    out
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || csr_backward_traverse(ProgramGraphShape::new(4, 4), "fin", "fout", 0xFFFF_FFFF),
        Some(|| {
            // Same graph as forward test. frontier_in = {3}; after
            // one reverse step, frontier_out = {1, 2} (both point at
            // 3).
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0, 0, 0, 0]),
                to_bytes(&[0, 2, 3, 4, 4]),
                to_bytes(&[1, 2, 3, 3]),
                to_bytes(&[1, 1, 1, 1]),
                to_bytes(&[0, 0, 0, 0]),
                to_bytes(&[0b1000]),
                to_bytes(&[0]),
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0b0110])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_step_reaches_predecessors() {
        let got = cpu_ref(
            4,
            &[0, 2, 3, 4, 4],
            &[1, 2, 3, 3],
            &[1, 1, 1, 1],
            &[0b1000],
            0xFFFF_FFFF,
        );
        assert_eq!(got, vec![0b0110]);
    }
}
