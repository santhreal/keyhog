//! CSR frontier expansion over an in-place accumulator bitset.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::{GeneratorRef, Ident};
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::graph::program_graph::{
    ProgramGraphShape, BINDING_PRIMITIVE_START, NAME_EDGE_KIND_MASK, NAME_EDGE_OFFSETS,
    NAME_EDGE_TARGETS,
};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::graph::csr_forward_or_changed";

/// Build one in-place forward expansion pass over an accumulating frontier.
#[must_use]
pub fn csr_forward_or_changed_body(
    shape: ProgramGraphShape,
    frontier_out: &str,
    changed_var: &str,
    edge_kind_mask: u32,
) -> Vec<Node> {
    vec![
        Node::let_bind("src", Expr::gid_x()),
        Node::let_bind("word_idx", Expr::shr(Expr::var("src"), Expr::u32(5))),
        Node::let_bind(
            "bit_mask",
            Expr::shl(Expr::u32(1), Expr::bitand(Expr::var("src"), Expr::u32(31))),
        ),
        Node::let_bind("src_word", Expr::load(frontier_out, Expr::var("word_idx"))),
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
                                Expr::bitand(Expr::var("kind_mask"), Expr::u32(edge_kind_mask)),
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
                                            "old",
                                            Expr::atomic_or(
                                                frontier_out,
                                                Expr::var("dst_word_idx"),
                                                Expr::var("dst_bit"),
                                            ),
                                        ),
                                        Node::if_then(
                                            Expr::eq(
                                                Expr::bitand(
                                                    Expr::var("old"),
                                                    Expr::var("dst_bit"),
                                                ),
                                                Expr::u32(0),
                                            ),
                                            vec![Node::assign(changed_var, Expr::u32(1))],
                                        ),
                                    ],
                                ),
                            ],
                        ),
                    ],
                ),
            ],
        ),
    ]
}

/// Wrap one traversal pass as a child Region of `parent_op_id`.
#[must_use]
pub fn csr_forward_or_changed_child(
    parent_op_id: &str,
    shape: ProgramGraphShape,
    frontier_out: &str,
    changed_var: &str,
    edge_kind_mask: u32,
) -> Node {
    Node::Region {
        generator: Ident::from(OP_ID),
        source_region: Some(GeneratorRef {
            name: parent_op_id.to_string(),
        }),
        body: Arc::new(csr_forward_or_changed_body(
            shape,
            frontier_out,
            changed_var,
            edge_kind_mask,
        )),
    }
}

/// Standalone in-place expansion program for primitive conformance.
#[must_use]
pub fn csr_forward_or_changed(
    shape: ProgramGraphShape,
    frontier_out: &str,
    changed: &str,
    edge_kind_mask: u32,
) -> Program {
    let words = crate::bitset::bitset_words(shape.node_count);
    let mut body = vec![Node::let_bind("local_changed", Expr::u32(0))];
    body.extend(csr_forward_or_changed_body(
        shape,
        frontier_out,
        "local_changed",
        edge_kind_mask,
    ));
    body.push(Node::if_then(
        Expr::eq(Expr::var("local_changed"), Expr::u32(1)),
        vec![Node::let_bind(
            "_changed",
            Expr::atomic_or(changed, Expr::u32(0), Expr::u32(1)),
        )],
    ));
    let mut buffers = shape.read_only_buffers();
    buffers.push(
        BufferDecl::storage(
            frontier_out,
            BINDING_PRIMITIVE_START,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(words.max(1)),
    );
    buffers.push(
        BufferDecl::storage(
            changed,
            BINDING_PRIMITIVE_START + 1,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(1),
    );
    Program::wrapped(
        buffers,
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU reference for one in-place expansion pass.
#[must_use]
pub fn cpu_ref(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier: &[u32],
    allow_mask: u32,
) -> (Vec<u32>, u32) {
    let words = crate::bitset::bitset_words(node_count) as usize;
    let mut out = frontier.to_vec();
    out.resize(words, 0);
    let mut changed = 0u32;
    for src in 0..node_count as usize {
        let src_word = src / 32;
        let src_bit = 1u32 << (src % 32);
        if out[src_word] & src_bit == 0 {
            continue;
        }
        let start = edge_offsets.get(src).copied().unwrap_or(0) as usize;
        let end = edge_offsets.get(src + 1).copied().unwrap_or(start as u32) as usize;
        for edge in start..end.min(edge_targets.len()).min(edge_kind_mask.len()) {
            if edge_kind_mask[edge] & allow_mask == 0 {
                continue;
            }
            let dst = edge_targets[edge] as usize;
            if dst >= node_count as usize {
                continue;
            }
            let word = dst / 32;
            let bit = 1u32 << (dst % 32);
            let old = out[word];
            out[word] |= bit;
            if out[word] != old {
                changed = 1;
            }
        }
    }
    (out, changed)
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || csr_forward_or_changed(ProgramGraphShape::new(4, 4), "frontier", "changed", 1),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0, 0, 0, 0]),
                to_bytes(&[0, 2, 3, 4, 4]),
                to_bytes(&[1, 2, 3, 3]),
                to_bytes(&[1, 1, 1, 1]),
                to_bytes(&[0, 0, 0, 0]),
                to_bytes(&[0b0001]),
                to_bytes(&[0]),
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0b1111]), to_bytes(&[1])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_ref_expands_in_place_frontier_pass() {
        let (frontier, changed) = cpu_ref(
            4,
            &[0, 2, 3, 4, 4],
            &[1, 2, 3, 3],
            &[1, 1, 1, 1],
            &[0b0001],
            1,
        );
        assert_eq!(frontier, vec![0b1111]);
        assert_eq!(changed, 1);
    }
}
