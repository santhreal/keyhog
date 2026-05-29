use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use super::layout::{
    CSR_FORWARD_OR_CHANGED_CHANGED_BUFFER, CSR_FORWARD_OR_CHANGED_FRONTIER_BUFFER,
    CSR_FORWARD_OR_CHANGED_WORKGROUP_SIZE, OP_ID,
};
use crate::graph::program_graph::{
    ProgramGraphShape, NAME_EDGE_KIND_MASK, NAME_EDGE_OFFSETS, NAME_EDGE_TARGETS,
};

/// Parallel in-place expansion program for production fixed-point drivers.
///
/// Unlike [`csr_forward_or_changed`], this variant gives each source node its
/// own invocation instead of walking the whole CSR from one lane. The pass is
/// monotone: each dispatch may observe only the frontier bits visible at that
/// point in the dispatch, but every newly discovered destination is ORed into
/// the same resident accumulator and sets `changed[0]`. Re-dispatch until the
/// changed flag stays zero to compute the same reachability fixpoint without a
/// full frontier readback per iteration.
#[must_use]
pub fn csr_forward_or_changed_parallel(
    shape: ProgramGraphShape,
    frontier_out: &str,
    changed: &str,
    edge_kind_mask: u32,
) -> Program {
    let src = Expr::InvocationId { axis: 0 };
    let words = crate::bitset::bitset_words(shape.node_count);
    let body = vec![
        Node::let_bind("word_idx", Expr::shr(src.clone(), Expr::u32(5))),
        Node::let_bind(
            "bit_mask",
            Expr::shl(Expr::u32(1), Expr::bitand(src.clone(), Expr::u32(31))),
        ),
        Node::let_bind("src_word", Expr::load(frontier_out, Expr::var("word_idx"))),
        Node::if_then(
            Expr::ne(
                Expr::bitand(Expr::var("src_word"), Expr::var("bit_mask")),
                Expr::u32(0),
            ),
            vec![
                Node::let_bind("edge_start", Expr::load(NAME_EDGE_OFFSETS, src.clone())),
                Node::let_bind(
                    "edge_end",
                    Expr::load(NAME_EDGE_OFFSETS, Expr::add(src.clone(), Expr::u32(1))),
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
                                            vec![Node::let_bind(
                                                "_changed",
                                                Expr::atomic_or(
                                                    changed,
                                                    Expr::u32(0),
                                                    Expr::u32(1),
                                                ),
                                            )],
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
            frontier_out,
            CSR_FORWARD_OR_CHANGED_FRONTIER_BUFFER,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(words.max(1)),
    );
    buffers.push(
        BufferDecl::storage(
            changed,
            CSR_FORWARD_OR_CHANGED_CHANGED_BUFFER,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(1),
    );
    Program::wrapped(
        buffers,
        CSR_FORWARD_OR_CHANGED_WORKGROUP_SIZE,
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(
                Expr::lt(src.clone(), Expr::u32(shape.node_count)),
                body,
            )]),
        }],
    )
}
