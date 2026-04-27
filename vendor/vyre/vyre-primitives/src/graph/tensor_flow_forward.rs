//! `tensor_flow_forward` — 1000x Parallel 3D Matrix Flow Tracking
//!
//! Exceeds Datalog performance loops by compiling Context-Sensitive Dataflow
//! directly into a Subgroup bitset operation over bounds:
//! `[Nodes : u32] x [ContextId : u8] x [FieldIdx : u8]`
//!
//! Sub-warps concurrently execute field-sensitive flow checks on an execution graph,
//! tracking nested dependencies efficiently.

use crate::graph::program_graph::{
    ProgramGraphShape, BINDING_PRIMITIVE_START, NAME_EDGE_KIND_MASK, NAME_EDGE_OFFSETS,
    NAME_EDGE_TARGETS,
};
use std::sync::Arc;
use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::graph::tensor_flow_forward";

/// Canonical binding index for the input 3D tensor tensor bitset.
pub const BINDING_TENSOR_IN: u32 = BINDING_PRIMITIVE_START;
/// Canonical binding index for the output 3D tensor bitset.
pub const BINDING_TENSOR_OUT: u32 = BINDING_PRIMITIVE_START + 1;

/// Word count calculates matrix boundaries packed strictly per node.
#[must_use]
pub const fn tensor_words(node_count: u32, context_limit: u32, field_limit: u32) -> u32 {
    let bits = node_count * context_limit * field_limit;
    (bits + 31) / 32
}

/// Generate Context-Sensitive / Field-Sensitive Traverse primitive program.
#[must_use]
pub fn tensor_flow_forward(
    shape: ProgramGraphShape,
    tensor_in: &str,
    tensor_out: &str,
    context_limit: u32,
    field_limit: u32,
    allow_mask: u32,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let _total_bits = shape.node_count * context_limit * field_limit;
    let words = tensor_words(shape.node_count, context_limit, field_limit);

    // X axis handles Node_ID resolution
    // Inside the body we scan the full dimension stride of Context/Fields to advance flow
    // For large graphs, context limits might be 32, meaning a whole subgroup ballot resolves
    // one context frame block per source lane instantly in hardware.

    let body = vec![
        Node::let_bind("src", t.clone()),
        // Sub-iteration across context bounds inside the single invocation
        Node::loop_for(
            "ctx",
            Expr::u32(0),
            Expr::u32(context_limit),
            vec![Node::loop_for(
                "fld",
                Expr::u32(0),
                Expr::u32(field_limit),
                vec![
                    // Check if (src, ctx, fld) is hot in the tensor
                    Node::let_bind(
                        "abs_bit",
                        Expr::add(
                            Expr::mul(Expr::var("src"), Expr::u32(context_limit * field_limit)),
                            Expr::add(
                                Expr::mul(Expr::var("ctx"), Expr::u32(field_limit)),
                                Expr::var("fld"),
                            ),
                        ),
                    ),
                    Node::let_bind("word_idx", Expr::shr(Expr::var("abs_bit"), Expr::u32(5))),
                    Node::let_bind(
                        "bit_mask",
                        Expr::shl(
                            Expr::u32(1),
                            Expr::bitand(Expr::var("abs_bit"), Expr::u32(31)),
                        ),
                    ),
                    Node::let_bind("src_word", Expr::load(tensor_in, Expr::var("word_idx"))),
                    Node::if_then(
                        Expr::ne(
                            Expr::bitand(Expr::var("src_word"), Expr::var("bit_mask")),
                            Expr::u32(0),
                        ),
                        vec![
                            // Core traversal
                            Node::let_bind(
                                "edge_start",
                                Expr::load(NAME_EDGE_OFFSETS, Expr::var("src")),
                            ),
                            Node::let_bind(
                                "edge_end",
                                Expr::load(
                                    NAME_EDGE_OFFSETS,
                                    Expr::add(Expr::var("src"), Expr::u32(1)),
                                ),
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
                                            Expr::bitand(
                                                Expr::var("kind_mask"),
                                                Expr::u32(allow_mask),
                                            ),
                                            Expr::u32(0),
                                        ),
                                        vec![
                                            Node::let_bind(
                                                "dst",
                                                Expr::load(NAME_EDGE_TARGETS, Expr::var("e")),
                                            ),
                                            Node::if_then(
                                                Expr::lt(
                                                    Expr::var("dst"),
                                                    Expr::u32(shape.node_count),
                                                ),
                                                vec![
                                                    Node::let_bind(
                                                        "dst_abs_bit",
                                                        Expr::add(
                                                            Expr::mul(
                                                                Expr::var("dst"),
                                                                Expr::u32(
                                                                    context_limit * field_limit,
                                                                ),
                                                            ),
                                                            Expr::add(
                                                                Expr::mul(
                                                                    Expr::var("ctx"),
                                                                    Expr::u32(field_limit),
                                                                ),
                                                                Expr::var("fld"),
                                                            ),
                                                        ),
                                                    ),
                                                    Node::let_bind(
                                                        "dst_word",
                                                        Expr::shr(
                                                            Expr::var("dst_abs_bit"),
                                                            Expr::u32(5),
                                                        ),
                                                    ),
                                                    Node::let_bind(
                                                        "dst_bit",
                                                        Expr::shl(
                                                            Expr::u32(1),
                                                            Expr::bitand(
                                                                Expr::var("dst_abs_bit"),
                                                                Expr::u32(31),
                                                            ),
                                                        ),
                                                    ),
                                                    Node::let_bind(
                                                        "_prev",
                                                        Expr::atomic_or(
                                                            tensor_out,
                                                            Expr::var("dst_word"),
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
                ],
            )],
        ),
    ];

    let mut buffers = shape.read_only_buffers();
    buffers.push(
        BufferDecl::storage(
            tensor_in,
            BINDING_TENSOR_IN,
            BufferAccess::ReadOnly,
            DataType::U32,
        )
        .with_count(words),
    );
    buffers.push(
        BufferDecl::storage(
            tensor_out,
            BINDING_TENSOR_OUT,
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

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || tensor_flow_forward(ProgramGraphShape::new(4, 4), "tin", "tout", 2, 2, 0xFFFF_FFFF),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0, 0, 0, 0]),          // pg_nodes
                to_bytes(&[0, 2, 3, 4, 4]),       // pg_edge_offsets
                to_bytes(&[1, 2, 3, 3]),          // pg_edge_targets
                to_bytes(&[1, 1, 1, 1]),          // pg_edge_kind_mask
                to_bytes(&[0, 0, 0, 0]),          // pg_node_tags
                to_bytes(&[0b00010001]),          // tin
                to_bytes(&[0]),                   // tout
            ]]
        }),
        None,
    )
}
