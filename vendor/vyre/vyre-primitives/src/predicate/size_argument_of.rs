//! `size_argument_of` — reverse CallArg traversal for size argument
//! candidates.
//!
//! The primitive marks argument nodes whose callee is in the input
//! frontier. Rule-level predicates own any additional node-kind
//! filtering.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::graph::csr_backward_traverse::{BINDING_FRONTIER_IN, BINDING_FRONTIER_OUT};
use crate::graph::csr_forward_traverse::bitset_words;
use crate::graph::program_graph::ProgramGraphShape;
use crate::graph::program_graph::{NAME_EDGE_KIND_MASK, NAME_EDGE_OFFSETS, NAME_EDGE_TARGETS};
use crate::predicate::edge_kind;
#[cfg(feature = "inventory-registry")]
use crate::predicate::node_kind;

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::predicate::size_argument_of";

/// Build a Program that reverse-traverses CallArg edges and marks
/// argument nodes whose callees are in `frontier_in`.
///
/// Downstream analyzer rules own any additional node-kind predicates at the rule
/// layer. This primitive deliberately avoids a baked-in Literal filter:
/// allocator size arguments are often computed expressions, and
/// filtering here would erase realistic vulnerability witnesses before
/// rule-specific predicates can inspect them.
#[must_use]
pub fn size_argument_of(
    shape: ProgramGraphShape,
    frontier_in: &str,
    frontier_out: &str,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let words = bitset_words(shape.node_count);
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
            vec![Node::if_then(
                Expr::eq(Expr::var("hit"), Expr::u32(0)),
                vec![
                    Node::let_bind("kind_mask", Expr::load(NAME_EDGE_KIND_MASK, Expr::var("e"))),
                    Node::if_then(
                        Expr::ne(
                            Expr::bitand(Expr::var("kind_mask"), Expr::u32(edge_kind::CALL_ARG)),
                            Expr::u32(0),
                        ),
                        vec![
                            Node::let_bind("dst", Expr::load(NAME_EDGE_TARGETS, Expr::var("e"))),
                            Node::let_bind(
                                "dst_word",
                                Expr::load(frontier_in, Expr::shr(Expr::var("dst"), Expr::u32(5))),
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
                                    Expr::bitand(Expr::var("dst_word"), Expr::var("dst_bit")),
                                    Expr::u32(0),
                                ),
                                vec![Node::assign("hit", Expr::u32(1))],
                            ),
                        ],
                    ),
                ],
            )],
        ),
        // Set bit `src` in frontier_out iff there's any CALL_ARG
        // edge from `src` whose destination is in frontier_in.
        //
        // Earlier this filtered to `src_kind == LITERAL`, but
        // allocator size arguments are rarely literal — they are
        // typically computed expressions (`size * 2`, `len + 8`).
        // The surge rule chains `node_kind($size_arg, "binary")`
        // itself when a kind filter is wanted; baking a literal-only
        // pre-filter here drops every realistic vuln the rule is
        // designed to catch. The vyre kind constants also disagreed
        // with surge_source's emission convention (LITERAL=4 in vyre
        // versus 4 in surge_source by coincidence, but
        // BINARY=7 vs 128 — so even pure literals would fail to
        // pass through any subsequent kind check).
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
        [256, 1, 1],
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

/// CPU reference: reverse-traverse CallArg edges and mark every caller
/// argument whose callee bit is present in `frontier_in`.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref(
    node_count: u32,
    _nodes: &[u32],
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
) -> Vec<u32> {
    crate::graph::csr_backward_traverse::cpu_ref(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
        edge_kind::CALL_ARG,
    )
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || size_argument_of(ProgramGraphShape::new(4, 4), "fin", "fout"),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[node_kind::LITERAL, node_kind::CALL, node_kind::LITERAL, node_kind::CALL]),
                to_bytes(&[0, 1, 2, 3, 4]),
                to_bytes(&[1, 2, 3, 0]),
                to_bytes(&[edge_kind::CALL_ARG, 0, edge_kind::CALL_ARG, 0]),
                to_bytes(&[0, 0, 0, 0]),
                to_bytes(&[0b1010]),
                to_bytes(&[0]),
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0b0101])]]
        }),
    )
}
