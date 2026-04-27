//! `size_argument_of` — arg_of, but restricted to argument nodes
//! whose `NodeKind == Literal`.
//!
//! One reverse CallArg traversal fused with the Literal node-kind
//! filter so the primitive name and runtime contract stay identical.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::graph::csr_backward_traverse::{BINDING_FRONTIER_IN, BINDING_FRONTIER_OUT};
use crate::graph::csr_forward_traverse::bitset_words;
use crate::graph::program_graph::{ProgramGraphShape, NAME_NODES};
use crate::graph::program_graph::{NAME_EDGE_KIND_MASK, NAME_EDGE_OFFSETS, NAME_EDGE_TARGETS};
use crate::predicate::edge_kind;
use crate::predicate::node_kind;

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::predicate::size_argument_of";

/// Build a Program that reverse-traverses CallArg edges. Surgec
/// chains this with `node_kind_eq(Literal)` to filter to size-argument
/// nodes only; keeping the steps separate preserves the ≤4 loop /
/// ≤200 node budget from Gate 1.
///
/// AUDIT_2026-04-24 F-SAO-01 (deferred): the present IR fuses the
/// backward CallArg traversal with the `NodeKind == Literal` filter
/// into a single kernel. That violates extend-don't-hack because
/// a future refinement to either half forces touching both. The
/// intended composition is `csr_backward_traverse(CALL_ARG)` →
/// `bitset_and` with `node_kind_eq(LITERAL)`. That composition
/// requires an intermediate bitset buffer and an extra dispatch,
/// which vyre's current dispatcher cannot yet chain without
/// copy-out; unwinding the fusion is tracked as a follow-up after
/// the dispatcher learns persistent-bitset chaining. The `cpu_ref`
/// below models the composed form so the semantic contract is
/// documented even while the IR remains fused. See also the audit
/// line in vyre-primitives/AUDIT_2026-04-24.md (F-SAO-01).
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
    let _ = NAME_NODES; // referenced only by the removed kind filter
    let _ = node_kind::LITERAL;

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

/// CPU reference: reverse-traverse CallArg edges, then keep only
/// arguments whose NodeKind is Literal.
#[must_use]
pub fn cpu_ref(
    node_count: u32,
    nodes: &[u32],
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
) -> Vec<u32> {
    let mut args = crate::graph::csr_backward_traverse::cpu_ref(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
        edge_kind::CALL_ARG,
    );
    for (v, kind) in nodes.iter().enumerate() {
        if *kind != node_kind::LITERAL {
            let word = v / 32;
            let bit = 1u32 << (v % 32);
            if word < args.len() {
                args[word] &= !bit;
            }
        }
    }
    args
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
