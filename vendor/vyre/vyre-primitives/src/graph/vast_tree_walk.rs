//! VAST first-child / next-sibling tree traversal primitives.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};
use vyre_foundation::vast::{NODE_STRIDE_U32, SENTINEL};

/// Primitive op id for preorder VAST tree traversal.
pub const PREORDER_OP_ID: &str = "vyre-primitives::graph::vast_walk_preorder";
/// Primitive op id for postorder VAST tree traversal.
pub const POSTORDER_OP_ID: &str = "vyre-primitives::graph::vast_walk_postorder";

/// Emit preorder node indices for a VAST first-child / next-sibling tree.
#[must_use]
pub fn ast_walk_preorder(nodes: &str, out: &str, node_count: u32, out_cap: u32) -> Program {
    let stride = NODE_STRIDE_U32 as u32;
    let node_words = node_count.saturating_mul(stride).max(1);
    let out_words = out_cap.max(1);
    let valid_node = |expr: Expr| {
        Expr::and(
            Expr::ne(expr.clone(), Expr::u32(SENTINEL)),
            Expr::lt(expr, Expr::u32(node_count)),
        )
    };

    let body = vec![
        Node::let_bind("oi", Expr::u32(0)),
        Node::let_bind("n", Expr::u32(0)),
        Node::loop_for(
            "step",
            Expr::u32(0),
            Expr::u32(node_count),
            vec![
                Node::if_then(
                    Expr::eq(Expr::u32(node_count), Expr::u32(0)),
                    vec![Node::return_()],
                ),
                Node::if_then(
                    Expr::ge(Expr::var("oi"), Expr::u32(out_cap)),
                    vec![Node::return_()],
                ),
                Node::if_then(
                    Expr::ge(Expr::var("n"), Expr::u32(node_count)),
                    vec![Node::return_()],
                ),
                Node::let_bind("base", Expr::mul(Expr::var("n"), Expr::u32(stride))),
                Node::let_bind(
                    "fc",
                    Expr::load(nodes, Expr::add(Expr::var("base"), Expr::u32(2))),
                ),
                Node::store(out, Expr::var("oi"), Expr::var("n")),
                Node::assign("oi", Expr::add(Expr::var("oi"), Expr::u32(1))),
                Node::if_then(
                    valid_node(Expr::var("fc")),
                    vec![Node::assign("n", Expr::var("fc"))],
                ),
                Node::if_then(
                    Expr::not(valid_node(Expr::var("fc"))),
                    vec![
                        Node::let_bind("next", Expr::u32(SENTINEL)),
                        Node::let_bind("walk", Expr::var("n")),
                        Node::loop_for(
                            "climb",
                            Expr::u32(0),
                            Expr::u32(node_count),
                            vec![Node::if_then(
                                Expr::and(
                                    Expr::eq(Expr::var("next"), Expr::u32(SENTINEL)),
                                    valid_node(Expr::var("walk")),
                                ),
                                vec![
                                    Node::let_bind(
                                        "walk_base",
                                        Expr::mul(Expr::var("walk"), Expr::u32(stride)),
                                    ),
                                    Node::let_bind(
                                        "sib",
                                        Expr::load(
                                            nodes,
                                            Expr::add(Expr::var("walk_base"), Expr::u32(3)),
                                        ),
                                    ),
                                    Node::if_then(
                                        valid_node(Expr::var("sib")),
                                        vec![Node::assign("next", Expr::var("sib"))],
                                    ),
                                    Node::if_then(
                                        Expr::not(valid_node(Expr::var("sib"))),
                                        vec![
                                            Node::let_bind(
                                                "parent",
                                                Expr::load(
                                                    nodes,
                                                    Expr::add(Expr::var("walk_base"), Expr::u32(1)),
                                                ),
                                            ),
                                            Node::assign("walk", Expr::var("parent")),
                                        ],
                                    ),
                                ],
                            )],
                        ),
                        Node::if_then(
                            Expr::eq(Expr::var("next"), Expr::u32(SENTINEL)),
                            vec![Node::return_()],
                        ),
                        Node::assign("n", Expr::var("next")),
                    ],
                ),
            ],
        ),
    ];

    tree_walk_program(PREORDER_OP_ID, nodes, out, node_words, out_words, body)
}

/// Emit postorder node indices for a VAST first-child / next-sibling tree.
#[must_use]
pub fn ast_walk_postorder(nodes: &str, out: &str, node_count: u32, out_cap: u32) -> Program {
    let stride = NODE_STRIDE_U32 as u32;
    let node_words = node_count.saturating_mul(stride).max(1);
    let out_words = out_cap.max(1);
    let valid_node = |expr: Expr| {
        Expr::and(
            Expr::ne(expr.clone(), Expr::u32(SENTINEL)),
            Expr::lt(expr, Expr::u32(node_count)),
        )
    };
    let descend_to_leftmost_leaf = |nodes_name: &str| {
        Node::loop_for(
            "descend",
            Expr::u32(0),
            Expr::u32(node_count),
            vec![Node::if_then(
                valid_node(Expr::var("n")),
                vec![
                    Node::let_bind(
                        "fc_idx",
                        Expr::add(Expr::mul(Expr::var("n"), Expr::u32(stride)), Expr::u32(2)),
                    ),
                    Node::let_bind("fc", Expr::load(nodes_name, Expr::var("fc_idx"))),
                    Node::if_then(
                        valid_node(Expr::var("fc")),
                        vec![Node::assign("n", Expr::var("fc"))],
                    ),
                ],
            )],
        )
    };
    let body = vec![
        Node::if_then(
            Expr::eq(Expr::u32(node_count), Expr::u32(0)),
            vec![Node::return_()],
        ),
        Node::let_bind("oi", Expr::u32(0)),
        Node::let_bind("n", Expr::u32(0)),
        descend_to_leftmost_leaf(nodes),
        Node::loop_for(
            "emit",
            Expr::u32(0),
            Expr::u32(node_count),
            vec![
                Node::if_then(
                    Expr::ge(Expr::var("oi"), Expr::u32(out_cap)),
                    vec![Node::return_()],
                ),
                Node::if_then(
                    Expr::ge(Expr::var("n"), Expr::u32(node_count)),
                    vec![Node::return_()],
                ),
                Node::store(out, Expr::var("oi"), Expr::var("n")),
                Node::assign("oi", Expr::add(Expr::var("oi"), Expr::u32(1))),
                Node::if_then(
                    Expr::eq(Expr::var("n"), Expr::u32(0)),
                    vec![Node::return_()],
                ),
                Node::let_bind("base", Expr::mul(Expr::var("n"), Expr::u32(stride))),
                Node::let_bind(
                    "sib",
                    Expr::load(nodes, Expr::add(Expr::var("base"), Expr::u32(3))),
                ),
                Node::if_then(
                    valid_node(Expr::var("sib")),
                    vec![
                        Node::assign("n", Expr::var("sib")),
                        descend_to_leftmost_leaf(nodes),
                    ],
                ),
                Node::if_then(
                    Expr::not(valid_node(Expr::var("sib"))),
                    vec![
                        Node::let_bind(
                            "parent",
                            Expr::load(nodes, Expr::add(Expr::var("base"), Expr::u32(1))),
                        ),
                        Node::if_then(
                            Expr::not(valid_node(Expr::var("parent"))),
                            vec![Node::return_()],
                        ),
                        Node::assign("n", Expr::var("parent")),
                    ],
                ),
            ],
        ),
    ];

    tree_walk_program(POSTORDER_OP_ID, nodes, out, node_words, out_words, body)
}

fn tree_walk_program(
    op_id: &'static str,
    nodes: &str,
    out: &str,
    node_words: u32,
    out_words: u32,
    body: Vec<Node>,
) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::storage(nodes, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(node_words),
            BufferDecl::storage(out, 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(out_words),
        ],
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(op_id),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

#[cfg(feature = "inventory-registry")]
fn fixture_u32(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

#[cfg(feature = "inventory-registry")]
fn fixture_tree_words() -> Vec<u32> {
    vec![
        1, SENTINEL, 1, SENTINEL, 0, 0, 0, 0, 0, 0, // root
        2, 0, SENTINEL, 2, 0, 0, 0, 0, 0, 0, // first child
        3, 0, SENTINEL, SENTINEL, 0, 0, 0, 0, 0, 0, // second child
    ]
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        PREORDER_OP_ID,
        || ast_walk_preorder("nodes", "out", 3, 3),
        Some(|| vec![vec![
            fixture_u32(&fixture_tree_words()),
            fixture_u32(&[SENTINEL, SENTINEL, SENTINEL]),
        ]]),
        Some(|| vec![vec![fixture_u32(&[0, 1, 2])]]),
    )
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        POSTORDER_OP_ID,
        || ast_walk_postorder("nodes", "out", 3, 3),
        Some(|| vec![vec![
            fixture_u32(&fixture_tree_words()),
            fixture_u32(&[SENTINEL, SENTINEL, SENTINEL]),
        ]]),
        Some(|| vec![vec![fixture_u32(&[1, 2, 0])]]),
    )
}
