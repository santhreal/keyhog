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
    match try_ast_walk_preorder(nodes, out, node_count, out_cap) {
        Ok(program) => program,
        Err(error) => {
            eprintln!("{error}");
            inert_tree_walk_program(PREORDER_OP_ID, nodes, out)
        }
    }
}

/// Emit preorder node indices for a VAST first-child / next-sibling tree with
/// checked launch-shape validation.
pub fn try_ast_walk_preorder(
    nodes: &str,
    out: &str,
    node_count: u32,
    out_cap: u32,
) -> Result<Program, String> {
    let stride = NODE_STRIDE_U32 as u32;
    let node_words = checked_node_words(node_count, stride, PREORDER_OP_ID)?;
    let out_words = checked_out_words(out_cap, PREORDER_OP_ID)?;
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

    Ok(tree_walk_program(
        PREORDER_OP_ID,
        nodes,
        out,
        node_words,
        out_words,
        body,
    ))
}

/// Emit postorder node indices for a VAST first-child / next-sibling tree.
#[must_use]
pub fn ast_walk_postorder(nodes: &str, out: &str, node_count: u32, out_cap: u32) -> Program {
    match try_ast_walk_postorder(nodes, out, node_count, out_cap) {
        Ok(program) => program,
        Err(error) => {
            eprintln!("{error}");
            inert_tree_walk_program(POSTORDER_OP_ID, nodes, out)
        }
    }
}

/// Emit postorder node indices for a VAST first-child / next-sibling tree with
/// checked launch-shape validation.
pub fn try_ast_walk_postorder(
    nodes: &str,
    out: &str,
    node_count: u32,
    out_cap: u32,
) -> Result<Program, String> {
    let stride = NODE_STRIDE_U32 as u32;
    let node_words = checked_node_words(node_count, stride, POSTORDER_OP_ID)?;
    let out_words = checked_out_words(out_cap, POSTORDER_OP_ID)?;
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

    Ok(tree_walk_program(
        POSTORDER_OP_ID,
        nodes,
        out,
        node_words,
        out_words,
        body,
    ))
}

fn checked_node_words(node_count: u32, stride: u32, op_id: &'static str) -> Result<u32, String> {
    if node_count == 0 {
        return Ok(1);
    }
    node_count.checked_mul(stride).ok_or_else(|| {
        format!(
            "{op_id} node_count={node_count} stride={stride} overflows VAST node buffer words. Fix: shard the tree before GPU dispatch."
        )
    })
}

fn checked_out_words(out_cap: u32, op_id: &'static str) -> Result<u32, String> {
    if out_cap == 0 {
        Err(format!(
            "{op_id} requires out_cap > 0. Fix: allocate traversal output capacity before GPU dispatch."
        ))
    } else {
        Ok(out_cap)
    }
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

fn inert_tree_walk_program(op_id: &'static str, nodes: &str, out: &str) -> Program {
    tree_walk_program(op_id, nodes, out, 1, 1, vec![Node::return_()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_preorder_rejects_zero_output_capacity() {
        let error = try_ast_walk_preorder("nodes", "out", 1, 0)
            .expect_err("checked preorder builder must reject zero output capacity");

        assert!(
            error.contains("out_cap > 0"),
            "error should describe the launch-shape fix: {error}"
        );
    }

    #[test]
    fn checked_postorder_rejects_node_word_overflow() {
        let error = try_ast_walk_postorder("nodes", "out", u32::MAX, 1)
            .expect_err("checked postorder builder must reject node buffer overflow");

        assert!(
            error.contains("overflows VAST node buffer words"),
            "error should describe the VAST buffer overflow: {error}"
        );
    }

    #[test]
    fn legacy_vast_walk_builders_do_not_panic_on_invalid_shape() {
        let preorder = ast_walk_preorder("nodes", "out", 1, 0);
        let postorder = ast_walk_postorder("nodes", "out", u32::MAX, 1);

        assert_eq!(preorder.workgroup_size, [1, 1, 1]);
        assert_eq!(postorder.workgroup_size, [1, 1, 1]);
    }

    #[test]
    fn vast_tree_walk_release_source_has_checked_builders_without_panics() {
        let source = include_str!("vast_tree_walk.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("VAST tree walk production source must precede tests");

        assert!(
            production.contains("pub fn try_ast_walk_preorder(")
                && production.contains("pub fn try_ast_walk_postorder(")
                && !production.contains(concat!("panic", "!("))
                && !production.contains(".unwrap_or_else("),
            "Fix: VAST traversal builders must expose checked release APIs and avoid production panics."
        );
    }
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
