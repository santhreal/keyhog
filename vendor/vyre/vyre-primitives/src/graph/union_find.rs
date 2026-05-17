//! Lock-free union-find (disjoint-set) alias tracking as Vyre IR.
//!
//! This module deliberately emits `Program` / `Node` IR, not target shader
//! text. Concrete drivers own target spelling; primitives own the backend-
//! neutral algorithm.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical operation id for one union-find merge pass.
pub const OP_ID: &str = "vyre-primitives::graph::union_find";

/// Build the path-halving body used by [`union_roots_body`].
///
/// `id_var` is read at entry. On exit `root_var` contains the discovered root
/// and `scratch_parent_var` contains the last parent read. The loop is bounded
/// by `node_count` so malformed parent arrays cannot create an infinite kernel.
#[must_use]
pub fn find_root_body(
    parent: &str,
    id_var: &str,
    root_var: &str,
    scratch_parent_var: &str,
    node_count: u32,
) -> Vec<Node> {
    vec![
        Node::let_bind(root_var, Expr::var(id_var)),
        Node::let_bind(scratch_parent_var, Expr::var(id_var)),
        Node::loop_for(
            "uf_find_iter",
            Expr::u32(0),
            Expr::u32(node_count.max(1)),
            vec![Node::if_then(
                Expr::ne(Expr::var(root_var), Expr::var(scratch_parent_var)),
                vec![
                    Node::assign(root_var, Expr::var(scratch_parent_var)),
                    Node::if_then(
                        Expr::ge(Expr::var(root_var), Expr::u32(node_count)),
                        vec![Node::trap(Expr::var(root_var), "union-find-parent-oob")],
                    ),
                    Node::assign(scratch_parent_var, Expr::load(parent, Expr::var(root_var))),
                    Node::if_then(
                        Expr::lt(Expr::var(scratch_parent_var), Expr::u32(node_count)),
                        vec![Node::let_bind(
                            "uf_grandparent",
                            Expr::load(parent, Expr::var(scratch_parent_var)),
                        )],
                    ),
                    Node::if_then(
                        Expr::lt(Expr::var(scratch_parent_var), Expr::u32(node_count)),
                        vec![Node::let_bind(
                            "uf_path_old",
                            Expr::atomic_min(
                                parent,
                                Expr::var(root_var),
                                Expr::var("uf_grandparent"),
                            ),
                        )],
                    ),
                ],
            )],
        ),
    ]
}

/// Build one deterministic lock-free union pass for edge `edge_index_var`.
///
/// `edge_a[edge_index]` and `edge_b[edge_index]` are merged into the shared
/// `parent` array using ordered root selection and compare-exchange. The retry
/// loop is bounded by `node_count`; if another lane wins the race, this lane
/// reloads the observed parent and tries again.
#[must_use]
pub fn union_roots_body(
    parent: &str,
    edge_a: &str,
    edge_b: &str,
    edge_index_var: &str,
    node_count: u32,
) -> Vec<Node> {
    let mut body = vec![
        Node::let_bind("uf_a", Expr::load(edge_a, Expr::var(edge_index_var))),
        Node::let_bind("uf_b", Expr::load(edge_b, Expr::var(edge_index_var))),
        Node::if_then(
            Expr::or(
                Expr::ge(Expr::var("uf_a"), Expr::u32(node_count)),
                Expr::ge(Expr::var("uf_b"), Expr::u32(node_count)),
            ),
            vec![Node::trap(Expr::var(edge_index_var), "union-find-edge-oob")],
        ),
    ];
    body.extend(find_root_body(
        parent,
        "uf_a",
        "uf_root_a",
        "uf_parent_a",
        node_count,
    ));
    body.extend(find_root_body(
        parent,
        "uf_b",
        "uf_root_b",
        "uf_parent_b",
        node_count,
    ));
    body.push(Node::loop_for(
        "uf_union_iter",
        Expr::u32(0),
        Expr::u32(node_count.max(1)),
        vec![Node::if_then(
            Expr::ne(Expr::var("uf_root_a"), Expr::var("uf_root_b")),
            vec![
                Node::let_bind(
                    "uf_low",
                    Expr::select(
                        Expr::lt(Expr::var("uf_root_a"), Expr::var("uf_root_b")),
                        Expr::var("uf_root_a"),
                        Expr::var("uf_root_b"),
                    ),
                ),
                Node::let_bind(
                    "uf_high",
                    Expr::select(
                        Expr::lt(Expr::var("uf_root_a"), Expr::var("uf_root_b")),
                        Expr::var("uf_root_b"),
                        Expr::var("uf_root_a"),
                    ),
                ),
                Node::let_bind(
                    "uf_observed",
                    Expr::atomic_compare_exchange(
                        parent,
                        Expr::var("uf_high"),
                        Expr::var("uf_high"),
                        Expr::var("uf_low"),
                    ),
                ),
                Node::if_then_else(
                    Expr::eq(Expr::var("uf_observed"), Expr::var("uf_high")),
                    vec![Node::assign("uf_root_b", Expr::var("uf_low"))],
                    vec![
                        Node::assign("uf_b", Expr::var("uf_observed")),
                        Node::Block(find_root_body(
                            parent,
                            "uf_b",
                            "uf_root_b",
                            "uf_parent_b",
                            node_count,
                        )),
                    ],
                ),
            ],
        )],
    ));
    body
}

/// Build a Program that applies a batch of union operations.
#[must_use]
pub fn union_find_program(
    parent: &str,
    edge_a: &str,
    edge_b: &str,
    node_count: u32,
    edge_count: u32,
) -> Program {
    let lane = Expr::gid_x();
    let body = vec![Node::if_then(
        Expr::lt(lane.clone(), Expr::u32(edge_count)),
        union_roots_body(parent, edge_a, edge_b, "uf_edge", node_count),
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(parent, 0, BufferAccess::ReadWrite, DataType::U32)
                .with_count(node_count.max(1)),
            BufferDecl::storage(edge_a, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(edge_count.max(1)),
            BufferDecl::storage(edge_b, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(edge_count.max(1)),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new({
                let mut entry = vec![Node::let_bind("uf_edge", lane)];
                entry.extend(body);
                entry
            }),
        }],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn union_find_program_uses_atomic_ir_not_target_text() {
        let program = union_find_program("parent", "edge_a", "edge_b", 8, 4);
        let dump = format!("{program:#?}");
        assert!(dump.contains("CompareExchange"));
        assert!(dump.contains("Min"));
        assert!(!dump.contains("atomicCAS"));
        assert!(!dump.contains("ptr<storage"));
    }

    #[test]
    fn union_find_program_declares_batch_buffers() {
        let program = union_find_program("parent", "edge_a", "edge_b", 8, 4);
        assert_eq!(program.buffers().len(), 3);
        assert_eq!(program.workgroup_size(), [256, 1, 1]);
    }
}
