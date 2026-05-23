use super::ast_to_pg_nodes::C_AST_PG_EDGE_NONE;
use vyre::ir::{Expr, Node};

pub(super) const VAST_NODE_STRIDE_U32: u32 = 10;
pub(super) const IDX_KIND: usize = 0;
pub(super) const IDX_PARENT: usize = 1;
pub(super) const IDX_FIRST_CHILD: usize = 2;
pub(super) const IDX_NEXT_SIBLING: usize = 3;
pub(super) const IDX_SYMBOL_HASH: usize = 9;

#[derive(Clone, Copy)]
pub(super) struct SemanticEdge {
    pub(super) kind: u32,
    pub(super) src: u32,
    pub(super) dst: u32,
}

impl SemanticEdge {
    pub(super) const NONE: Self = Self {
        kind: C_AST_PG_EDGE_NONE,
        src: u32::MAX,
        dst: u32::MAX,
    };

    pub(super) const fn new(kind: u32, src: u32, dst: u32) -> Self {
        Self { kind, src, dst }
    }
}

pub(super) fn expr_is_kind(kind: Expr, expected: u32) -> Expr {
    Expr::eq(kind, Expr::u32(expected))
}

pub(super) fn valid_node_idx(idx: Expr, num_nodes: &Expr) -> Expr {
    Expr::and(
        Expr::ne(idx.clone(), Expr::u32(u32::MAX)),
        Expr::lt(idx, num_nodes.clone()),
    )
}

pub(super) fn vast_field(vast_nodes: &str, idx: Expr, field: usize) -> Expr {
    Expr::load(
        vast_nodes,
        Expr::add(
            Expr::mul(idx, Expr::u32(VAST_NODE_STRIDE_U32)),
            Expr::u32(field as u32),
        ),
    )
}

pub(super) fn resolve_root_nodes(
    vast_nodes: &str,
    num_nodes: &Expr,
    start_idx: Expr,
    root_var: &str,
    parent_var: &str,
    loop_var: &str,
) -> Vec<Node> {
    vec![
        Node::let_bind(root_var, start_idx.clone()),
        Node::let_bind(parent_var, Expr::u32(u32::MAX)),
        Node::if_then(
            valid_node_idx(start_idx.clone(), num_nodes),
            vec![Node::assign(
                parent_var,
                vast_field(vast_nodes, start_idx, IDX_PARENT),
            )],
        ),
        Node::loop_for(
            loop_var,
            Expr::u32(0),
            num_nodes.clone(),
            vec![Node::if_then(
                valid_node_idx(Expr::var(parent_var), num_nodes),
                vec![
                    Node::assign(root_var, Expr::var(parent_var)),
                    Node::assign(
                        parent_var,
                        vast_field(vast_nodes, Expr::var(parent_var), IDX_PARENT),
                    ),
                ],
            )],
        ),
    ]
}
