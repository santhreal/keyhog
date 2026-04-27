//! SSA dominance-frontier lookahead scan.

use vyre_foundation::ir::{Expr, Node};

use super::ast_ops::AST_ASSIGN;

/// Stable op id for the SSA dominance scan child region.
pub const OP_ID: &str = "vyre-primitives::parsing::ssa_dominance_scan";

/// Emit the bounded lookahead scan that allocates phi nodes when rival
/// assignments to the same variable cross block headers.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn ssa_dominance_scan(
    ast_opcodes: &str,
    ast_rights: &str,
    ast_vals: &str,
    block_headers: &str,
    num_nodes: Expr,
    out_phi_nodes: &str,
    out_phi_count: &str,
    t: Expr,
) -> Vec<Node> {
    vec![
        Node::let_bind("var_id", Expr::load(ast_vals, t.clone())),
        Node::let_bind("blk", Expr::load(block_headers, t.clone())),
        Node::loop_for(
            "lookahead",
            Expr::add(t.clone(), Expr::u32(1)),
            Expr::add(t.clone(), Expr::u32(64)),
            vec![
                Node::if_then(
                    Expr::ge(Expr::var("lookahead"), num_nodes.clone()),
                    vec![Node::assign(
                        "lookahead",
                        Expr::add(t.clone(), Expr::u32(64)),
                    )],
                ),
                Node::if_then(
                    Expr::lt(Expr::var("lookahead"), num_nodes.clone()),
                    vec![
                        Node::let_bind("fwd_op", Expr::load(ast_opcodes, Expr::var("lookahead"))),
                        Node::let_bind("fwd_var", Expr::load(ast_vals, Expr::var("lookahead"))),
                        Node::let_bind(
                            "fwd_blk",
                            Expr::load(block_headers, Expr::var("lookahead")),
                        ),
                        // Combined guard: same variable + rival assignment in a different block.
                        // Merged from two nested if_thens to stay within MAX_DEPTH=6.
                        Node::if_then(
                            Expr::and(
                                Expr::and(
                                    Expr::eq(Expr::var("fwd_op"), Expr::u32(AST_ASSIGN)),
                                    Expr::eq(Expr::var("fwd_var"), Expr::var("var_id")),
                                ),
                                Expr::ne(Expr::var("fwd_blk"), Expr::var("blk")),
                            ),
                            vec![
                                Node::let_bind(
                                    "phi_idx",
                                    Expr::atomic_add(out_phi_count, Expr::u32(0), Expr::u32(4)),
                                ),
                                Node::store(
                                    out_phi_nodes,
                                    Expr::var("phi_idx"),
                                    Expr::var("var_id"),
                                ),
                                Node::store(
                                    out_phi_nodes,
                                    Expr::add(Expr::var("phi_idx"), Expr::u32(1)),
                                    Expr::load(ast_rights, t.clone()),
                                ),
                                Node::store(
                                    out_phi_nodes,
                                    Expr::add(Expr::var("phi_idx"), Expr::u32(2)),
                                    Expr::load(ast_rights, Expr::var("lookahead")),
                                ),
                                Node::assign("lookahead", Expr::add(t.clone(), Expr::u32(64))),
                            ],
                        ),
                    ],
                ),
            ],
        ),
    ]
}
