//! Structural-hash CSE probe/insert wave.

use vyre_foundation::ir::{Expr, Node};

use super::ast_ops::{AST_ADD, AST_PTR_DEREF, AST_VAR};

/// Stable op id for the structural CSE child region.
pub const OP_ID: &str = "vyre-primitives::parsing::cse_structural_hash";

/// Emit the structural-hash deduplication phase.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn cse_structural_hash(
    ast_opcodes: &str,
    ast_lefts: &str,
    ast_rights: &str,
    ast_vals: &str,
    hash_set: &str,
    hash_set_capacity: u32,
    out_modified_flag: &str,
    t: Expr,
) -> Vec<Node> {
    vec![Node::if_then(
        Expr::or(
            Expr::eq(Expr::var("op"), Expr::u32(AST_ADD)),
            Expr::eq(Expr::var("op"), Expr::u32(AST_PTR_DEREF)),
        ),
        vec![
            Node::let_bind("l_idx2", Expr::load(ast_lefts, t.clone())),
            Node::let_bind("r_idx2", Expr::load(ast_rights, t.clone())),
            Node::let_bind(
                "h",
                Expr::bitxor(
                    Expr::mul(Expr::var("op"), Expr::u32(0x01000193)),
                    Expr::var("l_idx2"),
                ),
            ),
            Node::assign(
                "h",
                Expr::bitxor(
                    Expr::mul(Expr::var("h"), Expr::u32(0x01000193)),
                    Expr::var("r_idx2"),
                ),
            ),
            Node::let_bind(
                "slot",
                Expr::rem(Expr::var("h"), Expr::u32(hash_set_capacity)),
            ),
            Node::loop_for(
                "probe",
                Expr::u32(0),
                Expr::u32(hash_set_capacity),
                vec![
                    Node::let_bind("slot_hash", Expr::mul(Expr::var("slot"), Expr::u32(2))),
                    Node::let_bind("slot_idx", Expr::add(Expr::var("slot_hash"), Expr::u32(1))),
                    Node::let_bind(
                        "old_hash",
                        Expr::atomic_compare_exchange(
                            hash_set,
                            Expr::var("slot_hash"),
                            Expr::u32(0),
                            Expr::var("h"),
                        ),
                    ),
                    Node::if_then(
                        Expr::eq(Expr::var("old_hash"), Expr::u32(0)),
                        vec![
                            Node::store(hash_set, Expr::var("slot_idx"), t.clone()),
                            Node::assign("probe", Expr::u32(hash_set_capacity)),
                        ],
                    ),
                    // Conditionally load earliest index (u32::MAX sentinel when no match)
                    // to avoid depth-violating nested if_then.
                    Node::let_bind(
                        "earliest",
                        Expr::Select {
                            cond: Box::new(Expr::eq(Expr::var("old_hash"), Expr::var("h"))),
                            true_val: Box::new(Expr::load(hash_set, Expr::var("slot_idx"))),
                            false_val: Box::new(Expr::u32(u32::MAX)),
                        },
                    ),
                    // CSE dedup: redirect current node to reference the earlier one
                    Node::if_then(
                        Expr::and(
                            Expr::eq(Expr::var("old_hash"), Expr::var("h")),
                            Expr::lt(Expr::var("earliest"), t.clone()),
                        ),
                        vec![
                            Node::store(ast_opcodes, t.clone(), Expr::u32(AST_VAR)),
                            Node::store(ast_vals, t.clone(), Expr::var("earliest")),
                            Node::let_bind(
                                "_",
                                Expr::atomic_add(out_modified_flag, Expr::u32(0), Expr::u32(1)),
                            ),
                        ],
                    ),
                    // Break out of probe loop on hash match
                    Node::if_then(
                        Expr::eq(Expr::var("old_hash"), Expr::var("h")),
                        vec![Node::assign("probe", Expr::u32(hash_set_capacity))],
                    ),
                    Node::assign(
                        "slot",
                        Expr::rem(
                            Expr::add(Expr::var("slot"), Expr::u32(1)),
                            Expr::u32(hash_set_capacity),
                        ),
                    ),
                ],
            ),
        ],
    )]
}
