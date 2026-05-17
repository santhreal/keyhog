//! Audit-fix A36 `vast/typedef_ann.rs` extract.

#![allow(missing_docs)] // c-parser feature: A33-A36 split lost some leading doc comments; lint loud, fix surgically when revisiting docs.
use crate::parsing::c::lex::tokens::*;
use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use super::build::*;
use super::helpers::*;
use super::*;

pub fn c11_annotate_typedef_names(
    vast_nodes: &str,
    haystack: &str,
    haystack_len: Expr,
    num_nodes: Expr,
    out_annotated_vast_nodes: &str,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let base = Expr::mul(t.clone(), Expr::u32(VAST_NODE_STRIDE_U32));

    let mut loop_body = vec![
        Node::let_bind("raw_kind", Expr::load(vast_nodes, base.clone())),
        Node::let_bind(
            "tok_start",
            Expr::load(vast_nodes, Expr::add(base.clone(), Expr::u32(5))),
        ),
        Node::let_bind(
            "tok_len",
            Expr::load(vast_nodes, Expr::add(base.clone(), Expr::u32(6))),
        ),
        Node::let_bind("name_hash", Expr::u32(0)),
        Node::if_then(
            Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_IDENTIFIER)),
            vec![
                Node::assign("name_hash", Expr::u32(0x811c9dc5)),
                Node::loop_for(
                    "hash_i",
                    Expr::u32(0),
                    Expr::var("tok_len"),
                    vec![Node::if_then(
                        Expr::lt(
                            Expr::add(Expr::var("tok_start"), Expr::var("hash_i")),
                            haystack_len.clone(),
                        ),
                        vec![
                            Node::let_bind(
                                "hash_byte",
                                Expr::load(
                                    haystack,
                                    Expr::add(Expr::var("tok_start"), Expr::var("hash_i")),
                                ),
                            ),
                            Node::assign(
                                "name_hash",
                                Expr::bitxor(Expr::var("name_hash"), Expr::var("hash_byte")),
                            ),
                            Node::assign(
                                "name_hash",
                                Expr::mul(Expr::var("name_hash"), Expr::u32(0x01000193)),
                            ),
                        ],
                    )],
                ),
            ],
        ),
        Node::let_bind("scope_open", Expr::u32(SENTINEL)),
        Node::let_bind("scope_depth", Expr::u32(0)),
        Node::loop_for(
            "scope_scan",
            Expr::u32(0),
            t.clone(),
            vec![
                Node::let_bind(
                    "scope_idx",
                    Expr::sub(Expr::sub(t.clone(), Expr::u32(1)), Expr::var("scope_scan")),
                ),
                Node::let_bind(
                    "scope_kind",
                    Expr::load(
                        vast_nodes,
                        Expr::mul(Expr::var("scope_idx"), Expr::u32(VAST_NODE_STRIDE_U32)),
                    ),
                ),
                Node::if_then(
                    Expr::eq(Expr::var("scope_kind"), Expr::u32(TOK_RBRACE)),
                    vec![Node::assign(
                        "scope_depth",
                        Expr::add(Expr::var("scope_depth"), Expr::u32(1)),
                    )],
                ),
                Node::if_then(
                    Expr::eq(Expr::var("scope_open"), Expr::u32(SENTINEL)),
                    vec![Node::if_then(
                        Expr::eq(Expr::var("scope_kind"), Expr::u32(TOK_LBRACE)),
                        vec![Node::if_then_else(
                            Expr::eq(Expr::var("scope_depth"), Expr::u32(0)),
                            vec![Node::assign("scope_open", Expr::var("scope_idx"))],
                            vec![Node::assign(
                                "scope_depth",
                                Expr::sub(Expr::var("scope_depth"), Expr::u32(1)),
                            )],
                        )],
                    )],
                ),
            ],
        ),
        Node::let_bind("last_decl_kind", Expr::u32(0)),
    ];

    loop_body.extend(emit_typedef_visibility_scan(
        vast_nodes,
        haystack,
        &haystack_len,
        &num_nodes,
        t.clone(),
    ));
    loop_body.extend(emit_current_declaration_annotation(
        vast_nodes,
        haystack,
        &haystack_len,
        t.clone(),
        &num_nodes,
    ));

    loop_body.extend([
        Node::let_bind("typedef_flags", Expr::u32(0)),
        Node::if_then(
            Expr::and(
                Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_IDENTIFIER)),
                Expr::and(
                    Expr::eq(Expr::var("last_decl_kind"), Expr::u32(1)),
                    Expr::eq(Expr::var("current_decl_result_kind"), Expr::u32(0)),
                ),
            ),
            vec![Node::assign(
                "typedef_flags",
                Expr::bitor(
                    Expr::var("typedef_flags"),
                    Expr::u32(C_TYPEDEF_FLAG_VISIBLE_TYPEDEF_NAME),
                ),
            )],
        ),
        Node::if_then(
            is_typedef_declarator_annotation(Expr::var("current_decl_flags")),
            vec![Node::assign(
                "typedef_flags",
                Expr::bitor(
                    Expr::var("typedef_flags"),
                    Expr::u32(C_TYPEDEF_FLAG_TYPEDEF_DECLARATOR),
                ),
            )],
        ),
        Node::if_then(
            is_ordinary_declarator_annotation(Expr::var("current_decl_flags")),
            vec![Node::assign(
                "typedef_flags",
                Expr::bitor(
                    Expr::var("typedef_flags"),
                    Expr::u32(C_TYPEDEF_FLAG_ORDINARY_DECLARATOR),
                ),
            )],
        ),
    ]);

    for field in 0..VAST_NODE_STRIDE_U32 {
        let value = match field {
            VAST_TYPEDEF_FLAGS_FIELD => Expr::var("typedef_flags"),
            VAST_TYPEDEF_SCOPE_FIELD => Expr::var("scope_open"),
            VAST_TYPEDEF_SYMBOL_FIELD => Expr::var("name_hash"),
            _ => Expr::load(vast_nodes, Expr::add(base.clone(), Expr::u32(field))),
        };
        loop_body.push(Node::store(
            out_annotated_vast_nodes,
            Expr::add(base.clone(), Expr::u32(field)),
            value,
        ));
    }

    let n = node_count(&num_nodes).max(1);
    Program::wrapped(
        vec![
            BufferDecl::storage(vast_nodes, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n.saturating_mul(VAST_NODE_STRIDE_U32)),
            BufferDecl::storage(haystack, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(node_count(&haystack_len).max(1)),
            BufferDecl::storage(
                out_annotated_vast_nodes,
                2,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(n.saturating_mul(VAST_NODE_STRIDE_U32)),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(
            ANNOTATE_TYPEDEF_OP_ID,
            vec![Node::if_then(Expr::lt(t, num_nodes), loop_body)],
        )],
    )
    .with_entry_op_id(ANNOTATE_TYPEDEF_OP_ID)
    .with_non_composable_with_self(true)
}
