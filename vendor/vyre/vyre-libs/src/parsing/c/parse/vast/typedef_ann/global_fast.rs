use super::*;

#[must_use]
pub fn c11_annotate_global_typedef_names_fast(
    vast_nodes: &str,
    global_typedef_hashes: &str,
    num_nodes: Expr,
    num_global_typedefs: Expr,
    out_annotated_vast_nodes: &str,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let base = Expr::mul(t.clone(), Expr::u32(VAST_NODE_STRIDE_U32));
    let next_idx = Expr::select(
        Expr::lt(Expr::add(t.clone(), Expr::u32(1)), num_nodes.clone()),
        Expr::add(t.clone(), Expr::u32(1)),
        t.clone(),
    );
    let next_base = Expr::mul(next_idx, Expr::u32(VAST_NODE_STRIDE_U32));
    let prev_idx = Expr::select(
        Expr::gt(t.clone(), Expr::u32(0)),
        Expr::sub(t.clone(), Expr::u32(1)),
        Expr::u32(0),
    );
    let prev_base = Expr::mul(prev_idx, Expr::u32(VAST_NODE_STRIDE_U32));
    let mut loop_body = vec![
        Node::let_bind("raw_kind", Expr::load(vast_nodes, base.clone())),
        Node::let_bind(
            "name_hash",
            Expr::load(
                vast_nodes,
                Expr::add(base.clone(), Expr::u32(VAST_TYPEDEF_SYMBOL_FIELD)),
            ),
        ),
        Node::let_bind("is_global_typedef_hash", Expr::u32(0)),
        Node::if_then(
            Expr::and(
                Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_IDENTIFIER)),
                Expr::ne(Expr::var("name_hash"), Expr::u32(0)),
            ),
            vec![Node::loop_for(
                "global_typedef_hash_scan",
                Expr::u32(0),
                num_global_typedefs.clone(),
                vec![Node::if_then(
                    Expr::eq(
                        Expr::load(global_typedef_hashes, Expr::var("global_typedef_hash_scan")),
                        Expr::var("name_hash"),
                    ),
                    vec![Node::assign("is_global_typedef_hash", Expr::u32(1))],
                )],
            )],
        ),
        Node::let_bind(
            "prev_kind",
            Expr::select(
                Expr::gt(t.clone(), Expr::u32(0)),
                Expr::load(vast_nodes, prev_base),
                Expr::u32(SENTINEL),
            ),
        ),
        Node::let_bind("next_kind", Expr::load(vast_nodes, next_base)),
        Node::let_bind(
            "possible_declarator",
            any_token_eq(
                Expr::var("next_kind"),
                &[
                    TOK_SEMICOLON,
                    TOK_COMMA,
                    TOK_ASSIGN,
                    TOK_LPAREN,
                    TOK_LBRACKET,
                    TOK_COLON,
                    TOK_RPAREN,
                    TOK_RBRACKET,
                ],
            ),
        ),
        Node::let_bind(
            "declaration_candidate",
            Expr::and(
                Expr::var("possible_declarator"),
                Expr::and(
                    Expr::not(any_token_eq(
                        Expr::var("prev_kind"),
                        &[
                            TOK_STRUCT, TOK_UNION, TOK_ENUM, TOK_DOT, TOK_ARROW, TOK_GOTO,
                        ],
                    )),
                    Expr::ne(Expr::var("next_kind"), Expr::u32(TOK_COLON)),
                ),
            ),
        ),
        Node::let_bind("typedef_flags", Expr::u32(0)),
        Node::if_then(
            Expr::and(
                Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_IDENTIFIER)),
                Expr::eq(Expr::var("is_global_typedef_hash"), Expr::u32(1)),
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
            Expr::and(
                Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_IDENTIFIER)),
                Expr::var("declaration_candidate"),
            ),
            vec![Node::assign(
                "typedef_flags",
                Expr::select(
                    Expr::eq(Expr::var("is_global_typedef_hash"), Expr::u32(1)),
                    Expr::u32(C_TYPEDEF_FLAG_TYPEDEF_DECLARATOR),
                    Expr::u32(C_TYPEDEF_FLAG_ORDINARY_DECLARATOR),
                ),
            )],
        ),
    ];
    for field in 0..VAST_NODE_STRIDE_U32 {
        let value = match field {
            VAST_TYPEDEF_FLAGS_FIELD => Expr::var("typedef_flags"),
            _ => Expr::load(vast_nodes, Expr::add(base.clone(), Expr::u32(field))),
        };
        loop_body.push(Node::store(
            out_annotated_vast_nodes,
            Expr::add(base.clone(), Expr::u32(field)),
            value,
        ));
    }
    let n = node_count(&num_nodes).max(1);
    let typedef_count = node_count(&num_global_typedefs).max(1);
    Program::wrapped(
        vec![
            BufferDecl::storage(vast_nodes, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n.saturating_mul(VAST_NODE_STRIDE_U32)),
            BufferDecl::storage(
                global_typedef_hashes,
                1,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(typedef_count),
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
}
