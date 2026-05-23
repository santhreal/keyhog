use super::*;

pub fn c11_precompute_vast_decl_contexts(
    vast_nodes: &str,
    num_nodes: Expr,
    out_decl_contexts: &str,
) -> Program {
    const BUCKETS: u32 = 4096;

    let t = Expr::InvocationId { axis: 0 };
    let mut body = vec![
        Node::loop_for(
            "decl_ctx_bucket_init",
            Expr::u32(0),
            Expr::u32(BUCKETS),
            vec![
                Node::store(
                    "__vast_decl_symbol_heads",
                    Expr::var("decl_ctx_bucket_init"),
                    Expr::u32(SENTINEL),
                ),
                Node::store(
                    "__vast_decl_symbol_heads",
                    Expr::add(Expr::var("decl_ctx_bucket_init"), Expr::u32(BUCKETS)),
                    Expr::u32(0),
                ),
            ],
        ),
        Node::let_bind("decl_ctx_prefix_start", Expr::u32(0)),
    ];

    let row_context_base = Expr::mul(
        Expr::var("decl_ctx_row"),
        Expr::u32(VAST_DECL_CONTEXT_STRIDE_U32),
    );
    let row_body = vec![
        Node::let_bind(
            "decl_ctx_row_base",
            Expr::mul(Expr::var("decl_ctx_row"), Expr::u32(VAST_NODE_STRIDE_U32)),
        ),
        Node::let_bind(
            "decl_ctx_kind",
            Expr::load(vast_nodes, Expr::var("decl_ctx_row_base")),
        ),
        Node::let_bind(
            "decl_ctx_hash",
            Expr::load(
                vast_nodes,
                Expr::add(
                    Expr::var("decl_ctx_row_base"),
                    Expr::u32(VAST_TYPEDEF_SYMBOL_FIELD),
                ),
            ),
        ),
        Node::let_bind("decl_ctx_bucket_prev_encoded", Expr::u32(SENTINEL)),
        Node::let_bind("decl_ctx_exact_prev_encoded", Expr::u32(SENTINEL)),
        Node::let_bind("decl_ctx_bucket_chain_len", Expr::u32(0)),
        Node::let_bind("decl_ctx_exact_chain_len", Expr::u32(0)),
        Node::if_then(
            Expr::and(
                Expr::eq(Expr::var("decl_ctx_kind"), Expr::u32(TOK_IDENTIFIER)),
                Expr::ne(Expr::var("decl_ctx_hash"), Expr::u32(0)),
            ),
            vec![
                Node::let_bind(
                    "decl_ctx_bucket",
                    typedef_symbol_bucket(Expr::var("decl_ctx_hash"), BUCKETS),
                ),
                Node::let_bind(
                    "decl_ctx_prev",
                    Expr::load("__vast_decl_symbol_heads", Expr::var("decl_ctx_bucket")),
                ),
                Node::assign(
                    "decl_ctx_bucket_chain_len",
                    Expr::load(
                        "__vast_decl_symbol_heads",
                        Expr::add(Expr::var("decl_ctx_bucket"), Expr::u32(BUCKETS)),
                    ),
                ),
                Node::assign(
                    "decl_ctx_bucket_prev_encoded",
                    Expr::select(
                        Expr::eq(Expr::var("decl_ctx_prev"), Expr::u32(SENTINEL)),
                        Expr::u32(SENTINEL),
                        Expr::add(Expr::var("decl_ctx_prev"), Expr::u32(1)),
                    ),
                ),
                Node::let_bind("decl_ctx_exact_cursor", Expr::var("decl_ctx_prev")),
                Node::loop_for(
                    "decl_ctx_exact_scan",
                    Expr::u32(0),
                    Expr::var("decl_ctx_bucket_chain_len"),
                    vec![Node::if_then(
                        Expr::and(
                            Expr::eq(
                                Expr::var("decl_ctx_exact_prev_encoded"),
                                Expr::u32(SENTINEL),
                            ),
                            Expr::lt(Expr::var("decl_ctx_exact_cursor"), num_nodes.clone()),
                        ),
                        vec![
                            Node::let_bind(
                                "decl_ctx_exact_cursor_base",
                                Expr::mul(
                                    Expr::var("decl_ctx_exact_cursor"),
                                    Expr::u32(VAST_NODE_STRIDE_U32),
                                ),
                            ),
                            Node::let_bind(
                                "decl_ctx_exact_cursor_hash",
                                Expr::load(
                                    vast_nodes,
                                    Expr::add(
                                        Expr::var("decl_ctx_exact_cursor_base"),
                                        Expr::u32(VAST_TYPEDEF_SYMBOL_FIELD),
                                    ),
                                ),
                            ),
                            Node::let_bind(
                                "decl_ctx_exact_cursor_context_base",
                                Expr::mul(
                                    Expr::var("decl_ctx_exact_cursor"),
                                    Expr::u32(VAST_DECL_CONTEXT_STRIDE_U32),
                                ),
                            ),
                            Node::if_then(
                                Expr::eq(
                                    Expr::var("decl_ctx_exact_cursor_hash"),
                                    Expr::var("decl_ctx_hash"),
                                ),
                                vec![
                                    Node::assign(
                                        "decl_ctx_exact_prev_encoded",
                                        Expr::add(Expr::var("decl_ctx_exact_cursor"), Expr::u32(1)),
                                    ),
                                    Node::assign(
                                        "decl_ctx_exact_chain_len",
                                        Expr::add(
                                            Expr::load(
                                                out_decl_contexts,
                                                Expr::add(
                                                    Expr::var("decl_ctx_exact_cursor_context_base"),
                                                    Expr::u32(
                                                        VAST_DECL_CONTEXT_PREV_DECL_CHAIN_LEN_FIELD,
                                                    ),
                                                ),
                                            ),
                                            Expr::u32(1),
                                        ),
                                    ),
                                ],
                            ),
                            Node::let_bind(
                                "decl_ctx_exact_cursor_bucket_link",
                                Expr::load(
                                    out_decl_contexts,
                                    Expr::add(
                                        Expr::var("decl_ctx_exact_cursor_context_base"),
                                        Expr::u32(VAST_DECL_CONTEXT_PREV_BUCKET_LINK_FIELD),
                                    ),
                                ),
                            ),
                            Node::assign(
                                "decl_ctx_exact_cursor",
                                Expr::select(
                                    Expr::or(
                                        Expr::eq(
                                            Expr::var("decl_ctx_exact_cursor_bucket_link"),
                                            Expr::u32(0),
                                        ),
                                        Expr::eq(
                                            Expr::var("decl_ctx_exact_cursor_bucket_link"),
                                            Expr::u32(SENTINEL),
                                        ),
                                    ),
                                    Expr::u32(SENTINEL),
                                    Expr::sub(
                                        Expr::var("decl_ctx_exact_cursor_bucket_link"),
                                        Expr::u32(1),
                                    ),
                                ),
                            ),
                        ],
                    )],
                ),
                Node::let_bind(
                    "decl_ctx_next_idx",
                    Expr::select(
                        Expr::lt(
                            Expr::add(Expr::var("decl_ctx_row"), Expr::u32(1)),
                            num_nodes.clone(),
                        ),
                        Expr::add(Expr::var("decl_ctx_row"), Expr::u32(1)),
                        Expr::var("decl_ctx_row"),
                    ),
                ),
                Node::let_bind(
                    "decl_ctx_next_kind",
                    Expr::select(
                        Expr::lt(
                            Expr::add(Expr::var("decl_ctx_row"), Expr::u32(1)),
                            num_nodes.clone(),
                        ),
                        Expr::load(
                            vast_nodes,
                            Expr::mul(
                                Expr::var("decl_ctx_next_idx"),
                                Expr::u32(VAST_NODE_STRIDE_U32),
                            ),
                        ),
                        Expr::u32(SENTINEL),
                    ),
                ),
                Node::let_bind(
                    "decl_ctx_possible_declarator",
                    any_token_eq(
                        Expr::var("decl_ctx_next_kind"),
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
                Node::if_then(
                    Expr::var("decl_ctx_possible_declarator"),
                    vec![
                        Node::store(
                            "__vast_decl_symbol_heads",
                            Expr::var("decl_ctx_bucket"),
                            Expr::var("decl_ctx_row"),
                        ),
                        Node::store(
                            "__vast_decl_symbol_heads",
                            Expr::add(Expr::var("decl_ctx_bucket"), Expr::u32(BUCKETS)),
                            Expr::add(Expr::var("decl_ctx_bucket_chain_len"), Expr::u32(1)),
                        ),
                    ],
                ),
            ],
        ),
        Node::store(
            out_decl_contexts,
            Expr::add(
                row_context_base.clone(),
                Expr::u32(VAST_DECL_CONTEXT_PREFIX_START_FIELD),
            ),
            Expr::var("decl_ctx_prefix_start"),
        ),
        Node::store(
            out_decl_contexts,
            Expr::add(
                row_context_base.clone(),
                Expr::u32(VAST_DECL_CONTEXT_PREV_BUCKET_LINK_FIELD),
            ),
            Expr::var("decl_ctx_bucket_prev_encoded"),
        ),
        Node::store(
            out_decl_contexts,
            Expr::add(
                row_context_base.clone(),
                Expr::u32(VAST_DECL_CONTEXT_PREV_DECL_LINK_FIELD),
            ),
            Expr::var("decl_ctx_exact_prev_encoded"),
        ),
        Node::store(
            out_decl_contexts,
            Expr::add(
                row_context_base,
                Expr::u32(VAST_DECL_CONTEXT_PREV_DECL_CHAIN_LEN_FIELD),
            ),
            Expr::var("decl_ctx_exact_chain_len"),
        ),
        Node::if_then(
            is_decl_prefix_reset_token(Expr::var("decl_ctx_kind")),
            vec![Node::assign(
                "decl_ctx_prefix_start",
                Expr::add(Expr::var("decl_ctx_row"), Expr::u32(1)),
            )],
        ),
    ];
    body.push(Node::loop_for(
        "decl_ctx_row",
        Expr::u32(0),
        num_nodes.clone(),
        row_body,
    ));

    let n = node_count(&num_nodes).max(1);
    Program::wrapped(
        vec![
            BufferDecl::storage(vast_nodes, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n.saturating_mul(VAST_NODE_STRIDE_U32)),
            BufferDecl::storage(out_decl_contexts, 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(n.saturating_mul(VAST_DECL_CONTEXT_STRIDE_U32)),
            BufferDecl::workgroup("__vast_decl_symbol_heads", BUCKETS * 2, DataType::U32),
        ],
        [1, 1, 1],
        vec![wrap_anonymous(
            PRECOMPUTE_VAST_DECL_CONTEXTS_OP_ID,
            vec![Node::if_then(Expr::eq(t, Expr::u32(0)), body)],
        )],
    )
    .with_entry_op_id(PRECOMPUTE_VAST_DECL_CONTEXTS_OP_ID)
    .with_non_composable_with_self(true)
}
