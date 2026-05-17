use super::*;

pub(super) fn extend(
    out: &mut Vec<Node>,
    vast_nodes: &str,
    out_typed_vast_nodes: &str,
    num_nodes: Expr,
    t: Expr,
    base: Expr,
) {
    out.extend(vec![
        Node::loop_for(
            "parent_ctx_scan",
            Expr::u32(0),
            Expr::var("parent_ctx_scan_limit"),
            vec![
                Node::let_bind(
                    "parent_ctx_base",
                    Expr::mul(
                        Expr::var("parent_ctx_scan"),
                        Expr::u32(VAST_NODE_STRIDE_U32),
                    ),
                ),
                Node::let_bind(
                    "parent_ctx_kind",
                    Expr::load(vast_nodes, Expr::var("parent_ctx_base")),
                ),
                Node::let_bind(
                    "parent_ctx_typedef_flags",
                    Expr::load(
                        vast_nodes,
                        Expr::add(
                            Expr::var("parent_ctx_base"),
                            Expr::u32(VAST_TYPEDEF_FLAGS_FIELD),
                        ),
                    ),
                ),
                Node::let_bind(
                    "parent_ctx_symbol_hash",
                    Expr::load(
                        vast_nodes,
                        Expr::add(
                            Expr::var("parent_ctx_base"),
                            Expr::u32(VAST_TYPEDEF_SYMBOL_FIELD),
                        ),
                    ),
                ),
                Node::let_bind(
                    "parent_ctx_parent",
                    Expr::load(
                        vast_nodes,
                        Expr::add(Expr::var("parent_ctx_base"), Expr::u32(1)),
                    ),
                ),
                Node::if_then(
                    Expr::eq(
                        Expr::var("parent_ctx_parent"),
                        Expr::var("cur_parent_parent"),
                    ),
                    vec![
                        Node::let_bind(
                            "parent_ctx_aggregate_body_open",
                            is_aggregate_specifier_body_open(
                                Expr::var("parent_ctx_kind"),
                                Expr::var("parent_prev_kind"),
                                Expr::var("parent_prev_prev_kind"),
                            ),
                        ),
                        Node::if_then(
                            is_decl_prefix_reset_token(Expr::var("parent_ctx_kind")),
                            vec![Node::assign("parent_has_decl_prefix", Expr::u32(0))],
                        ),
                        Node::if_then(
                            Expr::or(
                                is_decl_prefix_token_or_gnu_type_hash(
                                    Expr::var("parent_ctx_kind"),
                                    Expr::var("parent_ctx_symbol_hash"),
                                ),
                                Expr::or(
                                    Expr::var("parent_ctx_aggregate_body_open"),
                                    Expr::and(
                                        Expr::eq(
                                            Expr::var("parent_ctx_kind"),
                                            Expr::u32(TOK_IDENTIFIER),
                                        ),
                                        is_typedef_name_annotation(Expr::var(
                                            "parent_ctx_typedef_flags",
                                        )),
                                    ),
                                ),
                            ),
                            vec![Node::assign("parent_has_decl_prefix", Expr::u32(1))],
                        ),
                        Node::assign("parent_prev_prev_kind", Expr::var("parent_prev_kind")),
                        Node::assign(
                            "parent_prev_kind",
                            Expr::load(vast_nodes, Expr::var("parent_ctx_base")),
                        ),
                    ],
                ),
            ],
        ),
        Node::let_bind("parent_parent_prev_kind", Expr::u32(SENTINEL)),
        Node::let_bind("parent_parent_prev_prev_kind", Expr::u32(SENTINEL)),
        Node::let_bind("parent_parent_has_decl_prefix", Expr::u32(0)),
        Node::if_then(
            Expr::var("cur_parent_parent_valid"),
            vec![Node::loop_for(
                "parent_parent_ctx_scan",
                Expr::u32(0),
                Expr::var("cur_parent_parent"),
                vec![
                    Node::let_bind(
                        "parent_parent_ctx_base",
                        Expr::mul(
                            Expr::var("parent_parent_ctx_scan"),
                            Expr::u32(VAST_NODE_STRIDE_U32),
                        ),
                    ),
                    Node::let_bind(
                        "parent_parent_ctx_kind",
                        Expr::load(vast_nodes, Expr::var("parent_parent_ctx_base")),
                    ),
                    Node::let_bind(
                        "parent_parent_ctx_typedef_flags",
                        Expr::load(
                            vast_nodes,
                            Expr::add(
                                Expr::var("parent_parent_ctx_base"),
                                Expr::u32(VAST_TYPEDEF_FLAGS_FIELD),
                            ),
                        ),
                    ),
                    Node::let_bind(
                        "parent_parent_ctx_symbol_hash",
                        Expr::load(
                            vast_nodes,
                            Expr::add(
                                Expr::var("parent_parent_ctx_base"),
                                Expr::u32(VAST_TYPEDEF_SYMBOL_FIELD),
                            ),
                        ),
                    ),
                    Node::let_bind(
                        "parent_parent_ctx_parent",
                        Expr::load(
                            vast_nodes,
                            Expr::add(Expr::var("parent_parent_ctx_base"), Expr::u32(1)),
                        ),
                    ),
                    Node::if_then(
                        Expr::eq(
                            Expr::var("parent_parent_ctx_parent"),
                            Expr::var("cur_parent_parent_parent"),
                        ),
                        vec![
                            Node::let_bind(
                                "parent_parent_ctx_aggregate_body_open",
                                is_aggregate_specifier_body_open(
                                    Expr::var("parent_parent_ctx_kind"),
                                    Expr::var("parent_parent_prev_kind"),
                                    Expr::var("parent_parent_prev_prev_kind"),
                                ),
                            ),
                            Node::if_then(
                                is_decl_prefix_reset_token(Expr::var("parent_parent_ctx_kind")),
                                vec![Node::assign("parent_parent_has_decl_prefix", Expr::u32(0))],
                            ),
                            Node::if_then(
                                Expr::or(
                                    is_decl_prefix_token_or_gnu_type_hash(
                                        Expr::var("parent_parent_ctx_kind"),
                                        Expr::var("parent_parent_ctx_symbol_hash"),
                                    ),
                                    Expr::or(
                                        Expr::var("parent_parent_ctx_aggregate_body_open"),
                                        Expr::and(
                                            Expr::eq(
                                                Expr::var("parent_parent_ctx_kind"),
                                                Expr::u32(TOK_IDENTIFIER),
                                            ),
                                            is_typedef_name_annotation(Expr::var(
                                                "parent_parent_ctx_typedef_flags",
                                            )),
                                        ),
                                    ),
                                ),
                                vec![Node::assign("parent_parent_has_decl_prefix", Expr::u32(1))],
                            ),
                            Node::assign(
                                "parent_parent_prev_prev_kind",
                                Expr::var("parent_parent_prev_kind"),
                            ),
                            Node::assign(
                                "parent_parent_prev_kind",
                                Expr::var("parent_parent_ctx_kind"),
                            ),
                        ],
                    ),
                ],
            )],
        ),
        Node::let_bind("ancestor_decl_prefix", Expr::u32(0)),
        Node::let_bind("decl_ancestor", Expr::var("cur_parent")),
        Node::let_bind("decl_ancestor_active", Expr::u32(1)),
    ]);
}
