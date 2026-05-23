use super::*;

pub(crate) fn emit_visible_typedef_name_for_index(
    vast_nodes: &str,
    haystack: &str,
    decl_contexts: Option<&str>,
    haystack_len: &Expr,
    idx: Expr,
    out_name: &str,
    prefix: &str,
    packed_haystack: bool,
) -> Vec<Node> {
    let target_base = format!("{prefix}_target_base");
    let target_link_raw = format!("{prefix}_target_link_raw");
    let target_prepared = format!("{prefix}_target_prepared");
    let target_chain_len = format!("{prefix}_target_chain_len");
    let scan_limit = format!("{prefix}_scan_limit");
    let target_scope = format!("{prefix}_target_scope");
    let target_function = format!("{prefix}_target_function");
    let last_decl_kind = format!("{prefix}_last_decl_kind");
    let chain_cursor = format!("{prefix}_chain_cursor");
    let chain_raw = format!("{prefix}_chain_raw");
    let scan_valid = format!("{prefix}_scan_valid");
    let scan_offset = format!("{prefix}_scan_offset");
    let scan = format!("{prefix}_scan");
    let scan_safe = format!("{prefix}_scan_safe");
    let scan_base = format!("{prefix}_scan_base");
    let scan_kind = format!("{prefix}_scan_kind");
    let scan_scope = format!("{prefix}_scan_scope");
    let scan_function = format!("{prefix}_scan_function");
    let scan_decl_kind = format!("{prefix}_scan_decl_result_kind");
    let scope_walk = format!("{prefix}_scope_walk");
    let scope_walk_depth = format!("{prefix}_scope_walk_depth");
    let same_name = format!("{prefix}_same_name");
    let visible_scope = format!("{prefix}_visible_scope");
    let visible_function = format!("{prefix}_visible_function");

    let mut nodes = vec![
        Node::let_bind(out_name, Expr::u32(0)),
        Node::let_bind(
            &target_base,
            Expr::mul(idx.clone(), Expr::u32(VAST_NODE_STRIDE_U32)),
        ),
        Node::let_bind(
            &target_link_raw,
            if let Some(decl_contexts) = decl_contexts {
                Expr::load(
                    decl_contexts,
                    Expr::add(
                        Expr::mul(idx.clone(), Expr::u32(VAST_DECL_CONTEXT_STRIDE_U32)),
                        Expr::u32(VAST_DECL_CONTEXT_PREV_DECL_LINK_FIELD),
                    ),
                )
            } else {
                Expr::load(
                    vast_nodes,
                    Expr::add(Expr::var(&target_base), Expr::u32(VAST_TYPEDEF_FLAGS_FIELD)),
                )
            },
        ),
        Node::let_bind(
            &target_prepared,
            Expr::ne(Expr::var(&target_link_raw), Expr::u32(0)),
        ),
        Node::let_bind(
            &target_chain_len,
            if let Some(decl_contexts) = decl_contexts {
                Expr::load(
                    decl_contexts,
                    Expr::add(
                        Expr::mul(idx.clone(), Expr::u32(VAST_DECL_CONTEXT_STRIDE_U32)),
                        Expr::u32(VAST_DECL_CONTEXT_PREV_DECL_CHAIN_LEN_FIELD),
                    ),
                )
            } else {
                idx.clone()
            },
        ),
        Node::let_bind(
            &scan_limit,
            Expr::select(
                Expr::var(&target_prepared),
                Expr::var(&target_chain_len),
                idx.clone(),
            ),
        ),
    ];
    let mut lookup_body = Vec::new();
    lookup_body.extend(emit_identifier_hash_for_row(
        vast_nodes,
        haystack,
        haystack_len,
        Expr::var(&target_base),
        &format!("{prefix}_target"),
        packed_haystack,
    ));
    lookup_body.push(Node::let_bind(
        &target_scope,
        Expr::load(
            vast_nodes,
            Expr::add(Expr::var(&target_base), Expr::u32(VAST_TYPEDEF_SCOPE_FIELD)),
        ),
    ));
    let mut target_scope_fallback = emit_scope_open_scan_assign_for_index(
        vast_nodes,
        idx.clone(),
        &target_scope,
        &format!("{prefix}_scope"),
    );
    target_scope_fallback.insert(0, Node::assign(&target_scope, Expr::u32(SENTINEL)));
    lookup_body.push(Node::if_then(
        Expr::not(Expr::var(&target_prepared)),
        target_scope_fallback,
    ));
    nodes.push(Node::let_bind(&last_decl_kind, Expr::u32(0)));
    nodes.push(Node::let_bind(
        &chain_cursor,
        Expr::select(
            Expr::and(
                Expr::var(&target_prepared),
                Expr::ne(Expr::var(&target_link_raw), Expr::u32(SENTINEL)),
            ),
            Expr::sub(Expr::var(&target_link_raw), Expr::u32(1)),
            Expr::u32(SENTINEL),
        ),
    ));
    nodes.push(Node::if_then(
        Expr::or(
            Expr::not(Expr::var(&target_prepared)),
            Expr::ne(Expr::var(&chain_cursor), Expr::u32(SENTINEL)),
        ),
        {
            lookup_body.push(Node::loop_for(
                &scan_offset,
                Expr::u32(0),
                Expr::var(&scan_limit),
                vec![
                    Node::let_bind(
                        &scan,
                        Expr::select(
                            Expr::var(&target_prepared),
                            Expr::var(&chain_cursor),
                            Expr::sub(
                                Expr::sub(idx.clone(), Expr::u32(1)),
                                Expr::var(&scan_offset),
                            ),
                        ),
                    ),
                    Node::let_bind(&scan_valid, Expr::ne(Expr::var(&scan), Expr::u32(SENTINEL))),
                    Node::let_bind(
                        &scan_safe,
                        Expr::select(Expr::var(&scan_valid), Expr::var(&scan), Expr::u32(0)),
                    ),
                    Node::let_bind(
                        &scan_base,
                        Expr::mul(Expr::var(&scan_safe), Expr::u32(VAST_NODE_STRIDE_U32)),
                    ),
                    Node::let_bind(
                        &scan_kind,
                        Expr::select(
                            Expr::var(&scan_valid),
                            Expr::load(vast_nodes, Expr::var(&scan_base)),
                            Expr::u32(SENTINEL),
                        ),
                    ),
                    Node::if_then(
                        Expr::and(
                            Expr::var(&scan_valid),
                            Expr::and(
                                Expr::eq(Expr::var(&last_decl_kind), Expr::u32(0)),
                                Expr::eq(Expr::var(&scan_kind), Expr::u32(TOK_IDENTIFIER)),
                            ),
                        ),
                        {
                            let scan_hash_prefix = format!("{prefix}_scan_hash");
                            let target_hash = format!("{prefix}_target_hash");
                            let target_len = format!("{prefix}_target_len");
                            let scan_len = format!("{prefix}_scan_len");
                            let scan_next_idx = format!("{prefix}_scan_next_idx");
                            let scan_next_base = format!("{prefix}_scan_next_base");
                            let scan_next_kind = format!("{prefix}_scan_next_kind");
                            let scan_possible_declarator =
                                format!("{prefix}_scan_possible_declarator");
                            let mut body = emit_identifier_hash_for_row(
                                vast_nodes,
                                haystack,
                                haystack_len,
                                Expr::var(&scan_base),
                                &scan_hash_prefix,
                                packed_haystack,
                            );
                            body.push(Node::let_bind(
                                &same_name,
                                Expr::and(
                                    Expr::eq(
                                        Expr::var(format!("{scan_hash_prefix}_hash")),
                                        Expr::var(&target_hash),
                                    ),
                                    Expr::eq(
                                        Expr::var(format!("{scan_hash_prefix}_len")),
                                        Expr::var(&target_len),
                                    ),
                                ),
                            ));
                            let mut same_name_body = Vec::new();
                            same_name_body.push(Node::let_bind(
                                &scan_scope,
                                Expr::load(
                                    vast_nodes,
                                    Expr::add(
                                        Expr::var(&scan_base),
                                        Expr::u32(VAST_TYPEDEF_SCOPE_FIELD),
                                    ),
                                ),
                            ));
                            let mut scan_scope_fallback = emit_scope_open_scan_assign_for_index(
                                vast_nodes,
                                Expr::var(&scan),
                                &scan_scope,
                                &format!("{prefix}_scan_scope"),
                            );
                            scan_scope_fallback
                                .insert(0, Node::assign(&scan_scope, Expr::u32(SENTINEL)));
                            same_name_body.push(Node::if_then(
                                Expr::not(Expr::var(&target_prepared)),
                                scan_scope_fallback,
                            ));
                            same_name_body.extend(emit_builtin_declaration_kind_for_index(
                                vast_nodes,
                                Expr::var(&scan),
                                &scan_decl_kind,
                                &format!("{prefix}_scan_decl"),
                                decl_contexts,
                            ));
                            same_name_body
                                .push(Node::let_bind(&visible_function, Expr::bool(true)));
                            let mut scan_function_body = emit_enclosing_function_lparen_for_index(
                                vast_nodes,
                                idx.clone(),
                                &target_function,
                                &format!("{prefix}_function"),
                            );
                            scan_function_body.extend(emit_enclosing_function_lparen_for_index(
                                vast_nodes,
                                Expr::var(&scan),
                                &scan_function,
                                &format!("{prefix}_scan_function"),
                            ));
                            scan_function_body.push(Node::assign(
                                &visible_function,
                                Expr::or(
                                    Expr::eq(Expr::var(&scan_function), Expr::u32(SENTINEL)),
                                    Expr::eq(
                                        Expr::var(&scan_function),
                                        Expr::var(&target_function),
                                    ),
                                ),
                            ));
                            same_name_body.push(Node::if_then(
                                Expr::eq(Expr::var(&scan_decl_kind), Expr::u32(2)),
                                scan_function_body,
                            ));
                            same_name_body.push(Node::let_bind(
                                &visible_scope,
                                Expr::eq(Expr::var(&scan_scope), Expr::u32(SENTINEL)),
                            ));
                            same_name_body.push(Node::if_then(
                                Expr::and(
                                    Expr::not(Expr::var(&visible_scope)),
                                    Expr::and(
                                        Expr::var(&visible_function),
                                        Expr::ne(Expr::var(&scan_decl_kind), Expr::u32(0)),
                                    ),
                                ),
                                vec![
                                    Node::let_bind(&scope_walk, Expr::var(&target_scope)),
                                    Node::loop_for(
                                        &scope_walk_depth,
                                        Expr::u32(0),
                                        Expr::var("annot_num_nodes"),
                                        vec![
                                            Node::if_then(
                                                Expr::and(
                                                    Expr::not(Expr::var(&visible_scope)),
                                                    Expr::eq(
                                                        Expr::var(&scope_walk),
                                                        Expr::var(&scan_scope),
                                                    ),
                                                ),
                                                vec![Node::assign(
                                                    &visible_scope,
                                                    Expr::bool(true),
                                                )],
                                            ),
                                            Node::if_then(
                                                Expr::and(
                                                    Expr::not(Expr::var(&visible_scope)),
                                                    Expr::ne(
                                                        Expr::var(&scope_walk),
                                                        Expr::u32(SENTINEL),
                                                    ),
                                                ),
                                                vec![Node::assign(
                                                    &scope_walk,
                                                    Expr::load(
                                                        vast_nodes,
                                                        Expr::add(
                                                            Expr::mul(
                                                                Expr::var(&scope_walk),
                                                                Expr::u32(VAST_NODE_STRIDE_U32),
                                                            ),
                                                            Expr::u32(1),
                                                        ),
                                                    ),
                                                )],
                                            ),
                                        ],
                                    ),
                                ],
                            ));
                            same_name_body.push(Node::if_then(
                                Expr::and(
                                    Expr::var(&visible_scope),
                                    Expr::and(
                                        Expr::var(&visible_function),
                                        Expr::ne(Expr::var(&scan_decl_kind), Expr::u32(0)),
                                    ),
                                ),
                                vec![Node::assign(&last_decl_kind, Expr::var(&scan_decl_kind))],
                            ));
                            body.push(Node::if_then(Expr::var(&same_name), same_name_body));
                            vec![
                                Node::let_bind(
                                    &scan_len,
                                    Expr::load(
                                        vast_nodes,
                                        Expr::add(Expr::var(&scan_base), Expr::u32(6)),
                                    ),
                                ),
                                Node::let_bind(
                                    &scan_next_idx,
                                    Expr::select(
                                        Expr::lt(
                                            Expr::add(Expr::var(&scan), Expr::u32(1)),
                                            Expr::var("annot_num_nodes"),
                                        ),
                                        Expr::add(Expr::var(&scan), Expr::u32(1)),
                                        Expr::var(&scan),
                                    ),
                                ),
                                Node::let_bind(
                                    &scan_next_base,
                                    Expr::mul(
                                        Expr::var(&scan_next_idx),
                                        Expr::u32(VAST_NODE_STRIDE_U32),
                                    ),
                                ),
                                Node::let_bind(
                                    &scan_next_kind,
                                    Expr::load(vast_nodes, Expr::var(&scan_next_base)),
                                ),
                                Node::let_bind(
                                    &scan_possible_declarator,
                                    any_token_eq(
                                        Expr::var(&scan_next_kind),
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
                                    Expr::and(
                                        Expr::var(&scan_possible_declarator),
                                        Expr::eq(Expr::var(&scan_len), Expr::var(&target_len)),
                                    ),
                                    body,
                                ),
                            ]
                        },
                    ),
                    Node::if_then(
                        Expr::and(Expr::var(&target_prepared), Expr::var(&scan_valid)),
                        vec![
                            Node::let_bind(
                                &chain_raw,
                                Expr::load(
                                    vast_nodes,
                                    Expr::add(
                                        Expr::var(&scan_base),
                                        Expr::u32(VAST_TYPEDEF_FLAGS_FIELD),
                                    ),
                                ),
                            ),
                            Node::assign(
                                &chain_cursor,
                                Expr::select(
                                    Expr::or(
                                        Expr::eq(Expr::var(&chain_raw), Expr::u32(0)),
                                        Expr::eq(Expr::var(&chain_raw), Expr::u32(SENTINEL)),
                                    ),
                                    Expr::u32(SENTINEL),
                                    Expr::sub(Expr::var(&chain_raw), Expr::u32(1)),
                                ),
                            ),
                        ],
                    ),
                ],
            ));
            lookup_body
        },
    ));
    nodes.push(Node::if_then(
        Expr::eq(Expr::var(&last_decl_kind), Expr::u32(1)),
        vec![Node::assign(out_name, Expr::u32(1))],
    ));
    nodes
}

pub(crate) fn emit_typedef_visibility_scan(
    vast_nodes: &str,
    haystack: &str,
    decl_contexts: Option<&str>,
    haystack_len: &Expr,
    _num_nodes: &Expr,
    t: Expr,
    packed_haystack: bool,
) -> Vec<Node> {
    let mut nodes = Vec::new();
    nodes.extend(emit_visible_typedef_name_for_index(
        vast_nodes,
        haystack,
        decl_contexts,
        haystack_len,
        t,
        "current_visible_typedef_name",
        "current_visible_typedef",
        packed_haystack,
    ));
    nodes.push(Node::assign(
        "last_decl_kind",
        Expr::select(
            Expr::eq(Expr::var("current_visible_typedef_name"), Expr::u32(1)),
            Expr::u32(1),
            Expr::u32(0),
        ),
    ));
    nodes
}
