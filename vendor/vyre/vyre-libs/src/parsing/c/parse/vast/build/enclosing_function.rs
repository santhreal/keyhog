use super::*;

pub(crate) fn emit_enclosing_function_lparen_for_index(
    vast_nodes: &str,
    idx: Expr,
    out_name: &str,
    prefix: &str,
) -> Vec<Node> {
    let base = format!("{prefix}_base");
    let parent = format!("{prefix}_parent");
    let parent_walk = format!("{prefix}_parent_walk");
    let parent_base = format!("{prefix}_parent_base");
    let parent_kind = format!("{prefix}_parent_kind");
    let parent_prev_kind = format!("{prefix}_parent_prev_kind");
    let scope = format!("{prefix}_scope");
    let scope_walk = format!("{prefix}_scope_walk");
    let scope_base = format!("{prefix}_scope_base");
    let scope_kind = format!("{prefix}_scope_kind");
    let candidate = format!("{prefix}_candidate");
    let paren_depth = format!("{prefix}_paren_depth");
    let scan = format!("{prefix}_scan");
    let rev = format!("{prefix}_rev");
    let scan_kind = format!("{prefix}_scan_kind");
    let scan_prev_kind = format!("{prefix}_scan_prev_kind");

    let mut nodes = vec![
        Node::let_bind(out_name, Expr::u32(SENTINEL)),
        Node::let_bind(
            &base,
            Expr::mul(idx.clone(), Expr::u32(VAST_NODE_STRIDE_U32)),
        ),
        Node::let_bind(
            &parent,
            Expr::load(vast_nodes, Expr::add(Expr::var(&base), Expr::u32(1))),
        ),
        Node::loop_for(
            &parent_walk,
            Expr::u32(0),
            Expr::var("annot_num_nodes"),
            vec![Node::if_then(
                Expr::and(
                    Expr::eq(Expr::var(out_name), Expr::u32(SENTINEL)),
                    Expr::lt(Expr::var(&parent), Expr::var("annot_num_nodes")),
                ),
                vec![
                    Node::let_bind(
                        &parent_base,
                        Expr::mul(Expr::var(&parent), Expr::u32(VAST_NODE_STRIDE_U32)),
                    ),
                    Node::let_bind(
                        &parent_kind,
                        Expr::load(vast_nodes, Expr::var(&parent_base)),
                    ),
                    Node::let_bind(
                        &parent_prev_kind,
                        Expr::select(
                            Expr::gt(Expr::var(&parent), Expr::u32(0)),
                            Expr::load(
                                vast_nodes,
                                Expr::mul(
                                    Expr::sub(Expr::var(&parent), Expr::u32(1)),
                                    Expr::u32(VAST_NODE_STRIDE_U32),
                                ),
                            ),
                            Expr::u32(SENTINEL),
                        ),
                    ),
                    Node::if_then(
                        Expr::and(
                            Expr::eq(Expr::var(&parent_kind), Expr::u32(TOK_LPAREN)),
                            Expr::eq(Expr::var(&parent_prev_kind), Expr::u32(TOK_IDENTIFIER)),
                        ),
                        vec![Node::assign(out_name, Expr::var(&parent))],
                    ),
                    Node::assign(
                        &parent,
                        Expr::load(vast_nodes, Expr::add(Expr::var(&parent_base), Expr::u32(1))),
                    ),
                ],
            )],
        ),
    ];

    nodes.extend(emit_scope_open_for_index(
        vast_nodes,
        idx,
        &scope,
        &format!("{prefix}_scope_open"),
    ));
    nodes.push(Node::loop_for(
        &scope_walk,
        Expr::u32(0),
        Expr::var("annot_num_nodes"),
        vec![Node::if_then(
            Expr::and(
                Expr::eq(Expr::var(out_name), Expr::u32(SENTINEL)),
                Expr::lt(Expr::var(&scope), Expr::var("annot_num_nodes")),
            ),
            vec![
                Node::let_bind(
                    &scope_base,
                    Expr::mul(Expr::var(&scope), Expr::u32(VAST_NODE_STRIDE_U32)),
                ),
                Node::let_bind(&scope_kind, Expr::load(vast_nodes, Expr::var(&scope_base))),
                Node::if_then(
                    Expr::eq(Expr::var(&scope_kind), Expr::u32(TOK_LBRACE)),
                    vec![
                        Node::let_bind(&candidate, Expr::u32(SENTINEL)),
                        Node::let_bind(&paren_depth, Expr::u32(0)),
                        Node::loop_for(
                            &scan,
                            Expr::u32(0),
                            Expr::var(&scope),
                            vec![
                                Node::let_bind(
                                    &rev,
                                    Expr::sub(
                                        Expr::sub(Expr::var(&scope), Expr::u32(1)),
                                        Expr::var(&scan),
                                    ),
                                ),
                                Node::let_bind(
                                    &scan_kind,
                                    Expr::load(
                                        vast_nodes,
                                        Expr::mul(Expr::var(&rev), Expr::u32(VAST_NODE_STRIDE_U32)),
                                    ),
                                ),
                                Node::if_then(
                                    Expr::eq(Expr::var(&scan_kind), Expr::u32(TOK_RPAREN)),
                                    vec![Node::assign(
                                        &paren_depth,
                                        Expr::add(Expr::var(&paren_depth), Expr::u32(1)),
                                    )],
                                ),
                                Node::if_then(
                                    Expr::and(
                                        Expr::eq(Expr::var(&scan_kind), Expr::u32(TOK_LPAREN)),
                                        Expr::gt(Expr::var(&paren_depth), Expr::u32(0)),
                                    ),
                                    vec![
                                        Node::assign(
                                            &paren_depth,
                                            Expr::sub(Expr::var(&paren_depth), Expr::u32(1)),
                                        ),
                                        Node::if_then(
                                            Expr::and(
                                                Expr::eq(Expr::var(&paren_depth), Expr::u32(0)),
                                                Expr::eq(
                                                    Expr::var(&candidate),
                                                    Expr::u32(SENTINEL),
                                                ),
                                            ),
                                            vec![
                                                Node::let_bind(
                                                    &scan_prev_kind,
                                                    Expr::select(
                                                        Expr::gt(Expr::var(&rev), Expr::u32(0)),
                                                        Expr::load(
                                                            vast_nodes,
                                                            Expr::mul(
                                                                Expr::sub(
                                                                    Expr::var(&rev),
                                                                    Expr::u32(1),
                                                                ),
                                                                Expr::u32(VAST_NODE_STRIDE_U32),
                                                            ),
                                                        ),
                                                        Expr::u32(SENTINEL),
                                                    ),
                                                ),
                                                Node::if_then(
                                                    Expr::eq(
                                                        Expr::var(&scan_prev_kind),
                                                        Expr::u32(TOK_IDENTIFIER),
                                                    ),
                                                    vec![Node::assign(&candidate, Expr::var(&rev))],
                                                ),
                                            ],
                                        ),
                                    ],
                                ),
                            ],
                        ),
                        Node::if_then(
                            Expr::ne(Expr::var(&candidate), Expr::u32(SENTINEL)),
                            vec![Node::assign(out_name, Expr::var(&candidate))],
                        ),
                    ],
                ),
                Node::assign(
                    &scope,
                    Expr::load(vast_nodes, Expr::add(Expr::var(&scope_base), Expr::u32(1))),
                ),
            ],
        )],
    ));
    nodes
}
