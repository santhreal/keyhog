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
        Node::let_bind(
            "prev_sibling_first_child_typedef_flags",
            Expr::select(
                Expr::var("prev_sibling_first_child_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::add(
                        Expr::var("prev_sibling_first_child_base"),
                        Expr::u32(VAST_TYPEDEF_FLAGS_FIELD),
                    ),
                ),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "prev_sibling_first_child_symbol_hash",
            Expr::select(
                Expr::var("prev_sibling_first_child_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::add(
                        Expr::var("prev_sibling_first_child_base"),
                        Expr::u32(VAST_TYPEDEF_SYMBOL_FIELD),
                    ),
                ),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "cur_parent_valid",
            Expr::lt(Expr::var("cur_parent"), num_nodes.clone()),
        ),
        Node::let_bind(
            "safe_cur_parent_idx",
            Expr::select(
                Expr::var("cur_parent_valid"),
                Expr::var("cur_parent"),
                t.clone(),
            ),
        ),
        Node::let_bind(
            "cur_parent_base",
            Expr::mul(
                Expr::var("safe_cur_parent_idx"),
                Expr::u32(VAST_NODE_STRIDE_U32),
            ),
        ),
        Node::let_bind(
            "cur_parent_kind",
            Expr::select(
                Expr::var("cur_parent_valid"),
                Expr::load(vast_nodes, Expr::var("cur_parent_base")),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "cur_parent_parent",
            Expr::select(
                Expr::var("cur_parent_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::add(Expr::var("cur_parent_base"), Expr::u32(1)),
                ),
                Expr::u32(SENTINEL),
            ),
        ),
        Node::let_bind(
            "cur_parent_parent_valid",
            Expr::lt(Expr::var("cur_parent_parent"), num_nodes.clone()),
        ),
        Node::let_bind(
            "cur_parent_parent_base",
            Expr::mul(
                Expr::select(
                    Expr::var("cur_parent_parent_valid"),
                    Expr::var("cur_parent_parent"),
                    t.clone(),
                ),
                Expr::u32(VAST_NODE_STRIDE_U32),
            ),
        ),
        Node::let_bind(
            "cur_parent_parent_kind",
            Expr::select(
                Expr::var("cur_parent_parent_valid"),
                Expr::load(vast_nodes, Expr::var("cur_parent_parent_base")),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "cur_parent_parent_symbol_hash",
            Expr::select(
                Expr::var("cur_parent_parent_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::add(
                        Expr::var("cur_parent_parent_base"),
                        Expr::u32(VAST_TYPEDEF_SYMBOL_FIELD),
                    ),
                ),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "cur_parent_parent_parent",
            Expr::select(
                Expr::var("cur_parent_parent_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::add(Expr::var("cur_parent_parent_base"), Expr::u32(1)),
                ),
                Expr::u32(SENTINEL),
            ),
        ),
        Node::let_bind("cur_parent_prev_sibling_kind", Expr::u32(SENTINEL)),
        Node::let_bind("cur_parent_prev_prev_sibling_kind", Expr::u32(SENTINEL)),
        Node::loop_for(
            "cur_parent_prev_scan",
            Expr::u32(0),
            Expr::var("safe_cur_parent_idx"),
            vec![
                Node::let_bind(
                    "cur_parent_prev_scan_base",
                    Expr::mul(
                        Expr::var("cur_parent_prev_scan"),
                        Expr::u32(VAST_NODE_STRIDE_U32),
                    ),
                ),
                Node::let_bind(
                    "cur_parent_prev_scan_parent",
                    Expr::load(
                        vast_nodes,
                        Expr::add(Expr::var("cur_parent_prev_scan_base"), Expr::u32(1)),
                    ),
                ),
                Node::if_then(
                    Expr::and(
                        Expr::var("cur_parent_valid"),
                        Expr::eq(
                            Expr::var("cur_parent_prev_scan_parent"),
                            Expr::var("cur_parent_parent"),
                        ),
                    ),
                    vec![
                        Node::assign(
                            "cur_parent_prev_prev_sibling_kind",
                            Expr::var("cur_parent_prev_sibling_kind"),
                        ),
                        Node::assign(
                            "cur_parent_prev_sibling_kind",
                            Expr::load(vast_nodes, Expr::var("cur_parent_prev_scan_base")),
                        ),
                    ],
                ),
            ],
        ),
        Node::let_bind(
            "cur_parent_parent_safe_idx",
            Expr::select(
                Expr::var("cur_parent_parent_valid"),
                Expr::var("cur_parent_parent"),
                t.clone(),
            ),
        ),
        Node::let_bind("cur_grandparent_prev_sibling_kind", Expr::u32(SENTINEL)),
        Node::loop_for(
            "cur_grandparent_prev_scan",
            Expr::u32(0),
            Expr::var("cur_parent_parent_safe_idx"),
            vec![
                Node::let_bind(
                    "cur_grandparent_prev_scan_base",
                    Expr::mul(
                        Expr::var("cur_grandparent_prev_scan"),
                        Expr::u32(VAST_NODE_STRIDE_U32),
                    ),
                ),
                Node::let_bind(
                    "cur_grandparent_prev_scan_parent",
                    Expr::load(
                        vast_nodes,
                        Expr::add(Expr::var("cur_grandparent_prev_scan_base"), Expr::u32(1)),
                    ),
                ),
                Node::if_then(
                    Expr::and(
                        Expr::var("cur_parent_parent_valid"),
                        Expr::eq(
                            Expr::var("cur_grandparent_prev_scan_parent"),
                            Expr::var("cur_parent_parent_parent"),
                        ),
                    ),
                    vec![Node::assign(
                        "cur_grandparent_prev_sibling_kind",
                        Expr::load(vast_nodes, Expr::var("cur_grandparent_prev_scan_base")),
                    )],
                ),
            ],
        ),
        Node::let_bind(
            "cur_parent_parent_prev_adjacent_valid",
            Expr::and(
                Expr::var("cur_parent_parent_valid"),
                Expr::gt(Expr::var("cur_parent_parent"), Expr::u32(0)),
            ),
        ),
        Node::let_bind(
            "cur_parent_parent_prev_adjacent_base",
            Expr::mul(
                Expr::select(
                    Expr::var("cur_parent_parent_prev_adjacent_valid"),
                    Expr::sub(Expr::var("cur_parent_parent"), Expr::u32(1)),
                    t.clone(),
                ),
                Expr::u32(VAST_NODE_STRIDE_U32),
            ),
        ),
        Node::let_bind(
            "cur_parent_parent_prev_adjacent_kind",
            Expr::select(
                Expr::var("cur_parent_parent_prev_adjacent_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::var("cur_parent_parent_prev_adjacent_base"),
                ),
                Expr::u32(SENTINEL),
            ),
        ),
        Node::let_bind("colon_count_before", Expr::u32(0)),
        Node::loop_for(
            "colon_count_scan",
            Expr::u32(0),
            t.clone(),
            vec![
                Node::let_bind(
                    "colon_count_scan_base",
                    Expr::mul(
                        Expr::var("colon_count_scan"),
                        Expr::u32(VAST_NODE_STRIDE_U32),
                    ),
                ),
                Node::let_bind(
                    "colon_count_scan_parent",
                    Expr::load(
                        vast_nodes,
                        Expr::add(Expr::var("colon_count_scan_base"), Expr::u32(1)),
                    ),
                ),
                Node::let_bind(
                    "colon_count_scan_kind",
                    Expr::load(vast_nodes, Expr::var("colon_count_scan_base")),
                ),
                Node::if_then(
                    Expr::and(
                        Expr::eq(
                            Expr::var("colon_count_scan_parent"),
                            Expr::var("cur_parent"),
                        ),
                        Expr::eq(Expr::var("colon_count_scan_kind"), Expr::u32(TOK_COLON)),
                    ),
                    vec![Node::assign(
                        "colon_count_before",
                        Expr::add(Expr::var("colon_count_before"), Expr::u32(1)),
                    )],
                ),
            ],
        ),
        Node::let_bind(
            "cur_parent_next_idx",
            Expr::select(
                Expr::var("cur_parent_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::add(Expr::var("cur_parent_base"), Expr::u32(3)),
                ),
                Expr::u32(SENTINEL),
            ),
        ),
        Node::let_bind(
            "cur_parent_next_valid",
            Expr::lt(Expr::var("cur_parent_next_idx"), num_nodes.clone()),
        ),
        Node::let_bind(
            "cur_parent_next_kind",
            Expr::select(
                Expr::var("cur_parent_next_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::mul(
                        Expr::var("cur_parent_next_idx"),
                        Expr::u32(VAST_NODE_STRIDE_U32),
                    ),
                ),
                Expr::u32(0),
            ),
        ),
        Node::let_bind("parent_prev_kind", Expr::u32(SENTINEL)),
        Node::let_bind("parent_prev_prev_kind", Expr::u32(SENTINEL)),
        Node::let_bind("parent_has_decl_prefix", Expr::u32(0)),
        Node::let_bind(
            "parent_ctx_scan_limit",
            Expr::select(
                Expr::var("cur_parent_valid"),
                Expr::var("cur_parent"),
                Expr::u32(0),
            ),
        ),
    ]);
}
