use crate::parsing::c::lex::tokens::*;
use vyre::ir::{Expr, Node};

/// No declaration kind.
pub const DECL_KIND_NONE: u32 = 0;
/// Function definition declaration kind.
pub const DECL_KIND_FUNCTION: u32 = 1;
/// Function prototype declaration kind.
pub const DECL_KIND_FUNCTION_DECL: u32 = 2;
/// Variable declaration kind.
pub const DECL_KIND_VARIABLE: u32 = 3;
/// Label declaration kind.
pub const DECL_KIND_LABEL: u32 = 4;
/// Typedef declaration kind.
pub const DECL_KIND_TYPEDEF: u32 = 5;
/// Enum constant declaration kind.
pub const DECL_KIND_ENUM_CONSTANT: u32 = 6;

fn expr_is_any(token: Expr, candidates: &[u32]) -> Expr {
    let mut iter = candidates.iter();
    let Some(first) = iter.next() else {
        return Expr::u32(0);
    };
    iter.fold(
        Expr::eq(token.clone(), Expr::u32(*first)),
        |acc, candidate| Expr::or(acc, Expr::eq(token.clone(), Expr::u32(*candidate))),
    )
}

fn tag_keyword(token: Expr) -> Expr {
    expr_is_any(token, &[TOK_STRUCT, TOK_UNION, TOK_ENUM])
}

fn declaration_prefix(token: Expr) -> Expr {
    expr_is_any(
        token,
        &[
            TOK_AUTO,
            TOK_CONST,
            TOK_DOUBLE,
            TOK_ENUM,
            TOK_EXTERN,
            TOK_FLOAT_KW,
            TOK_INLINE,
            TOK_LONG,
            TOK_REGISTER,
            TOK_RESTRICT,
            TOK_SHORT,
            TOK_SIGNED,
            TOK_STATIC,
            TOK_STRUCT,
            TOK_THREAD_LOCAL,
            TOK_TYPEDEF,
            TOK_UNION,
            TOK_UNSIGNED,
            TOK_VOLATILE,
        ],
    )
}

/// Return an IR predicate that is true when the previous token can introduce a declaration.
pub fn declaration_context(prev_tok: Expr) -> Expr {
    Expr::or(
        Expr::eq(prev_tok.clone(), Expr::u32(TOK_INT)),
        Expr::or(
            Expr::eq(prev_tok.clone(), Expr::u32(TOK_CHAR_KW)),
            Expr::or(
                Expr::eq(prev_tok.clone(), Expr::u32(TOK_VOID)),
                Expr::or(
                    Expr::eq(prev_tok.clone(), Expr::u32(TOK_STRUCT)),
                    Expr::or(
                        Expr::eq(prev_tok.clone(), Expr::u32(TOK_TYPEDEF)),
                        Expr::or(
                            Expr::eq(prev_tok.clone(), Expr::u32(TOK_COMMA)),
                            Expr::or(
                                Expr::eq(prev_tok.clone(), Expr::u32(TOK_SEMICOLON)),
                                Expr::or(
                                    Expr::eq(prev_tok.clone(), Expr::u32(TOK_LPAREN)),
                                    Expr::or(
                                        Expr::eq(prev_tok.clone(), Expr::u32(TOK_RPAREN)),
                                        Expr::or(
                                            Expr::eq(prev_tok.clone(), Expr::u32(TOK_STAR)),
                                            declaration_prefix(prev_tok),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
}

fn emit_neighbor_tokens(node_idx: &Expr, num_tokens: &Expr) -> Vec<Node> {
    vec![
        Node::let_bind("prev_prev_tok", Expr::u32(0)),
        Node::if_then(
            Expr::gt(node_idx.clone(), Expr::u32(1)),
            vec![Node::assign(
                "prev_prev_tok",
                Expr::load("tok_types", Expr::sub(node_idx.clone(), Expr::u32(2))),
            )],
        ),
        Node::let_bind("next_next_tok", Expr::u32(0)),
        Node::if_then(
            Expr::lt(
                Expr::add(node_idx.clone(), Expr::u32(2)),
                num_tokens.clone(),
            ),
            vec![Node::assign(
                "next_next_tok",
                Expr::load("tok_types", Expr::add(node_idx.clone(), Expr::u32(2))),
            )],
        ),
    ]
}

fn emit_aggregate_context(node_idx: &Expr) -> Vec<Node> {
    vec![
        Node::let_bind("aggregate_kind", Expr::u32(0)),
        Node::let_bind("aggregate_depth", Expr::u32(0)),
        Node::loop_for(
            "aggregate_scan",
            Expr::u32(0),
            node_idx.clone(),
            vec![
                Node::let_bind(
                    "aggregate_idx",
                    Expr::sub(
                        Expr::sub(node_idx.clone(), Expr::u32(1)),
                        Expr::var("aggregate_scan"),
                    ),
                ),
                Node::let_bind(
                    "aggregate_tok",
                    Expr::load("tok_types", Expr::var("aggregate_idx")),
                ),
                Node::if_then(
                    Expr::eq(Expr::var("aggregate_tok"), Expr::u32(TOK_RBRACE)),
                    vec![Node::assign(
                        "aggregate_depth",
                        Expr::add(Expr::var("aggregate_depth"), Expr::u32(1)),
                    )],
                ),
                Node::if_then(
                    Expr::eq(Expr::var("aggregate_kind"), Expr::u32(0)),
                    vec![Node::if_then(
                        Expr::eq(Expr::var("aggregate_tok"), Expr::u32(TOK_LBRACE)),
                        vec![Node::if_then_else(
                            Expr::eq(Expr::var("aggregate_depth"), Expr::u32(0)),
                            emit_set_aggregate_kind(),
                            vec![Node::assign(
                                "aggregate_depth",
                                Expr::sub(Expr::var("aggregate_depth"), Expr::u32(1)),
                            )],
                        )],
                    )],
                ),
            ],
        ),
    ]
}

fn emit_set_aggregate_kind() -> Vec<Node> {
    vec![
        Node::let_bind("aggregate_prev", Expr::u32(0)),
        Node::let_bind("aggregate_prev_prev", Expr::u32(0)),
        Node::if_then(
            Expr::gt(Expr::var("aggregate_idx"), Expr::u32(0)),
            vec![Node::assign(
                "aggregate_prev",
                Expr::load(
                    "tok_types",
                    Expr::sub(Expr::var("aggregate_idx"), Expr::u32(1)),
                ),
            )],
        ),
        Node::if_then(
            Expr::gt(Expr::var("aggregate_idx"), Expr::u32(1)),
            vec![Node::assign(
                "aggregate_prev_prev",
                Expr::load(
                    "tok_types",
                    Expr::sub(Expr::var("aggregate_idx"), Expr::u32(2)),
                ),
            )],
        ),
        Node::if_then(
            tag_keyword(Expr::var("aggregate_prev")),
            vec![Node::assign("aggregate_kind", Expr::var("aggregate_prev"))],
        ),
        Node::if_then(
            Expr::and(
                Expr::eq(Expr::var("aggregate_kind"), Expr::u32(0)),
                tag_keyword(Expr::var("aggregate_prev_prev")),
            ),
            vec![Node::assign(
                "aggregate_kind",
                Expr::var("aggregate_prev_prev"),
            )],
        ),
    ]
}

fn emit_declaration_flags(node_idx: &Expr) -> Vec<Node> {
    vec![
        Node::let_bind("seen_typedef_in_decl", Expr::u32(0)),
        Node::let_bind("decl_prefix_active", Expr::u32(1)),
        Node::loop_for(
            "decl_prefix_scan",
            Expr::u32(0),
            node_idx.clone(),
            vec![
                Node::let_bind(
                    "decl_prefix_idx",
                    Expr::sub(
                        Expr::sub(node_idx.clone(), Expr::u32(1)),
                        Expr::var("decl_prefix_scan"),
                    ),
                ),
                Node::let_bind(
                    "decl_prefix_tok",
                    Expr::load("tok_types", Expr::var("decl_prefix_idx")),
                ),
                Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("decl_prefix_active"), Expr::u32(1)),
                        Expr::eq(Expr::var("decl_prefix_tok"), Expr::u32(TOK_TYPEDEF)),
                    ),
                    vec![Node::assign("seen_typedef_in_decl", Expr::u32(1))],
                ),
                Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("decl_prefix_active"), Expr::u32(1)),
                        Expr::or(
                            Expr::eq(Expr::var("decl_prefix_tok"), Expr::u32(TOK_SEMICOLON)),
                            Expr::eq(Expr::var("decl_prefix_tok"), Expr::u32(TOK_LBRACE)),
                        ),
                    ),
                    vec![Node::assign("decl_prefix_active", Expr::u32(0))],
                ),
            ],
        ),
    ]
}

/// Emit IR that classifies the declaration kind around `node_idx`.
pub fn emit_declaration_lookup(node_idx: Expr, num_tokens: &Expr) -> Vec<Node> {
    let mut nodes = vec![
        Node::let_bind("decl_kind", Expr::u32(DECL_KIND_NONE)),
        Node::let_bind("prev_idx", Expr::u32(u32::MAX)),
        Node::let_bind("next_idx", Expr::u32(u32::MAX)),
        Node::let_bind("prev_tok", Expr::u32(0)),
        Node::let_bind("next_tok", Expr::u32(0)),
    ];

    nodes.push(Node::if_then(
        Expr::gt(node_idx.clone(), Expr::u32(0)),
        vec![Node::assign(
            "prev_idx",
            Expr::sub(node_idx.clone(), Expr::u32(1)),
        )],
    ));
    nodes.push(Node::if_then(
        Expr::lt(
            Expr::add(node_idx.clone(), Expr::u32(1)),
            num_tokens.clone(),
        ),
        vec![Node::assign(
            "next_idx",
            Expr::add(node_idx.clone(), Expr::u32(1)),
        )],
    ));

    nodes.push(Node::if_then(
        Expr::ne(Expr::var("prev_idx"), Expr::u32(u32::MAX)),
        vec![Node::assign(
            "prev_tok",
            Expr::load("tok_types", Expr::var("prev_idx")),
        )],
    ));
    nodes.push(Node::if_then(
        Expr::ne(Expr::var("next_idx"), Expr::u32(u32::MAX)),
        vec![Node::assign(
            "next_tok",
            Expr::load("tok_types", Expr::var("next_idx")),
        )],
    ));
    nodes.extend(emit_neighbor_tokens(&node_idx, num_tokens));
    nodes.extend(emit_aggregate_context(&node_idx));
    nodes.extend(emit_declaration_flags(&node_idx));

    nodes.push(Node::if_then(
        Expr::eq(Expr::var("tok_type"), Expr::u32(TOK_IDENTIFIER)),
        vec![Node::if_then_else(
            Expr::and(
                Expr::eq(Expr::var("next_tok"), Expr::u32(TOK_COLON)),
                Expr::and(
                    Expr::ne(Expr::var("prev_tok"), Expr::u32(TOK_CASE)),
                    Expr::ne(Expr::var("prev_tok"), Expr::u32(TOK_GOTO)),
                ),
            ),
            vec![Node::assign("decl_kind", Expr::u32(DECL_KIND_LABEL))],
            vec![Node::if_then_else(
                tag_keyword(Expr::var("prev_tok")),
                vec![Node::assign("decl_kind", Expr::u32(DECL_KIND_NONE))],
                vec![Node::if_then_else(
                    Expr::and(
                        Expr::eq(Expr::var("aggregate_kind"), Expr::u32(TOK_ENUM)),
                        Expr::or(
                            Expr::or(
                                Expr::eq(Expr::var("prev_tok"), Expr::u32(TOK_LBRACE)),
                                Expr::eq(Expr::var("prev_tok"), Expr::u32(TOK_COMMA)),
                            ),
                            Expr::or(
                                Expr::eq(Expr::var("next_tok"), Expr::u32(TOK_COMMA)),
                                Expr::or(
                                    Expr::eq(Expr::var("next_tok"), Expr::u32(TOK_ASSIGN)),
                                    Expr::eq(Expr::var("next_tok"), Expr::u32(TOK_RBRACE)),
                                ),
                            ),
                        ),
                    ),
                    vec![Node::assign(
                        "decl_kind",
                        Expr::u32(DECL_KIND_ENUM_CONSTANT),
                    )],
                    vec![Node::if_then_else(
                        Expr::and(
                            Expr::ne(Expr::var("aggregate_kind"), Expr::u32(0)),
                            Expr::ne(Expr::var("aggregate_kind"), Expr::u32(TOK_ENUM)),
                        ),
                        vec![Node::assign("decl_kind", Expr::u32(DECL_KIND_NONE))],
                        vec![
                            Node::if_then(
                    Expr::eq(Expr::var("next_tok"), Expr::u32(TOK_LPAREN)),
                    vec![
                        Node::let_bind("paren_depth", Expr::u32(1)),
                        Node::let_bind("matching_rparen", Expr::u32(u32::MAX)),
                        Node::if_then(
                            Expr::lt(
                                Expr::add(node_idx.clone(), Expr::u32(2)),
                                num_tokens.clone(),
                            ),
                            vec![Node::loop_for(
                                "paren_scan",
                                Expr::u32(0),
                                Expr::sub(
                                    num_tokens.clone(),
                                    Expr::add(node_idx.clone(), Expr::u32(2)),
                                ),
                                vec![
                                    Node::let_bind(
                                        "paren_idx",
                                        Expr::add(
                                            Expr::add(node_idx.clone(), Expr::u32(2)),
                                            Expr::var("paren_scan"),
                                        ),
                                    ),
                                    Node::let_bind(
                                        "paren_tok",
                                        Expr::load("tok_types", Expr::var("paren_idx")),
                                    ),
                                    Node::if_then(
                                        Expr::eq(Expr::var("paren_tok"), Expr::u32(TOK_LPAREN)),
                                        vec![Node::assign(
                                            "paren_depth",
                                            Expr::add(Expr::var("paren_depth"), Expr::u32(1)),
                                        )],
                                    ),
                                    Node::if_then(
                                        Expr::eq(Expr::var("paren_tok"), Expr::u32(TOK_RPAREN)),
                                        vec![Node::if_then_else(
                                            Expr::and(
                                                Expr::eq(Expr::var("paren_depth"), Expr::u32(1)),
                                                Expr::eq(
                                                    Expr::var("matching_rparen"),
                                                    Expr::u32(u32::MAX),
                                                ),
                                            ),
                                            vec![Node::assign(
                                                "matching_rparen",
                                                Expr::var("paren_idx"),
                                            )],
                                            vec![Node::assign(
                                                "paren_depth",
                                                Expr::sub(Expr::var("paren_depth"), Expr::u32(1)),
                                            )],
                                        )],
                                    ),
                                ],
                            )],
                        ),
                        Node::if_then(
                            Expr::ne(Expr::var("matching_rparen"), Expr::u32(u32::MAX)),
                            vec![
                                Node::let_bind("after_matching_paren", Expr::u32(u32::MAX)),
                                Node::let_bind("after_scan_active", Expr::u32(1)),
                                Node::if_then(
                                    Expr::lt(
                                        Expr::add(Expr::var("matching_rparen"), Expr::u32(1)),
                                        num_tokens.clone(),
                                    ),
                                    vec![Node::loop_for(
                                        "after_paren_scan",
                                        Expr::add(Expr::var("matching_rparen"), Expr::u32(1)),
                                        num_tokens.clone(),
                                        vec![
                                            Node::let_bind(
                                                "after_scan_tok",
                                                Expr::load("tok_types", Expr::var("after_paren_scan")),
                                            ),
                                            Node::if_then(
                                                Expr::and(
                                                    Expr::eq(
                                                        Expr::var("after_scan_active"),
                                                        Expr::u32(1),
                                                    ),
                                                    Expr::or(
                                                        Expr::eq(
                                                            Expr::var("after_scan_tok"),
                                                            Expr::u32(TOK_LBRACE),
                                                        ),
                                                        Expr::and(
                                                            Expr::eq(
                                                                Expr::var("after_scan_tok"),
                                                                Expr::u32(TOK_SEMICOLON),
                                                            ),
                                                            Expr::eq(
                                                                Expr::var("after_paren_scan"),
                                                                Expr::add(
                                                                    Expr::var("matching_rparen"),
                                                                    Expr::u32(1),
                                                                ),
                                                            ),
                                                        ),
                                                    ),
                                                ),
                                                vec![
                                                    Node::assign(
                                                        "after_matching_paren",
                                                        Expr::var("after_scan_tok"),
                                                    ),
                                                    Node::assign("after_scan_active", Expr::u32(0)),
                                                ],
                                            ),
                                        ],
                                    )],
                                ),
                                Node::if_then_else(
                                    Expr::eq(
                                        Expr::var("after_matching_paren"),
                                        Expr::u32(TOK_LBRACE),
                                    ),
                                    vec![Node::assign("decl_kind", Expr::u32(DECL_KIND_FUNCTION))],
                                    vec![Node::if_then_else(
                                        declaration_context(Expr::var("prev_tok")),
                                        vec![Node::if_then_else(
                                            Expr::eq(Expr::var("prev_tok"), Expr::u32(TOK_TYPEDEF)),
                                            vec![Node::assign(
                                                "decl_kind",
                                                Expr::u32(DECL_KIND_TYPEDEF),
                                            )],
                                            vec![Node::assign(
                                                "decl_kind",
                                                Expr::u32(DECL_KIND_FUNCTION_DECL),
                                            )],
                                        )],
                                        vec![Node::if_then(
                                            Expr::eq(Expr::var("prev_tok"), Expr::u32(TOK_TYPEDEF)),
                                            vec![Node::assign(
                                                "decl_kind",
                                                Expr::u32(DECL_KIND_TYPEDEF),
                                            )],
                                        )],
                                    )],
                                ),
                            ],
                        ),
                    ],
                ),
                Node::if_then_else(
                    Expr::eq(Expr::var("decl_kind"), Expr::u32(DECL_KIND_NONE)),
                    vec![Node::if_then_else(
                        Expr::or(
                            Expr::eq(Expr::var("prev_tok"), Expr::u32(TOK_TYPEDEF)),
                            Expr::eq(Expr::var("seen_typedef_in_decl"), Expr::u32(1)),
                        ),
                        vec![Node::assign("decl_kind", Expr::u32(DECL_KIND_TYPEDEF))],
                        vec![Node::if_then(
                            declaration_context(Expr::var("prev_tok")),
                            vec![Node::assign("decl_kind", Expr::u32(DECL_KIND_VARIABLE))],
                        )],
                    )],
                    vec![],
                ),
            ],
                    )],
                )],
            )],
        )],
    ));

    nodes
}
