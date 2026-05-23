use super::*;

/// Extracted C11 Functions using Tier 3 Subgroup Allocation Strategy
#[must_use]
pub fn c11_extract_functions(
    tok_types: &str,
    paren_pairs: &str,
    brace_pairs: &str,
    num_tokens: Expr,
    out_functions: &str,
    out_counts: &str,
) -> Program {
    let t = Expr::var("t");

    // Flattened guard: `Expr::load` has no side effects, so reading
    // `next_type`, `matching_rparen`, `after_rparen_type`, and
    // `matching_rbrace` unconditionally at every index is cheaper
    // than the original 5-level nested if_then and keeps the
    // composition under the depth-6 budget enforced by
    // vyre-conform-enforce. Non-identifier positions read values
    // that never reach the `is_match` write path because the
    // guard expression gates the whole decision.
    let loop_body = vec![
        Node::let_bind("tok_type", Expr::load(tok_types, t.clone())),
        Node::let_bind("prev_type", Expr::u32(0)),
        Node::if_then(
            Expr::gt(t.clone(), Expr::u32(0)),
            vec![Node::assign(
                "prev_type",
                Expr::load(tok_types, Expr::sub(t.clone(), Expr::u32(1))),
            )],
        ),
        Node::let_bind(
            "next_type",
            Expr::load(tok_types, Expr::add(t.clone(), Expr::u32(1))),
        ),
        Node::let_bind("before_wrapper_type", Expr::u32(TOK_EOF)),
        Node::if_then(
            Expr::gt(t.clone(), Expr::u32(1)),
            vec![Node::assign(
                "before_wrapper_type",
                Expr::load(tok_types, Expr::sub(t.clone(), Expr::u32(2))),
            )],
        ),
        Node::let_bind(
            "matching_rparen",
            Expr::load(paren_pairs, Expr::add(t.clone(), Expr::u32(1))),
        ),
        Node::let_bind("parenthesized_wrapper_rparen", Expr::u32(u32::MAX)),
        Node::if_then(
            Expr::gt(t.clone(), Expr::u32(0)),
            vec![Node::assign(
                "parenthesized_wrapper_rparen",
                Expr::load(paren_pairs, Expr::sub(t.clone(), Expr::u32(1))),
            )],
        ),
        Node::let_bind("after_wrapper_type", Expr::u32(TOK_EOF)),
        Node::let_bind("after_wrapper_rparen", Expr::u32(u32::MAX)),
        Node::if_then(
            Expr::lt(Expr::add(t.clone(), Expr::u32(2)), num_tokens.clone()),
            vec![
                Node::assign(
                    "after_wrapper_type",
                    Expr::load(tok_types, Expr::add(t.clone(), Expr::u32(2))),
                ),
                Node::assign(
                    "after_wrapper_rparen",
                    Expr::load(paren_pairs, Expr::add(t.clone(), Expr::u32(2))),
                ),
            ],
        ),
        Node::let_bind(
            "is_parenthesized_function_name",
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("tok_type"), Expr::u32(TOK_IDENTIFIER)),
                    Expr::and(
                        Expr::eq(Expr::var("prev_type"), Expr::u32(TOK_LPAREN)),
                        Expr::eq(Expr::var("next_type"), Expr::u32(TOK_RPAREN)),
                    ),
                ),
                Expr::and(
                    Expr::eq(
                        Expr::var("parenthesized_wrapper_rparen"),
                        Expr::add(t.clone(), Expr::u32(1)),
                    ),
                    Expr::eq(Expr::var("after_wrapper_type"), Expr::u32(TOK_LPAREN)),
                ),
            ),
        ),
        Node::let_bind(
            "is_numeric_suffix_function_name",
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("tok_type"), Expr::u32(TOK_IDENTIFIER)),
                    Expr::eq(Expr::var("next_type"), Expr::u32(TOK_INTEGER)),
                ),
                Expr::eq(Expr::var("after_wrapper_type"), Expr::u32(TOK_LPAREN)),
            ),
        ),
        Node::if_then(
            Expr::var("is_numeric_suffix_function_name"),
            vec![Node::assign(
                "matching_rparen",
                Expr::var("after_wrapper_rparen"),
            )],
        ),
        Node::if_then(
            Expr::var("is_parenthesized_function_name"),
            vec![Node::assign(
                "matching_rparen",
                Expr::var("after_wrapper_rparen"),
            )],
        ),
    ];
    let mut loop_body = loop_body;
    loop_body.extend(emit_body_open_scan(
        tok_types,
        Expr::add(Expr::var("matching_rparen"), Expr::u32(1)),
        num_tokens.clone(),
        "body_open",
    ));
    loop_body.extend([
        Node::let_bind("matching_rbrace", Expr::u32(u32::MAX)),
        Node::if_then(
            Expr::ne(Expr::var("body_open"), Expr::u32(u32::MAX)),
            vec![Node::assign(
                "matching_rbrace",
                Expr::load(brace_pairs, Expr::var("body_open")),
            )],
        ),
        // Single flattened predicate. 5-way AND collapses the
        // previously-nested shape into one if_then.
        Node::let_bind(
            "is_attribute_suffix",
            Expr::and(
                Expr::eq(Expr::var("prev_type"), Expr::u32(TOK_RPAREN)),
                Expr::eq(Expr::var("before_wrapper_type"), Expr::u32(TOK_RPAREN)),
            ),
        ),
        Node::let_bind(
            "is_match",
            Expr::and(
                Expr::and(
                    Expr::and(
                        Expr::eq(Expr::var("tok_type"), Expr::u32(TOK_IDENTIFIER)),
                        Expr::or(
                            Expr::and(
                                Expr::or(
                                    Expr::eq(Expr::var("next_type"), Expr::u32(TOK_LPAREN)),
                                    Expr::var("is_numeric_suffix_function_name"),
                                ),
                                Expr::or(
                                    function_prefix_token(Expr::var("prev_type")),
                                    Expr::var("is_attribute_suffix"),
                                ),
                            ),
                            Expr::and(
                                Expr::var("is_parenthesized_function_name"),
                                function_prefix_token(Expr::var("before_wrapper_type")),
                            ),
                        ),
                    ),
                    Expr::and(
                        Expr::ne(Expr::var("matching_rparen"), Expr::u32(u32::MAX)),
                        Expr::ne(Expr::var("body_open"), Expr::u32(u32::MAX)),
                    ),
                ),
                Expr::ne(Expr::var("matching_rbrace"), Expr::u32(u32::MAX)),
            ),
        ),
        Node::if_then(
            Expr::var("is_match"),
            vec![
                Node::let_bind("body_start", Expr::var("body_open")),
                Node::let_bind("body_end", Expr::var("matching_rbrace")),
                Node::store(out_functions, Expr::var("sparse_idx"), t.clone()),
                Node::store(
                    out_functions,
                    Expr::add(Expr::var("sparse_idx"), Expr::u32(1)),
                    Expr::var("body_start"),
                ),
                Node::store(
                    out_functions,
                    Expr::add(Expr::var("sparse_idx"), Expr::u32(2)),
                    Expr::var("body_end"),
                ),
            ],
        ),
    ]);

    let tok_count = match &num_tokens {
        Expr::LitU32(n) => *n,
        _ => 1,
    };
    Program::wrapped(
        vec![
            BufferDecl::storage(tok_types, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_count),
            BufferDecl::storage(paren_pairs, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_count),
            BufferDecl::storage(brace_pairs, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_count),
            BufferDecl::output(out_functions, 3, DataType::U32)
                .with_count(tok_count.saturating_mul(3).max(3)),
            BufferDecl::storage(out_counts, 4, BufferAccess::ReadWrite, DataType::U32)
                .with_count(1)
                .with_pipeline_live_out(true),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(
            "vyre-libs::parsing::c11_extract_functions",
            vec![
                Node::let_bind("lane", Expr::LocalId { axis: 0 }),
                Node::let_bind("block", Expr::WorkgroupId { axis: 0 }),
                Node::let_bind(
                    "t",
                    Expr::add(
                        Expr::mul(Expr::var("block"), Expr::u32(256)),
                        Expr::var("lane"),
                    ),
                ),
                Node::let_bind("sparse_idx", Expr::mul(t.clone(), Expr::u32(3))),
                Node::if_then(
                    Expr::lt(t.clone(), num_tokens.clone()),
                    vec![
                        Node::if_then(
                            Expr::eq(t.clone(), Expr::u32(0)),
                            vec![Node::store(
                                out_counts,
                                Expr::u32(0),
                                Expr::mul(num_tokens.clone(), Expr::u32(3)),
                            )],
                        ),
                        Node::store(out_functions, Expr::var("sparse_idx"), Expr::u32(0)),
                        Node::store(
                            out_functions,
                            Expr::add(Expr::var("sparse_idx"), Expr::u32(1)),
                            Expr::u32(0),
                        ),
                        Node::store(
                            out_functions,
                            Expr::add(Expr::var("sparse_idx"), Expr::u32(2)),
                            Expr::u32(0),
                        ),
                    ],
                ),
                Node::if_then(
                    Expr::lt(t.clone(), Expr::sub(num_tokens.clone(), Expr::u32(2))),
                    loop_body,
                ),
            ],
        )],
    )
    .with_entry_op_id("vyre-libs::parsing::c11_extract_functions")
    .with_non_composable_with_self(true)
}
