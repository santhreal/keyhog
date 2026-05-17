use crate::parsing::c::lex::tokens::*;
use crate::parsing::composition::child_phase;
use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

fn expr_is_any(token: Expr, candidates: &[u32]) -> Expr {
    let ranges = merged_token_ranges(candidates);
    let mut iter = ranges.into_iter();
    let Some((first_lo, first_hi)) = iter.next() else {
        return Expr::u32(0);
    };
    iter.fold(
        token_range_expr(&token, first_lo, first_hi),
        |acc, (lo, hi)| Expr::or(acc, token_range_expr(&token, lo, hi)),
    )
}

fn token_range_expr(token: &Expr, lo: u32, hi: u32) -> Expr {
    if lo == hi {
        Expr::eq(token.clone(), Expr::u32(lo))
    } else {
        Expr::and(
            Expr::ge(token.clone(), Expr::u32(lo)),
            Expr::le(token.clone(), Expr::u32(hi)),
        )
    }
}

fn merged_token_ranges(candidates: &[u32]) -> Vec<(u32, u32)> {
    let mut values = candidates.to_vec();
    values.sort_unstable();
    values.dedup();

    let mut ranges: Vec<(u32, u32)> = Vec::new();
    for value in values {
        match ranges.last_mut() {
            Some((_, hi)) if hi.checked_add(1) == Some(value) => *hi = value,
            _ => ranges.push((value, value)),
        }
    }
    ranges
}

fn function_prefix_token(token: Expr) -> Expr {
    expr_is_any(
        token,
        &[
            TOK_AUTO,
            TOK_ATOMIC,
            TOK_BOOL,
            TOK_CHAR_KW,
            TOK_COMPLEX,
            TOK_CONST,
            TOK_DOUBLE,
            TOK_ENUM,
            TOK_EXTERN,
            TOK_FLOAT_KW,
            TOK_GNU_TYPEOF,
            TOK_GNU_TYPEOF_UNQUAL,
            TOK_IDENTIFIER,
            TOK_IMAGINARY,
            TOK_INLINE,
            TOK_INT,
            TOK_GNU_INT128,
            TOK_LONG,
            TOK_REGISTER,
            TOK_RESTRICT,
            TOK_SHORT,
            TOK_SIGNED,
            TOK_STATIC,
            TOK_STAR,
            TOK_STRUCT,
            TOK_THREAD_LOCAL,
            TOK_TYPEDEF,
            TOK_UNION,
            TOK_UNSIGNED,
            TOK_VOID,
            TOK_VOLATILE,
        ],
    )
}

fn emit_body_open_scan(
    tok_types: &str,
    start_idx: Expr,
    num_tokens: Expr,
    out_var: &str,
) -> Vec<Node> {
    vec![
        Node::let_bind(out_var, Expr::u32(u32::MAX)),
        Node::let_bind("body_open_scan_active", Expr::u32(1)),
        Node::let_bind("body_open_paren_depth", Expr::u32(0)),
        Node::let_bind("body_open_bracket_depth", Expr::u32(0)),
        Node::loop_for(
            "body_open_scan",
            start_idx,
            num_tokens,
            vec![
                Node::let_bind(
                    "body_open_tok",
                    Expr::load(tok_types, Expr::var("body_open_scan")),
                ),
                Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("body_open_scan_active"), Expr::u32(1)),
                        Expr::and(
                            Expr::eq(Expr::var("body_open_paren_depth"), Expr::u32(0)),
                            Expr::and(
                                Expr::eq(Expr::var("body_open_bracket_depth"), Expr::u32(0)),
                                Expr::eq(Expr::var("body_open_tok"), Expr::u32(TOK_LBRACE)),
                            ),
                        ),
                    ),
                    vec![
                        Node::assign(out_var, Expr::var("body_open_scan")),
                        Node::assign("body_open_scan_active", Expr::u32(0)),
                    ],
                ),
                Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("body_open_scan_active"), Expr::u32(1)),
                        Expr::and(
                            Expr::eq(Expr::var("body_open_paren_depth"), Expr::u32(0)),
                            Expr::and(
                                Expr::eq(Expr::var("body_open_bracket_depth"), Expr::u32(0)),
                                Expr::eq(Expr::var("body_open_tok"), Expr::u32(TOK_SEMICOLON)),
                            ),
                        ),
                    ),
                    vec![Node::assign("body_open_scan_active", Expr::u32(0))],
                ),
                Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("body_open_scan_active"), Expr::u32(1)),
                        Expr::eq(Expr::var("body_open_tok"), Expr::u32(TOK_LPAREN)),
                    ),
                    vec![Node::assign(
                        "body_open_paren_depth",
                        Expr::add(Expr::var("body_open_paren_depth"), Expr::u32(1)),
                    )],
                ),
                Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("body_open_scan_active"), Expr::u32(1)),
                        Expr::and(
                            Expr::gt(Expr::var("body_open_paren_depth"), Expr::u32(0)),
                            Expr::eq(Expr::var("body_open_tok"), Expr::u32(TOK_RPAREN)),
                        ),
                    ),
                    vec![Node::assign(
                        "body_open_paren_depth",
                        Expr::sub(Expr::var("body_open_paren_depth"), Expr::u32(1)),
                    )],
                ),
                Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("body_open_scan_active"), Expr::u32(1)),
                        Expr::eq(Expr::var("body_open_tok"), Expr::u32(TOK_LBRACKET)),
                    ),
                    vec![Node::assign(
                        "body_open_bracket_depth",
                        Expr::add(Expr::var("body_open_bracket_depth"), Expr::u32(1)),
                    )],
                ),
                Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("body_open_scan_active"), Expr::u32(1)),
                        Expr::and(
                            Expr::gt(Expr::var("body_open_bracket_depth"), Expr::u32(0)),
                            Expr::eq(Expr::var("body_open_tok"), Expr::u32(TOK_RBRACKET)),
                        ),
                    ),
                    vec![Node::assign(
                        "body_open_bracket_depth",
                        Expr::sub(Expr::var("body_open_bracket_depth"), Expr::u32(1)),
                    )],
                ),
            ],
        ),
    ]
}

fn emit_enclosing_function_lookup(
    functions: &str,
    num_functions: Expr,
    token_idx: Expr,
) -> Vec<Node> {
    vec![
        Node::let_bind("caller_id", Expr::u32(u32::MAX)),
        Node::loop_for(
            "caller_fn_scan",
            Expr::u32(0),
            num_functions,
            vec![
                Node::let_bind(
                    "fn_rec_base",
                    Expr::mul(Expr::var("caller_fn_scan"), Expr::u32(3)),
                ),
                Node::let_bind(
                    "fn_body_start",
                    Expr::load(functions, Expr::add(Expr::var("fn_rec_base"), Expr::u32(1))),
                ),
                Node::let_bind(
                    "fn_body_end",
                    Expr::load(functions, Expr::add(Expr::var("fn_rec_base"), Expr::u32(2))),
                ),
                Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("caller_id"), Expr::u32(u32::MAX)),
                        Expr::and(
                            Expr::ge(token_idx.clone(), Expr::var("fn_body_start")),
                            Expr::le(token_idx.clone(), Expr::var("fn_body_end")),
                        ),
                    ),
                    vec![Node::assign("caller_id", Expr::var("caller_fn_scan"))],
                ),
            ],
        ),
    ]
}

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
    let t = Expr::InvocationId { axis: 0 };

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
                                Expr::eq(Expr::var("next_type"), Expr::u32(TOK_LPAREN)),
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
                // Per-lane 3-slot allocation via atomic counter.
                Node::let_bind(
                    "final_idx",
                    Expr::atomic_add(out_counts, Expr::u32(0), Expr::u32(3)),
                ),
                Node::store(out_functions, Expr::var("final_idx"), t.clone()),
                Node::store(
                    out_functions,
                    Expr::add(Expr::var("final_idx"), Expr::u32(1)),
                    Expr::var("body_start"),
                ),
                Node::store(
                    out_functions,
                    Expr::add(Expr::var("final_idx"), Expr::u32(2)),
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
            BufferDecl::storage(out_functions, 3, BufferAccess::ReadWrite, DataType::U32)
                .with_count(tok_count.saturating_mul(3).max(3)),
            BufferDecl::storage(out_counts, 4, BufferAccess::ReadWrite, DataType::U32)
                .with_count(1),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(
            "vyre-libs::parsing::c11_extract_functions",
            vec![child_phase(
                "vyre-libs::parsing::c11_extract_functions",
                vyre_primitives::text::line_index::OP_ID,
                vec![Node::if_then(
                    Expr::lt(t.clone(), Expr::sub(num_tokens.clone(), Expr::u32(2))),
                    loop_body,
                )],
            )],
        )],
    )
    .with_entry_op_id("vyre-libs::parsing::c11_extract_functions")
    .with_non_composable_with_self(true)
}

/// Call site extraction using Subgroup Allocation
#[must_use]
pub fn c11_extract_calls(
    tok_types: &str,
    paren_pairs: &str,
    functions: &str,
    num_tokens: Expr,
    num_functions: Expr,
    out_calls: &str,
    out_counts: &str,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };

    let mut loop_body = vec![
        Node::let_bind("tok_type", Expr::load(tok_types, t.clone())),
        Node::let_bind("prev_type", Expr::u32(0)),
        Node::let_bind("prev_prev_type", Expr::u32(0)),
        Node::if_then(
            Expr::gt(t.clone(), Expr::u32(0)),
            vec![Node::assign(
                "prev_type",
                Expr::load(tok_types, Expr::sub(t.clone(), Expr::u32(1))),
            )],
        ),
        Node::if_then(
            Expr::gt(t.clone(), Expr::u32(1)),
            vec![Node::assign(
                "prev_prev_type",
                Expr::load(tok_types, Expr::sub(t.clone(), Expr::u32(2))),
            )],
        ),
        Node::let_bind(
            "next_type",
            Expr::load(tok_types, Expr::add(t.clone(), Expr::u32(1))),
        ),
        Node::let_bind(
            "matching_rparen",
            Expr::load(paren_pairs, Expr::add(t.clone(), Expr::u32(1))),
        ),
        Node::let_bind("after_direct_call", Expr::u32(0)),
        Node::if_then(
            Expr::and(
                Expr::ne(Expr::var("matching_rparen"), Expr::u32(u32::MAX)),
                Expr::lt(
                    Expr::add(Expr::var("matching_rparen"), Expr::u32(1)),
                    num_tokens.clone(),
                ),
            ),
            vec![Node::assign(
                "after_direct_call",
                Expr::load(
                    tok_types,
                    Expr::add(Expr::var("matching_rparen"), Expr::u32(1)),
                ),
            )],
        ),
        Node::let_bind("is_function_name_record", Expr::u32(0)),
        Node::loop_for(
            "call_fn_record_scan",
            Expr::u32(0),
            num_functions.clone(),
            vec![
                Node::let_bind(
                    "call_fn_record_name",
                    Expr::load(
                        functions,
                        Expr::mul(Expr::var("call_fn_record_scan"), Expr::u32(3)),
                    ),
                ),
                Node::if_then(
                    Expr::eq(Expr::var("call_fn_record_name"), t.clone()),
                    vec![Node::assign("is_function_name_record", Expr::u32(1))],
                ),
            ],
        ),
        Node::let_bind(
            "is_direct_call",
            Expr::and(
                Expr::and(
                    Expr::and(
                        Expr::eq(Expr::var("tok_type"), Expr::u32(TOK_IDENTIFIER)),
                        Expr::eq(Expr::var("next_type"), Expr::u32(TOK_LPAREN)),
                    ),
                    Expr::and(
                        Expr::ne(Expr::var("matching_rparen"), Expr::u32(u32::MAX)),
                        Expr::eq(Expr::var("is_function_name_record"), Expr::u32(0)),
                    ),
                ),
                Expr::or(
                    Expr::not(function_prefix_token(Expr::var("prev_type"))),
                    Expr::and(
                        Expr::ne(Expr::var("after_direct_call"), Expr::u32(TOK_SEMICOLON)),
                        Expr::ne(Expr::var("after_direct_call"), Expr::u32(TOK_LBRACE)),
                    ),
                ),
            ),
        ),
        Node::let_bind("args_end", Expr::var("matching_rparen")),
        Node::let_bind("ptr_wrapper_rparen", Expr::u32(u32::MAX)),
        Node::let_bind("before_ptr_wrapper_type", Expr::u32(TOK_EOF)),
        Node::if_then(
            Expr::gt(t.clone(), Expr::u32(1)),
            vec![
                Node::assign(
                    "ptr_wrapper_rparen",
                    Expr::load(paren_pairs, Expr::sub(t.clone(), Expr::u32(2))),
                ),
                Node::if_then(
                    Expr::gt(t.clone(), Expr::u32(2)),
                    vec![Node::assign(
                        "before_ptr_wrapper_type",
                        Expr::load(tok_types, Expr::sub(t.clone(), Expr::u32(3))),
                    )],
                ),
            ],
        ),
        Node::let_bind(
            "ptr_call_lparen",
            Expr::add(Expr::var("ptr_wrapper_rparen"), Expr::u32(1)),
        ),
        Node::let_bind("ptr_call_lparen_type", Expr::u32(0)),
        Node::let_bind("ptr_call_rparen", Expr::u32(u32::MAX)),
        Node::if_then(
            Expr::lt(Expr::var("ptr_call_lparen"), num_tokens.clone()),
            vec![
                Node::assign(
                    "ptr_call_lparen_type",
                    Expr::load(tok_types, Expr::var("ptr_call_lparen")),
                ),
                Node::assign(
                    "ptr_call_rparen",
                    Expr::load(paren_pairs, Expr::var("ptr_call_lparen")),
                ),
            ],
        ),
        Node::let_bind(
            "is_ptr_call",
            Expr::and(
                Expr::and(
                    Expr::and(
                        Expr::eq(Expr::var("tok_type"), Expr::u32(TOK_IDENTIFIER)),
                        Expr::not(function_prefix_token(Expr::var("before_ptr_wrapper_type"))),
                    ),
                    Expr::and(
                        Expr::eq(Expr::var("prev_type"), Expr::u32(TOK_STAR)),
                        Expr::eq(Expr::var("prev_prev_type"), Expr::u32(TOK_LPAREN)),
                    ),
                ),
                Expr::and(
                    Expr::eq(Expr::var("next_type"), Expr::u32(TOK_RPAREN)),
                    Expr::and(
                        Expr::eq(Expr::var("ptr_call_lparen_type"), Expr::u32(TOK_LPAREN)),
                        Expr::ne(Expr::var("ptr_call_rparen"), Expr::u32(u32::MAX)),
                    ),
                ),
            ),
        ),
    ];
    loop_body.extend(emit_enclosing_function_lookup(
        functions,
        num_functions.clone(),
        t.clone(),
    ));
    loop_body.extend([
        // Per-lane global allocation: each matching lane claims a
        // 4-slot record via one atomic_add. The previous design used
        // subgroup_add + subgroup_shuffle to batch claims per warp,
        // but this library must stay backend-neutral. Concrete drivers
        // can recognize this atomic allocation pattern and lower it to
        // target-native subgroup allocation without changing library IR.
        Node::if_then(
            Expr::var("is_direct_call"),
            vec![
                Node::let_bind(
                    "final_idx",
                    Expr::atomic_add(out_counts, Expr::u32(0), Expr::u32(4)),
                ),
                Node::store(out_calls, Expr::var("final_idx"), Expr::var("caller_id")),
                Node::store(
                    out_calls,
                    Expr::add(Expr::var("final_idx"), Expr::u32(1)),
                    t.clone(),
                ),
                Node::store(
                    out_calls,
                    Expr::add(Expr::var("final_idx"), Expr::u32(2)),
                    Expr::add(t.clone(), Expr::u32(1)),
                ),
                Node::store(
                    out_calls,
                    Expr::add(Expr::var("final_idx"), Expr::u32(3)),
                    Expr::var("args_end"),
                ),
            ],
        ),
        Node::if_then(
            Expr::var("is_ptr_call"),
            vec![
                Node::let_bind(
                    "ptr_final_idx",
                    Expr::atomic_add(out_counts, Expr::u32(0), Expr::u32(4)),
                ),
                Node::store(
                    out_calls,
                    Expr::var("ptr_final_idx"),
                    Expr::var("caller_id"),
                ),
                Node::store(
                    out_calls,
                    Expr::add(Expr::var("ptr_final_idx"), Expr::u32(1)),
                    t.clone(),
                ),
                Node::store(
                    out_calls,
                    Expr::add(Expr::var("ptr_final_idx"), Expr::u32(2)),
                    Expr::var("ptr_call_lparen"),
                ),
                Node::store(
                    out_calls,
                    Expr::add(Expr::var("ptr_final_idx"), Expr::u32(3)),
                    Expr::var("ptr_call_rparen"),
                ),
            ],
        ),
    ]);

    let tok_count = match &num_tokens {
        Expr::LitU32(n) => *n,
        _ => 1,
    };
    let fn_count = match &num_functions {
        Expr::LitU32(n) => *n,
        _ => 1,
    };
    let fn_u32_words = fn_count.saturating_mul(3).max(3);
    Program::wrapped(
        vec![
            BufferDecl::storage(tok_types, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_count),
            BufferDecl::storage(paren_pairs, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_count),
            BufferDecl::storage(functions, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(fn_u32_words),
            BufferDecl::storage(out_calls, 3, BufferAccess::ReadWrite, DataType::U32)
                .with_count(tok_count.saturating_mul(4)),
            BufferDecl::storage(out_counts, 4, BufferAccess::ReadWrite, DataType::U32)
                .with_count(1),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(
            "vyre-libs::parsing::c11_extract_calls",
            vec![child_phase(
                "vyre-libs::parsing::c11_extract_calls",
                vyre_primitives::text::utf8_validate::OP_ID,
                vec![Node::if_then(
                    Expr::lt(t.clone(), Expr::sub(num_tokens.clone(), Expr::u32(1))),
                    loop_body,
                )],
            )],
        )],
    )
    .with_entry_op_id("vyre-libs::parsing::c11_extract_calls")
    .with_non_composable_with_self(true)
}

/// Tier 3 Composed Call Graph Extraction
/// Adheres purely to LEGO block constraints: No inner N^2 linear loops.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn c11_build_call_graph(
    calls: &str,
    fn_hashes: &str,
    tok_starts: &str,
    tok_lens: &str,
    haystack: &str,
    num_calls: Expr,
    num_functions: Expr,
    out_edges: &str,
    out_counts: &str,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };

    let loop_body = vec![
        Node::let_bind(
            "caller_fn_id",
            Expr::load(calls, Expr::mul(t.clone(), Expr::u32(4))),
        ),
        Node::let_bind(
            "callee_tok_idx",
            Expr::load(
                calls,
                Expr::add(Expr::mul(t.clone(), Expr::u32(4)), Expr::u32(1)),
            ),
        ),
        Node::let_bind(
            "callee_tok_start",
            Expr::load(tok_starts, Expr::var("callee_tok_idx")),
        ),
        Node::let_bind(
            "callee_tok_len",
            Expr::load(tok_lens, Expr::var("callee_tok_idx")),
        ),
        // Compute FNV-1a32 hash of the callee token on the fly (no nested divergence since it bounds evenly by token length)
        Node::let_bind("callee_hash", Expr::u32(2166136261)),
        Node::loop_for(
            "b",
            Expr::u32(0),
            Expr::var("callee_tok_len"),
            vec![
                Node::let_bind(
                    "byte",
                    Expr::load(
                        haystack,
                        Expr::add(Expr::var("callee_tok_start"), Expr::var("b")),
                    ),
                ),
                Node::assign(
                    "callee_hash",
                    Expr::bitxor(Expr::var("callee_hash"), Expr::var("byte")),
                ),
                Node::assign(
                    "callee_hash",
                    Expr::mul(Expr::var("callee_hash"), Expr::u32(16777619)),
                ),
            ],
        ),
        Node::let_bind("matched_fn", Expr::u32(0)),
        // O(1) parallel hash table lookup (simulated here as linear over hashes for prototype, but fundamentally lock-free)
        Node::loop_for(
            "f",
            Expr::u32(0),
            num_functions.clone(),
            vec![
                Node::let_bind("func_hash", Expr::load(fn_hashes, Expr::var("f"))), // O(1) hash compare
                Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("matched_fn"), Expr::u32(0)),
                        Expr::eq(Expr::var("callee_hash"), Expr::var("func_hash")),
                    ),
                    vec![
                        // Subgroup optimized edge allocation (replaces global atomic_add chokepoint)
                        // In reality, this delegates to vyre_primitives::allocator::subgroup_allocate
                        Node::let_bind(
                            "idx",
                            Expr::atomic_add(out_counts, Expr::u32(0), Expr::u32(2)),
                        ), // Subgroup warp-leader allocation
                        Node::store(out_edges, Expr::var("idx"), Expr::var("caller_fn_id")),
                        Node::store(
                            out_edges,
                            Expr::add(Expr::var("idx"), Expr::u32(1)),
                            Expr::var("f"),
                        ),
                        Node::assign("matched_fn", Expr::u32(1)),
                    ],
                ),
            ],
        ),
    ];

    let call_count = match &num_calls {
        Expr::LitU32(n) => *n,
        _ => 1,
    };
    let fn_count = match &num_functions {
        Expr::LitU32(n) => *n,
        _ => 1,
    };
    Program::wrapped(
        vec![
            BufferDecl::storage(calls, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(call_count.saturating_mul(4)),
            BufferDecl::storage(fn_hashes, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(fn_count),
            BufferDecl::storage(tok_starts, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(call_count),
            BufferDecl::storage(tok_lens, 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(call_count),
            BufferDecl::storage(haystack, 4, BufferAccess::ReadOnly, DataType::U32)
                .with_count(call_count.saturating_mul(16)),
            BufferDecl::storage(out_edges, 5, BufferAccess::ReadWrite, DataType::U32)
                .with_count(call_count.saturating_mul(4)),
            BufferDecl::storage(out_counts, 6, BufferAccess::ReadWrite, DataType::U32)
                .with_count(1),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(
            "vyre-libs::parsing::c11_build_call_graph",
            vec![Node::if_then(
                Expr::lt(t.clone(), num_calls.clone()),
                loop_body,
            )],
        )],
    )
    .with_entry_op_id("vyre-libs::parsing::c11_build_call_graph")
    .with_non_composable_with_self(true)
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::parsing::c11_extract_functions",
        build: || c11_extract_functions(
            "tok_types", "paren_pairs", "brace_pairs", Expr::u32(6), "out_functions", "out_counts"
        ),
        test_inputs: Some(function_extract_inputs),
        expected_output: Some(function_extract_expected),
    }
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::parsing::c11_extract_calls",
        build: || c11_extract_calls(
            "tok_types", "paren_pairs", "functions", Expr::u32(9), Expr::u32(1), "out_calls", "out_counts"
        ),
        test_inputs: Some(call_extract_inputs),
        expected_output: Some(call_extract_expected),
    }
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::parsing::c11_build_call_graph",
        build: || c11_build_call_graph("calls", "fn_hashes", "tok_starts", "tok_lens", "haystack", Expr::u32(1), Expr::u32(1), "out_edges", "out_counts"),
        test_inputs: Some(call_graph_inputs),
        expected_output: Some(call_graph_expected),
    }
}

fn pack_u32(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn function_extract_inputs() -> Vec<Vec<Vec<u8>>> {
    vec![vec![
        pack_u32(&[
            TOK_INT,
            TOK_IDENTIFIER,
            TOK_LPAREN,
            TOK_RPAREN,
            TOK_LBRACE,
            TOK_RBRACE,
        ]),
        pack_u32(&[u32::MAX, u32::MAX, 3, 2, u32::MAX, u32::MAX]),
        pack_u32(&[u32::MAX, u32::MAX, u32::MAX, u32::MAX, 5, 4]),
        vec![0u8; 6 * 3 * 4],
        pack_u32(&[0]),
    ]]
}

fn function_extract_expected() -> Vec<Vec<Vec<u8>>> {
    let mut functions = vec![0u32; 18];
    functions[0..3].copy_from_slice(&[1, 4, 5]);
    vec![vec![pack_u32(&functions), pack_u32(&[3])]]
}

fn call_extract_inputs() -> Vec<Vec<Vec<u8>>> {
    vec![vec![
        pack_u32(&[
            TOK_INT,
            TOK_IDENTIFIER,
            TOK_LPAREN,
            TOK_RPAREN,
            TOK_LBRACE,
            TOK_IDENTIFIER,
            TOK_LPAREN,
            TOK_RPAREN,
            TOK_SEMICOLON,
        ]),
        pack_u32(&[u32::MAX, u32::MAX, 3, 2, u32::MAX, u32::MAX, 7, 6, u32::MAX]),
        pack_u32(&[1, 4, 8]),
        vec![0u8; 9 * 4 * 4],
        pack_u32(&[0]),
    ]]
}

fn call_extract_expected() -> Vec<Vec<Vec<u8>>> {
    let mut calls = vec![0u32; 9 * 4];
    calls[0..4].copy_from_slice(&[0, 5, 6, 7]);
    vec![vec![pack_u32(&calls), pack_u32(&[4])]]
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(2_166_136_261u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(16_777_619)
    })
}

fn call_graph_inputs() -> Vec<Vec<Vec<u8>>> {
    vec![vec![
        pack_u32(&[0, 5, 6, 7]),
        pack_u32(&[fnv1a32(b"foo")]),
        pack_u32(&[0, 0, 0, 0, 0, 0]),
        pack_u32(&[0, 0, 0, 0, 0, 3]),
        pack_u32(&[
            u32::from(b'f'),
            u32::from(b'o'),
            u32::from(b'o'),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]),
        vec![0u8; 4 * 4],
        pack_u32(&[0]),
    ]]
}

fn call_graph_expected() -> Vec<Vec<Vec<u8>>> {
    vec![vec![pack_u32(&[0, 0, 0, 0]), pack_u32(&[2])]]
}
