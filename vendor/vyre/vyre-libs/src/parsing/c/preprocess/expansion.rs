use crate::parsing::c::lex::tokens::{
    TOK_COMMA, TOK_HASH, TOK_HASHHASH, TOK_IDENTIFIER, TOK_LPAREN, TOK_PP_ELIF, TOK_PP_ELSE,
    TOK_PP_ENDIF, TOK_PP_IF, TOK_PP_IFDEF, TOK_PP_IFNDEF, TOK_PREPROC, TOK_RPAREN,
};
use crate::parsing::c::preprocess::materialization::{
    append_to_previous_output_token, emit_materialized_output_token,
    emit_stringified_argument_token, C_MACRO_SOURCE_COUNT_BYTES,
};
use crate::parsing::c::preprocess::synthesis::{stringification_token_type, C_TOKEN_PASTE_RULES};
use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

const EMPTY_MACRO_SLOT: u32 = u32::MAX;
const MACRO_TABLE_SLOTS: u32 = 1024;
const MACRO_TABLE_MASK: u32 = MACRO_TABLE_SLOTS - 1;
const FNV1A32_OFFSET: u32 = 0x811c_9dc5;
const FNV1A32_PRIME: u32 = 0x0100_0193;
const MACRO_NAME_BYTES: u32 = 4096;

/// Object-like C macro table kind for `opt_named_macro_expansion`.
pub const C_MACRO_KIND_OBJECT_LIKE: u32 = 0;
/// Function-like C macro table kind for `opt_named_macro_expansion`.
pub const C_MACRO_KIND_FUNCTION_LIKE: u32 = 1;
/// Replacement parameter marker meaning this replacement token is literal.
pub const C_MACRO_REPLACEMENT_LITERAL: u32 = u32::MAX;

fn emit_macro_lookup(
    prefix: &str,
    token: Expr,
    macro_keys: &str,
    macro_vals: &str,
    output_var: &str,
) -> Vec<Node> {
    let token_name = format!("{prefix}_tok");
    let probe_slot = format!("{prefix}_probe_slot");
    let probed_key = format!("{prefix}_probed_key");
    let probe = format!("{prefix}_probe");
    let lookup_done = format!("{prefix}_lookup_done");
    let lookup_seen_empty = format!("{prefix}_lookup_seen_empty");
    vec![
        Node::let_bind(&token_name, token),
        Node::let_bind(
            &probe_slot,
            Expr::bitand(
                Expr::mul(Expr::var(&token_name), Expr::u32(2_654_435_769)),
                Expr::u32(MACRO_TABLE_MASK),
            ),
        ),
        Node::let_bind(output_var, Expr::u32(EMPTY_MACRO_SLOT)),
        Node::let_bind(&lookup_done, Expr::u32(0)),
        Node::let_bind(&lookup_seen_empty, Expr::u32(0)),
        Node::loop_for(
            probe,
            Expr::u32(0),
            Expr::u32(MACRO_TABLE_SLOTS),
            vec![Node::if_then(
                Expr::eq(Expr::var(&lookup_done), Expr::u32(0)),
                vec![
                    Node::let_bind(&probed_key, Expr::load(macro_keys, Expr::var(&probe_slot))),
                    Node::if_then(
                        Expr::eq(Expr::var(&probed_key), Expr::var(&token_name)),
                        vec![
                            Node::assign(
                                output_var,
                                Expr::load(macro_vals, Expr::var(&probe_slot)),
                            ),
                            Node::assign(&lookup_done, Expr::u32(1)),
                        ],
                    ),
                    Node::if_then(
                        Expr::eq(Expr::var(&probed_key), Expr::u32(EMPTY_MACRO_SLOT)),
                        vec![
                            Node::assign(&lookup_seen_empty, Expr::u32(1)),
                            Node::assign(&lookup_done, Expr::u32(1)),
                        ],
                    ),
                    Node::assign(
                        &probe_slot,
                        Expr::bitand(
                            Expr::add(Expr::var(&probe_slot), Expr::u32(1)),
                            Expr::u32(MACRO_TABLE_MASK),
                        ),
                    ),
                ],
            )],
        ),
        Node::if_then(
            Expr::and(
                Expr::eq(Expr::var(output_var), Expr::u32(EMPTY_MACRO_SLOT)),
                Expr::eq(Expr::var(&lookup_seen_empty), Expr::u32(0)),
            ),
            vec![Node::trap(
                Expr::var(&token_name),
                "macro-lookup-table-full-without-empty-slot",
            )],
        ),
    ]
}

fn emit_macro_hash_lookup(
    prefix: &str,
    name_hash: Expr,
    source_start: Expr,
    source_len: Expr,
    source_words: &str,
    macro_name_hashes: &str,
    macro_name_starts: &str,
    macro_name_lens: &str,
    macro_name_words: &str,
    output_var: &str,
) -> Vec<Node> {
    let hash_name = format!("{prefix}_name_hash");
    let probe_slot = format!("{prefix}_probe_slot");
    let probed_key = format!("{prefix}_probed_key");
    let probe = format!("{prefix}_probe");
    let lookup_done = format!("{prefix}_lookup_done");
    let lookup_seen_empty = format!("{prefix}_lookup_seen_empty");
    let candidate_name_start = format!("{prefix}_candidate_name_start");
    let candidate_name_len = format!("{prefix}_candidate_name_len");
    let candidate_name_end = format!("{prefix}_candidate_name_end");
    let candidate_name_matches = format!("{prefix}_candidate_name_matches");
    let candidate_byte_i = format!("{prefix}_candidate_byte_i");
    let source_byte = format!("{prefix}_source_byte");
    let macro_name_byte = format!("{prefix}_macro_name_byte");
    vec![
        Node::let_bind(&hash_name, name_hash),
        Node::let_bind(
            &probe_slot,
            Expr::bitand(
                Expr::mul(Expr::var(&hash_name), Expr::u32(2_654_435_769)),
                Expr::u32(MACRO_TABLE_MASK),
            ),
        ),
        Node::assign(output_var, Expr::u32(EMPTY_MACRO_SLOT)),
        Node::let_bind(&lookup_done, Expr::u32(0)),
        Node::let_bind(&lookup_seen_empty, Expr::u32(0)),
        Node::loop_for(
            probe,
            Expr::u32(0),
            Expr::u32(MACRO_TABLE_SLOTS),
            vec![Node::if_then(
                Expr::eq(Expr::var(&lookup_done), Expr::u32(0)),
                vec![
                    Node::let_bind(
                        &probed_key,
                        Expr::load(macro_name_hashes, Expr::var(&probe_slot)),
                    ),
                    Node::if_then(
                        Expr::eq(Expr::var(&probed_key), Expr::var(&hash_name)),
                        vec![
                            Node::let_bind(
                                &candidate_name_start,
                                Expr::load(macro_name_starts, Expr::var(&probe_slot)),
                            ),
                            Node::let_bind(
                                &candidate_name_len,
                                Expr::load(macro_name_lens, Expr::var(&probe_slot)),
                            ),
                            Node::let_bind(
                                &candidate_name_end,
                                Expr::add(
                                    Expr::var(&candidate_name_start),
                                    Expr::var(&candidate_name_len),
                                ),
                            ),
                            Node::if_then(
                                Expr::or(
                                    Expr::lt(
                                        Expr::var(&candidate_name_end),
                                        Expr::var(&candidate_name_start),
                                    ),
                                    Expr::gt(
                                        Expr::var(&candidate_name_end),
                                        Expr::u32(MACRO_NAME_BYTES),
                                    ),
                                ),
                                vec![Node::trap(
                                    Expr::var(&candidate_name_end),
                                    "macro-name-candidate-span-out-of-bounds",
                                )],
                            ),
                            Node::let_bind(
                                &candidate_name_matches,
                                Expr::select(
                                    Expr::eq(source_len.clone(), Expr::var(&candidate_name_len)),
                                    Expr::u32(1),
                                    Expr::u32(0),
                                ),
                            ),
                            Node::loop_for(
                                candidate_byte_i.clone(),
                                Expr::u32(0),
                                Expr::var(&candidate_name_len),
                                vec![Node::if_then(
                                    Expr::eq(Expr::var(&candidate_name_matches), Expr::u32(1)),
                                    vec![
                                        Node::let_bind(
                                            &source_byte,
                                            Expr::load(
                                                source_words,
                                                Expr::add(
                                                    source_start.clone(),
                                                    Expr::var(&candidate_byte_i),
                                                ),
                                            ),
                                        ),
                                        Node::let_bind(
                                            &macro_name_byte,
                                            Expr::load(
                                                macro_name_words,
                                                Expr::add(
                                                    Expr::var(&candidate_name_start),
                                                    Expr::var(&candidate_byte_i),
                                                ),
                                            ),
                                        ),
                                        Node::if_then(
                                            Expr::ne(
                                                Expr::var(&source_byte),
                                                Expr::var(&macro_name_byte),
                                            ),
                                            vec![Node::assign(
                                                &candidate_name_matches,
                                                Expr::u32(0),
                                            )],
                                        ),
                                    ],
                                )],
                            ),
                            Node::if_then(
                                Expr::eq(Expr::var(&candidate_name_matches), Expr::u32(1)),
                                vec![
                                    Node::assign(output_var, Expr::var(&probe_slot)),
                                    Node::assign(&lookup_done, Expr::u32(1)),
                                ],
                            ),
                        ],
                    ),
                    Node::if_then(
                        Expr::eq(Expr::var(&probed_key), Expr::u32(EMPTY_MACRO_SLOT)),
                        vec![
                            Node::assign(&lookup_seen_empty, Expr::u32(1)),
                            Node::assign(&lookup_done, Expr::u32(1)),
                        ],
                    ),
                    Node::assign(
                        &probe_slot,
                        Expr::bitand(
                            Expr::add(Expr::var(&probe_slot), Expr::u32(1)),
                            Expr::u32(MACRO_TABLE_MASK),
                        ),
                    ),
                ],
            )],
        ),
        Node::if_then(
            Expr::and(
                Expr::eq(Expr::var(output_var), Expr::u32(EMPTY_MACRO_SLOT)),
                Expr::eq(Expr::var(&lookup_seen_empty), Expr::u32(0)),
            ),
            vec![Node::trap(
                Expr::var(&hash_name),
                "macro-name-lookup-table-full-without-empty-slot",
            )],
        ),
    ]
}

fn emit_source_span_hash(
    prefix: &str,
    token_index: Expr,
    in_tok_starts: &str,
    in_tok_lens: &str,
    source_words: &str,
    source_len: Expr,
    output_var: &str,
) -> Vec<Node> {
    let start = format!("{prefix}_start");
    let len = format!("{prefix}_len");
    let end = format!("{prefix}_end");
    let byte_idx = format!("{prefix}_byte_idx");
    let byte = format!("{prefix}_byte");
    vec![
        Node::let_bind(&start, Expr::load(in_tok_starts, token_index.clone())),
        Node::let_bind(&len, Expr::load(in_tok_lens, token_index)),
        Node::let_bind(&end, Expr::add(Expr::var(&start), Expr::var(&len))),
        Node::if_then(
            Expr::or(
                Expr::lt(Expr::var(&end), Expr::var(&start)),
                Expr::gt(Expr::var(&end), source_len),
            ),
            vec![Node::trap(
                Expr::var(&end),
                "macro-name-source-span-out-of-bounds",
            )],
        ),
        Node::let_bind(output_var, Expr::u32(FNV1A32_OFFSET)),
        Node::loop_for(
            byte_idx.clone(),
            Expr::u32(0),
            Expr::var(&len),
            vec![
                Node::let_bind(
                    &byte,
                    Expr::bitand(
                        Expr::load(
                            source_words,
                            Expr::add(Expr::var(&start), Expr::var(&byte_idx)),
                        ),
                        Expr::u32(0xff),
                    ),
                ),
                Node::assign(
                    output_var,
                    Expr::bitxor(Expr::var(output_var), Expr::var(&byte)),
                ),
                Node::assign(
                    output_var,
                    Expr::mul(Expr::var(output_var), Expr::u32(FNV1A32_PRIME)),
                ),
            ],
        ),
    ]
}

fn selected_arg_bound(arg_bounds: &str, param: Expr) -> Expr {
    Expr::load(arg_bounds, param)
}

fn assign_arg_bound(
    arg_bounds: &str,
    arg_index: Expr,
    value: Expr,
    num_tokens: Expr,
    overflow_trap: &'static str,
) -> Vec<Node> {
    vec![Node::if_then_else(
        Expr::lt(arg_index.clone(), num_tokens.clone()),
        vec![Node::store(arg_bounds, arg_index.clone(), value)],
        vec![Node::trap(arg_index, overflow_trap)],
    )]
}

fn emit_one_output_token(out_tok_types: &str, token: Expr, max_out_tokens: u32) -> Vec<Node> {
    vec![
        Node::if_then(
            Expr::gt(
                Expr::add(Expr::var("named_out_idx"), Expr::u32(1)),
                Expr::u32(max_out_tokens),
            ),
            vec![Node::trap(
                Expr::add(Expr::var("named_out_idx"), Expr::u32(1)),
                "named-macro-expansion-output-overflow",
            )],
        ),
        Node::store(out_tok_types, Expr::var("named_out_idx"), token),
        Node::assign(
            "named_out_idx",
            Expr::add(Expr::var("named_out_idx"), Expr::u32(1)),
        ),
    ]
}

fn synthesized_paste_token(left: Expr, right: Expr) -> Expr {
    C_TOKEN_PASTE_RULES.iter().rev().fold(
        Expr::u32(EMPTY_MACRO_SLOT),
        |fallback, (left_tok, right_tok, out_tok)| {
            Expr::select(
                Expr::and(
                    Expr::eq(left.clone(), Expr::u32(*left_tok)),
                    Expr::eq(right.clone(), Expr::u32(*right_tok)),
                ),
                Expr::u32(*out_tok),
                fallback,
            )
        },
    )
}

fn emit_object_like_replacement(
    macro_vals: &str,
    macro_replacement_params: &str,
    out_tok_types: &str,
    max_out_tokens: u32,
) -> Vec<Node> {
    vec![
        Node::let_bind("named_skip_repl", Expr::u32(0)),
        Node::loop_for(
            "named_repl_i",
            Expr::u32(0),
            Expr::var("named_repl_size"),
            {
                vec![Node::if_then_else(
                    Expr::eq(Expr::var("named_skip_repl"), Expr::u32(1)),
                    vec![Node::assign("named_skip_repl", Expr::u32(0))],
                    {
                        let mut body = vec![
                            Node::let_bind(
                                "named_repl_offset",
                                Expr::add(Expr::var("named_macro_idx"), Expr::var("named_repl_i")),
                            ),
                            Node::let_bind(
                                "named_repl_param",
                                Expr::load(
                                    macro_replacement_params,
                                    Expr::var("named_repl_offset"),
                                ),
                            ),
                            Node::if_then(
                                Expr::ne(
                                    Expr::var("named_repl_param"),
                                    Expr::u32(C_MACRO_REPLACEMENT_LITERAL),
                                ),
                                vec![Node::trap(
                                    Expr::var("named_repl_param"),
                                    "object-like-macro-replacement-cannot-reference-parameters",
                                )],
                            ),
                            Node::let_bind(
                                "named_repl_tok",
                                Expr::load(macro_vals, Expr::var("named_repl_offset")),
                            ),
                        ];
                        body.push(Node::if_then_else(
                            Expr::eq(Expr::var("named_repl_tok"), Expr::u32(TOK_HASHHASH)),
                            vec![
                                Node::if_then(
                                    Expr::eq(Expr::var("named_out_idx"), Expr::u32(0)),
                                    vec![Node::trap(
                                        Expr::var("named_repl_i"),
                                        "object-like-token-paste-missing-left-token",
                                    )],
                                ),
                                Node::if_then(
                                    Expr::ge(
                                        Expr::add(Expr::var("named_repl_i"), Expr::u32(1)),
                                        Expr::var("named_repl_size"),
                                    ),
                                    vec![Node::trap(
                                        Expr::var("named_repl_i"),
                                        "object-like-token-paste-missing-right-token",
                                    )],
                                ),
                                Node::let_bind(
                                    "macro_paste_next_offset",
                                    Expr::add(
                                        Expr::var("named_macro_idx"),
                                        Expr::add(Expr::var("named_repl_i"), Expr::u32(1)),
                                    ),
                                ),
                                Node::let_bind(
                                    "macro_paste_next_param",
                                    Expr::load(
                                        macro_replacement_params,
                                        Expr::var("macro_paste_next_offset"),
                                    ),
                                ),
                                Node::if_then(
                                    Expr::ne(
                                        Expr::var("macro_paste_next_param"),
                                        Expr::u32(C_MACRO_REPLACEMENT_LITERAL),
                                    ),
                                    vec![Node::trap(
                                        Expr::var("macro_paste_next_param"),
                                        "object-like-token-paste-cannot-reference-parameters",
                                    )],
                                ),
                                Node::let_bind(
                                    "macro_paste_left_tok",
                                    Expr::load(
                                        out_tok_types,
                                        Expr::sub(Expr::var("named_out_idx"), Expr::u32(1)),
                                    ),
                                ),
                                Node::let_bind(
                                    "macro_paste_right_tok",
                                    Expr::load(macro_vals, Expr::var("macro_paste_next_offset")),
                                ),
                                Node::let_bind(
                                    "macro_paste_synth_tok",
                                    synthesized_paste_token(
                                        Expr::var("macro_paste_left_tok"),
                                        Expr::var("macro_paste_right_tok"),
                                    ),
                                ),
                                Node::if_then(
                                    Expr::eq(
                                        Expr::var("macro_paste_synth_tok"),
                                        Expr::u32(EMPTY_MACRO_SLOT),
                                    ),
                                    vec![Node::trap(
                                        Expr::var("macro_paste_right_tok"),
                                        "object-like-token-paste-cannot-synthesize-token-type",
                                    )],
                                ),
                                Node::store(
                                    out_tok_types,
                                    Expr::sub(Expr::var("named_out_idx"), Expr::u32(1)),
                                    Expr::var("macro_paste_synth_tok"),
                                ),
                                Node::assign("named_skip_repl", Expr::u32(1)),
                            ],
                            emit_one_output_token(
                                out_tok_types,
                                Expr::var("named_repl_tok"),
                                max_out_tokens,
                            ),
                        ));
                        body
                    },
                )]
            },
        ),
        Node::assign("named_i", Expr::add(Expr::var("named_i"), Expr::u32(1))),
    ]
}

fn emit_function_like_replacement(
    in_tok_types: &str,
    macro_vals: &str,
    macro_replacement_params: &str,
    out_tok_types: &str,
    macro_arg_starts: &str,
    macro_arg_ends: &str,
    num_tokens: Expr,
    max_out_tokens: u32,
) -> Vec<Node> {
    let mut nodes = vec![
        Node::if_then(
            Expr::gt(Expr::var("named_param_count"), num_tokens.clone()),
            vec![Node::trap(
                Expr::var("named_param_count"),
                "function-like-macro-parameter-count-exceeds-token-capacity",
            )],
        ),
        Node::let_bind(
            "macro_scan_base",
            Expr::add(Expr::var("named_i"), Expr::u32(2)),
        ),
        Node::let_bind("macro_depth", Expr::u32(0)),
        Node::let_bind("macro_arg_index", Expr::u32(0)),
        Node::let_bind("macro_current_arg_start", Expr::var("macro_scan_base")),
        Node::let_bind("macro_found_close", Expr::u32(0)),
        Node::let_bind("macro_close_idx", num_tokens.clone()),
        Node::store(macro_arg_starts, Expr::u32(0), Expr::var("macro_scan_base")),
        Node::store(macro_arg_ends, Expr::u32(0), Expr::var("macro_scan_base")),
    ];

    let scan_body = vec![
        Node::let_bind(
            "macro_scan_idx",
            Expr::add(Expr::var("macro_scan_base"), Expr::var("macro_scan_rel")),
        ),
        Node::if_then(
            Expr::and(
                Expr::eq(Expr::var("macro_found_close"), Expr::u32(0)),
                Expr::ge(Expr::var("macro_scan_idx"), num_tokens.clone()),
            ),
            vec![Node::trap(
                Expr::var("macro_scan_idx"),
                "function-like-macro-invocation-missing-rparen",
            )],
        ),
        Node::if_then(
            Expr::and(
                Expr::eq(Expr::var("macro_found_close"), Expr::u32(0)),
                Expr::lt(Expr::var("macro_scan_idx"), num_tokens.clone()),
            ),
            {
                let active = vec![
                    Node::let_bind(
                        "macro_scan_tok",
                        Expr::load(in_tok_types, Expr::var("macro_scan_idx")),
                    ),
                    Node::if_then(
                        Expr::eq(Expr::var("macro_scan_tok"), Expr::u32(TOK_LPAREN)),
                        vec![Node::assign(
                            "macro_depth",
                            Expr::add(Expr::var("macro_depth"), Expr::u32(1)),
                        )],
                    ),
                    Node::if_then(
                        Expr::and(
                            Expr::eq(Expr::var("macro_scan_tok"), Expr::u32(TOK_COMMA)),
                            Expr::eq(Expr::var("macro_depth"), Expr::u32(0)),
                        ),
                        {
                            let mut comma = assign_arg_bound(
                                macro_arg_ends,
                                Expr::var("macro_arg_index"),
                                Expr::var("macro_scan_idx"),
                                num_tokens.clone(),
                                "function-like-macro-argument-count-overflow",
                            );
                            comma.extend([
                                Node::assign(
                                    "macro_arg_index",
                                    Expr::add(Expr::var("macro_arg_index"), Expr::u32(1)),
                                ),
                                Node::if_then(
                                    Expr::ge(Expr::var("macro_arg_index"), num_tokens.clone()),
                                    vec![Node::trap(
                                        Expr::var("macro_arg_index"),
                                        "function-like-macro-argument-count-overflow",
                                    )],
                                ),
                                Node::assign(
                                    "macro_current_arg_start",
                                    Expr::add(Expr::var("macro_scan_idx"), Expr::u32(1)),
                                ),
                            ]);
                            comma.extend(assign_arg_bound(
                                macro_arg_starts,
                                Expr::var("macro_arg_index"),
                                Expr::var("macro_current_arg_start"),
                                num_tokens.clone(),
                                "function-like-macro-argument-count-overflow",
                            ));
                            comma
                        },
                    ),
                    Node::if_then(
                        Expr::eq(Expr::var("macro_scan_tok"), Expr::u32(TOK_RPAREN)),
                        vec![Node::if_then_else(
                            Expr::eq(Expr::var("macro_depth"), Expr::u32(0)),
                            {
                                let mut close = assign_arg_bound(
                                    macro_arg_ends,
                                    Expr::var("macro_arg_index"),
                                    Expr::var("macro_scan_idx"),
                                    num_tokens.clone(),
                                    "function-like-macro-argument-count-overflow",
                                );
                                close.extend([
                                    Node::assign("macro_found_close", Expr::u32(1)),
                                    Node::assign("macro_close_idx", Expr::var("macro_scan_idx")),
                                ]);
                                close
                            },
                            vec![Node::assign(
                                "macro_depth",
                                Expr::sub(Expr::var("macro_depth"), Expr::u32(1)),
                            )],
                        )],
                    ),
                ];
                active
            },
        ),
    ];

    nodes.push(Node::loop_for(
        "macro_scan_rel",
        Expr::u32(0),
        num_tokens.clone(),
        scan_body,
    ));
    nodes.extend([
        Node::if_then(
            Expr::eq(Expr::var("macro_found_close"), Expr::u32(0)),
            vec![Node::trap(
                Expr::var("named_i"),
                "function-like-macro-invocation-missing-rparen",
            )],
        ),
        Node::let_bind(
            "macro_seen_arg_count",
            Expr::add(Expr::var("macro_arg_index"), Expr::u32(1)),
        ),
        Node::if_then(
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("macro_close_idx"), Expr::var("macro_scan_base")),
                    Expr::eq(Expr::var("named_param_count"), Expr::u32(0)),
                ),
                Expr::eq(Expr::var("macro_arg_index"), Expr::u32(0)),
            ),
            vec![Node::assign("macro_seen_arg_count", Expr::u32(0))],
        ),
        Node::if_then(
            Expr::ne(
                Expr::var("macro_seen_arg_count"),
                Expr::var("named_param_count"),
            ),
            vec![Node::trap(
                Expr::var("macro_seen_arg_count"),
                "function-like-macro-argument-count-mismatch",
            )],
        ),
        Node::let_bind("named_skip_repl", Expr::u32(0)),
        Node::loop_for(
            "named_repl_i",
            Expr::u32(0),
            Expr::var("named_repl_size"),
            {
                vec![Node::if_then_else(
                    Expr::eq(Expr::var("named_skip_repl"), Expr::u32(1)),
                    vec![Node::assign("named_skip_repl", Expr::u32(0))],
                    {
                        let mut repl = vec![
                            Node::let_bind(
                                "named_repl_offset",
                                Expr::add(Expr::var("named_macro_idx"), Expr::var("named_repl_i")),
                            ),
                            Node::let_bind(
                                "named_repl_param",
                                Expr::load(macro_replacement_params, Expr::var("named_repl_offset")),
                            ),
                            Node::let_bind(
                                "named_repl_tok",
                                Expr::load(macro_vals, Expr::var("named_repl_offset")),
                            ),
                        ];
                        repl.push(Node::if_then_else(
                            Expr::and(
                                Expr::eq(Expr::var("named_repl_tok"), Expr::u32(TOK_HASH)),
                                Expr::lt(
                                    Expr::add(Expr::var("named_repl_i"), Expr::u32(1)),
                                    Expr::var("named_repl_size"),
                                ),
                            ),
                            vec![
                                Node::let_bind(
                                    "macro_stringify_next_offset",
                                    Expr::add(
                                        Expr::var("named_macro_idx"),
                                        Expr::add(Expr::var("named_repl_i"), Expr::u32(1)),
                                    ),
                                ),
                                Node::let_bind(
                                    "macro_stringify_next_param",
                                    Expr::load(
                                        macro_replacement_params,
                                        Expr::var("macro_stringify_next_offset"),
                                    ),
                                ),
                                Node::if_then_else(
                                    Expr::eq(
                                        Expr::var("macro_stringify_next_param"),
                                        Expr::u32(C_MACRO_REPLACEMENT_LITERAL),
                                    ),
                                    emit_one_output_token(
                                        out_tok_types,
                                        Expr::var("named_repl_tok"),
                                        max_out_tokens,
                                    ),
                                    {
                                        let mut stringify = vec![Node::if_then(
                                            Expr::ge(
                                                Expr::var("macro_stringify_next_param"),
                                                Expr::var("named_param_count"),
                                            ),
                                            vec![Node::trap(
                                                Expr::var("macro_stringify_next_param"),
                                                "function-like-stringification-parameter-out-of-range",
                                            )],
                                        )];
                                        stringify.extend(emit_one_output_token(
                                            out_tok_types,
                                            Expr::u32(stringification_token_type()),
                                            max_out_tokens,
                                        ));
                                        stringify.push(Node::assign("named_skip_repl", Expr::u32(1)));
                                        stringify
                                    },
                                ),
                            ],
                            vec![Node::if_then_else(
                                Expr::eq(Expr::var("named_repl_tok"), Expr::u32(TOK_HASHHASH)),
                                {
                                    let paste = vec![
                                        Node::if_then(
                                            Expr::eq(Expr::var("named_out_idx"), Expr::u32(0)),
                                            vec![Node::trap(
                                                Expr::var("named_repl_i"),
                                                "function-like-token-paste-missing-left-token",
                                            )],
                                        ),
                                        Node::if_then(
                                            Expr::ge(
                                                Expr::add(Expr::var("named_repl_i"), Expr::u32(1)),
                                                Expr::var("named_repl_size"),
                                            ),
                                            vec![Node::trap(
                                                Expr::var("named_repl_i"),
                                                "function-like-token-paste-missing-right-token",
                                            )],
                                        ),
                                        Node::let_bind(
                                            "macro_paste_next_offset",
                                            Expr::add(
                                                Expr::var("named_macro_idx"),
                                                Expr::add(Expr::var("named_repl_i"), Expr::u32(1)),
                                            ),
                                        ),
                                        Node::let_bind(
                                            "macro_paste_next_param",
                                            Expr::load(
                                                macro_replacement_params,
                                                Expr::var("macro_paste_next_offset"),
                                            ),
                                        ),
                                        Node::let_bind("macro_paste_right_tok", Expr::u32(0)),
                                        Node::let_bind("macro_paste_arg_start", Expr::u32(0)),
                                        Node::let_bind("macro_paste_arg_end", Expr::u32(0)),
                                        Node::if_then_else(
                                            Expr::eq(
                                                Expr::var("macro_paste_next_param"),
                                                Expr::u32(C_MACRO_REPLACEMENT_LITERAL),
                                            ),
                                            vec![Node::assign(
                                                "macro_paste_right_tok",
                                                Expr::load(
                                                    macro_vals,
                                                    Expr::var("macro_paste_next_offset"),
                                                ),
                                            )],
                                            {
                                                let arg_start = selected_arg_bound(
                                                    macro_arg_starts,
                                                    Expr::var("macro_paste_next_param"),
                                                );
                                                let arg_end = selected_arg_bound(
                                                    macro_arg_ends,
                                                    Expr::var("macro_paste_next_param"),
                                                );
                                                vec![
                                                    Node::if_then(
                                                        Expr::ge(
                                                            Expr::var("macro_paste_next_param"),
                                                            Expr::var("named_param_count"),
                                                        ),
                                                        vec![Node::trap(
                                                            Expr::var("macro_paste_next_param"),
                                                            "function-like-token-paste-parameter-out-of-range",
                                                        )],
                                                    ),
                                                    Node::assign("macro_paste_arg_start", arg_start),
                                                    Node::assign("macro_paste_arg_end", arg_end),
                                                    Node::if_then(
                                                        Expr::ge(
                                                            Expr::var("macro_paste_arg_start"),
                                                            Expr::var("macro_paste_arg_end"),
                                                        ),
                                                        vec![Node::trap(
                                                            Expr::var("macro_paste_next_param"),
                                                            "function-like-token-paste-empty-argument",
                                                        )],
                                                    ),
                                                    Node::assign(
                                                        "macro_paste_right_tok",
                                                        Expr::load(
                                                            in_tok_types,
                                                            Expr::var("macro_paste_arg_start"),
                                                        ),
                                                    ),
                                                ]
                                            },
                                        ),
                                        Node::let_bind(
                                            "macro_paste_left_tok",
                                            Expr::load(
                                                out_tok_types,
                                                Expr::sub(
                                                    Expr::var("named_out_idx"),
                                                    Expr::u32(1),
                                                ),
                                            ),
                                        ),
                                        Node::let_bind(
                                            "macro_paste_synth_tok",
                                            synthesized_paste_token(
                                                Expr::var("macro_paste_left_tok"),
                                                Expr::var("macro_paste_right_tok"),
                                            ),
                                        ),
                                        Node::if_then(
                                            Expr::eq(
                                                Expr::var("macro_paste_synth_tok"),
                                                Expr::u32(EMPTY_MACRO_SLOT),
                                            ),
                                            vec![Node::trap(
                                                Expr::var("macro_paste_right_tok"),
                                                "function-like-token-paste-cannot-synthesize-token-type",
                                            )],
                                        ),
                                        Node::store(
                                            out_tok_types,
                                            Expr::sub(Expr::var("named_out_idx"), Expr::u32(1)),
                                            Expr::var("macro_paste_synth_tok"),
                                        ),
                                        Node::if_then(
                                            Expr::ne(
                                                Expr::var("macro_paste_next_param"),
                                                Expr::u32(C_MACRO_REPLACEMENT_LITERAL),
                                            ),
                                            vec![Node::loop_for(
                                                "macro_paste_rhs_rest_rel",
                                                Expr::u32(1),
                                                num_tokens.clone(),
                                                vec![Node::if_then(
                                                    Expr::lt(
                                                        Expr::add(
                                                            Expr::var("macro_paste_arg_start"),
                                                            Expr::var("macro_paste_rhs_rest_rel"),
                                                        ),
                                                        Expr::var("macro_paste_arg_end"),
                                                    ),
                                                    {
                                                        let mut copy = vec![Node::let_bind(
                                                            "macro_paste_rhs_rest_tok",
                                                            Expr::load(
                                                                in_tok_types,
                                                                Expr::add(
                                                                    Expr::var("macro_paste_arg_start"),
                                                                    Expr::var(
                                                                        "macro_paste_rhs_rest_rel",
                                                                    ),
                                                                ),
                                                            ),
                                                        )];
                                                        copy.extend(emit_one_output_token(
                                                            out_tok_types,
                                                            Expr::var("macro_paste_rhs_rest_tok"),
                                                            max_out_tokens,
                                                        ));
                                                        copy
                                                    },
                                                )],
                                            )],
                                        ),
                                        Node::assign("named_skip_repl", Expr::u32(1)),
                                    ];
                                    paste
                                },
                                {
                                    let regular_literal = emit_one_output_token(
                                        out_tok_types,
                                        Expr::var("named_repl_tok"),
                                        max_out_tokens,
                                    );
                                    let arg_start = selected_arg_bound(
                                        macro_arg_starts,
                                        Expr::var("named_repl_param"),
                                    );
                                    let arg_end = selected_arg_bound(
                                        macro_arg_ends,
                                        Expr::var("named_repl_param"),
                                    );
                                    vec![Node::if_then_else(
                                        Expr::eq(
                                            Expr::var("named_repl_param"),
                                            Expr::u32(C_MACRO_REPLACEMENT_LITERAL),
                                        ),
                                        regular_literal,
                                        vec![
                                            Node::if_then(
                                                Expr::ge(
                                                    Expr::var("named_repl_param"),
                                                    Expr::var("named_param_count"),
                                                ),
                                                vec![Node::trap(
                                                    Expr::var("named_repl_param"),
                                                    "function-like-macro-replacement-parameter-out-of-range",
                                                )],
                                            ),
                                            Node::let_bind("macro_sub_arg_start", arg_start),
                                            Node::let_bind("macro_sub_arg_end", arg_end),
                                            Node::loop_for(
                                                "macro_sub_arg_rel",
                                                Expr::u32(0),
                                                num_tokens.clone(),
                                                vec![Node::if_then(
                                                    Expr::lt(
                                                        Expr::add(
                                                            Expr::var("macro_sub_arg_start"),
                                                            Expr::var("macro_sub_arg_rel"),
                                                        ),
                                                        Expr::var("macro_sub_arg_end"),
                                                    ),
                                                    {
                                                        let mut copy = vec![Node::let_bind(
                                                            "macro_sub_arg_tok",
                                                            Expr::load(
                                                                in_tok_types,
                                                                Expr::add(
                                                                    Expr::var("macro_sub_arg_start"),
                                                                    Expr::var("macro_sub_arg_rel"),
                                                                ),
                                                            ),
                                                        )];
                                                        copy.extend(emit_one_output_token(
                                                            out_tok_types,
                                                            Expr::var("macro_sub_arg_tok"),
                                                            max_out_tokens,
                                                        ));
                                                        copy
                                                    },
                                                )],
                                            ),
                                        ],
                                    )]
                                },
                            )],
                        ));
                        repl
                    },
                )]
            },
        ),
        Node::assign(
            "named_i",
            Expr::add(Expr::var("macro_close_idx"), Expr::u32(1)),
        ),
    ]);

    nodes
}

/// LEGO Block 1: Lock-Free Dynamic Macro Expansion Engine (Tier-3)
///
/// General-purpose bounded token substitutor for already-parsed replacement
/// streams. A token ID probes the macro table, validates the replacement range,
/// preserves directive rows, and writes source-ordered output tokens.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn opt_dynamic_macro_expansion(
    in_tok_types: &str,
    macro_keys: &str,
    macro_vals: &str,
    macro_sizes: &str,
    out_tok_types: &str,
    out_tok_counts: &str,
    num_tokens: Expr,
    max_out_tokens: u32,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let mut loop_body = vec![Node::let_bind("tok", Expr::load(in_tok_types, t.clone()))];
    loop_body.extend(emit_macro_lookup(
        "current",
        Expr::var("tok"),
        macro_keys,
        macro_vals,
        "macro_idx",
    ));
    loop_body.extend([
        Node::if_then(
            Expr::eq(Expr::var("tok"), Expr::u32(TOK_PREPROC)),
            vec![Node::assign("macro_idx", Expr::u32(EMPTY_MACRO_SLOT))],
        ),
        // Determine number of tokens to emit
        Node::let_bind("emit_count", Expr::u32(0)),
        Node::if_then_else(
            Expr::eq(Expr::var("macro_idx"), Expr::u32(EMPTY_MACRO_SLOT)),
            vec![Node::assign("emit_count", Expr::u32(1))], // Passthrough original token
            vec![Node::assign(
                "emit_count",
                Expr::load(macro_sizes, Expr::var("macro_idx")),
            )], // Fetch replacement sequence length
        ),
        Node::if_then(
            Expr::and(
                Expr::ne(Expr::var("macro_idx"), Expr::u32(EMPTY_MACRO_SLOT)),
                Expr::gt(
                    Expr::add(Expr::var("macro_idx"), Expr::var("emit_count")),
                    Expr::u32(MACRO_TABLE_SLOTS),
                ),
            ),
            vec![Node::trap(
                Expr::add(Expr::var("macro_idx"), Expr::var("emit_count")),
                "macro-replacement-range-out-of-bounds",
            )],
        ),
        Node::let_bind("warp_base_idx", Expr::u32(0)),
        Node::loop_for("prior", Expr::u32(0), t.clone(), {
            let mut prior_body = vec![Node::let_bind(
                "prior_tok",
                Expr::load(in_tok_types, Expr::var("prior")),
            )];
            prior_body.extend(emit_macro_lookup(
                "prior_lookup",
                Expr::var("prior_tok"),
                macro_keys,
                macro_vals,
                "prior_macro_idx",
            ));
            prior_body.extend([
                Node::if_then(
                    Expr::eq(Expr::var("prior_tok"), Expr::u32(TOK_PREPROC)),
                    vec![Node::assign("prior_macro_idx", Expr::u32(EMPTY_MACRO_SLOT))],
                ),
                Node::let_bind("prior_emit_count", Expr::u32(0)),
                Node::if_then_else(
                    Expr::eq(Expr::var("prior_macro_idx"), Expr::u32(EMPTY_MACRO_SLOT)),
                    vec![Node::assign("prior_emit_count", Expr::u32(1))],
                    vec![
                        Node::assign(
                            "prior_emit_count",
                            Expr::load(macro_sizes, Expr::var("prior_macro_idx")),
                        ),
                        Node::if_then(
                            Expr::gt(
                                Expr::add(
                                    Expr::var("prior_macro_idx"),
                                    Expr::var("prior_emit_count"),
                                ),
                                Expr::u32(MACRO_TABLE_SLOTS),
                            ),
                            vec![Node::trap(
                                Expr::add(
                                    Expr::var("prior_macro_idx"),
                                    Expr::var("prior_emit_count"),
                                ),
                                "macro-prior-replacement-range-out-of-bounds",
                            )],
                        ),
                    ],
                ),
                Node::assign(
                    "warp_base_idx",
                    Expr::add(Expr::var("warp_base_idx"), Expr::var("prior_emit_count")),
                ),
            ]);
            prior_body
        }),
        Node::let_bind(
            "emit_end_idx",
            Expr::add(Expr::var("warp_base_idx"), Expr::var("emit_count")),
        ),
        Node::if_then(
            Expr::gt(Expr::var("emit_end_idx"), Expr::u32(max_out_tokens)),
            vec![Node::trap(
                Expr::var("emit_end_idx"),
                "macro-expansion-output-overflow",
            )],
        ),
        // 3. Dynamic Parallel Token Pasting
        Node::if_then_else(
            Expr::eq(Expr::var("macro_idx"), Expr::u32(EMPTY_MACRO_SLOT)),
            vec![
                // Fast path: Unchanged Token
                Node::store(out_tok_types, Expr::var("warp_base_idx"), Expr::var("tok")),
            ],
            vec![
                // Complex path: Expanding out multiple tokens (e.g. PAGE_SIZE -> (1 << 12))
                Node::loop_for(
                    "i",
                    Expr::u32(0),
                    Expr::var("emit_count"),
                    vec![
                        Node::let_bind(
                            "replacement_tok",
                            Expr::load(
                                macro_vals,
                                Expr::add(Expr::var("macro_idx"), Expr::var("i")),
                            ),
                        ),
                        Node::store(
                            out_tok_types,
                            Expr::add(Expr::var("warp_base_idx"), Expr::var("i")),
                            Expr::var("replacement_tok"),
                        ),
                    ],
                ),
            ],
        ),
        Node::if_then(
            Expr::eq(Expr::add(t.clone(), Expr::u32(1)), num_tokens.clone()),
            vec![Node::store(
                out_tok_counts,
                Expr::u32(0),
                Expr::var("emit_end_idx"),
            )],
        ),
    ]);

    let tok_count = match &num_tokens {
        Expr::LitU32(n) => *n,
        _ => 1,
    };
    let tok_buffer_count = tok_count.max(1);
    let out_buffer_count = max_out_tokens.max(1);
    Program::wrapped(
        vec![
            BufferDecl::storage(in_tok_types, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_buffer_count),
            BufferDecl::storage(macro_keys, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(macro_vals, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(macro_sizes, 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(out_tok_types, 4, BufferAccess::ReadWrite, DataType::U32)
                .with_count(out_buffer_count),
            BufferDecl::storage(out_tok_counts, 5, BufferAccess::ReadWrite, DataType::U32)
                .with_count(1),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(
            "vyre-libs::parsing::opt_dynamic_macro_expansion",
            vec![Node::if_then(Expr::lt(t.clone(), num_tokens), loop_body)],
        )],
    )
    .with_entry_op_id("vyre-libs::parsing::opt_dynamic_macro_expansion")
    .with_non_composable_with_self(true)
}

/// C macro expansion keyed by identifier source-name hashes.
///
/// This kernel is the named-macro successor to `opt_dynamic_macro_expansion`.
/// It computes FNV-1a over each identifier's source span, probes a bounded
/// open-addressed macro table by that name hash, expands object-like macros,
/// and consumes function-like invocations only when the macro name is followed
/// by `(`. Function-like replacement entries whose parameter marker is not
/// `C_MACRO_REPLACEMENT_LITERAL` splice the preserved argument token range for
/// that zero-based parameter index.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn opt_named_macro_expansion(
    in_tok_types: &str,
    in_tok_starts: &str,
    in_tok_lens: &str,
    source_words: &str,
    macro_name_hashes: &str,
    macro_name_starts: &str,
    macro_name_lens: &str,
    macro_name_words: &str,
    macro_vals: &str,
    macro_sizes: &str,
    macro_kinds: &str,
    macro_param_counts: &str,
    macro_replacement_params: &str,
    out_tok_types: &str,
    out_tok_counts: &str,
    num_tokens: Expr,
    source_len: Expr,
    max_out_tokens: u32,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let tok_count = match &num_tokens {
        Expr::LitU32(n) => *n,
        _ => 1,
    };
    let tok_buffer_count = tok_count.max(1);
    let source_count = match &source_len {
        Expr::LitU32(n) => *n,
        _ => 1,
    }
    .max(1);
    let out_buffer_count = max_out_tokens.max(1);

    let mut process_current = vec![
        Node::let_bind("named_tok", Expr::load(in_tok_types, Expr::var("named_i"))),
        Node::let_bind("named_macro_slot", Expr::u32(EMPTY_MACRO_SLOT)),
        Node::let_bind("named_macro_idx", Expr::u32(EMPTY_MACRO_SLOT)),
        Node::let_bind("named_macro_kind", Expr::u32(C_MACRO_KIND_OBJECT_LIKE)),
        Node::let_bind("named_param_count", Expr::u32(0)),
    ];

    process_current.push(Node::if_then(
        Expr::eq(Expr::var("named_tok"), Expr::u32(TOK_IDENTIFIER)),
        {
            let mut ident = emit_source_span_hash(
                "named",
                Expr::var("named_i"),
                in_tok_starts,
                in_tok_lens,
                source_words,
                source_len.clone(),
                "named_name_hash",
            );
            ident.extend(emit_macro_hash_lookup(
                "named_lookup",
                Expr::var("named_name_hash"),
                Expr::var("named_start"),
                Expr::var("named_len"),
                source_words,
                macro_name_hashes,
                macro_name_starts,
                macro_name_lens,
                macro_name_words,
                "named_macro_slot",
            ));
            ident
        },
    ));

    process_current.push(Node::if_then(
        Expr::ne(Expr::var("named_macro_slot"), Expr::u32(EMPTY_MACRO_SLOT)),
        vec![
            Node::assign(
                "named_macro_idx",
                Expr::load(macro_vals, Expr::var("named_macro_slot")),
            ),
            Node::assign(
                "named_macro_kind",
                Expr::load(macro_kinds, Expr::var("named_macro_slot")),
            ),
            Node::assign(
                "named_param_count",
                Expr::load(macro_param_counts, Expr::var("named_macro_slot")),
            ),
            Node::if_then(
                Expr::and(
                    Expr::ne(
                        Expr::var("named_macro_kind"),
                        Expr::u32(C_MACRO_KIND_OBJECT_LIKE),
                    ),
                    Expr::ne(
                        Expr::var("named_macro_kind"),
                        Expr::u32(C_MACRO_KIND_FUNCTION_LIKE),
                    ),
                ),
                vec![Node::trap(
                    Expr::var("named_macro_kind"),
                    "named-macro-kind-invalid",
                )],
            ),
        ],
    ));

    process_current.push(Node::if_then_else(
        Expr::eq(Expr::var("named_macro_slot"), Expr::u32(EMPTY_MACRO_SLOT)),
        {
            let mut passthrough =
                emit_one_output_token(out_tok_types, Expr::var("named_tok"), max_out_tokens);
            passthrough.push(Node::assign(
                "named_i",
                Expr::add(Expr::var("named_i"), Expr::u32(1)),
            ));
            passthrough
        },
        {
            let mut expanded = vec![
                Node::let_bind(
                    "named_repl_size",
                    Expr::load(macro_sizes, Expr::var("named_macro_idx")),
                ),
                Node::if_then(
                    Expr::gt(
                        Expr::add(Expr::var("named_macro_idx"), Expr::var("named_repl_size")),
                        Expr::u32(MACRO_TABLE_SLOTS),
                    ),
                    vec![Node::trap(
                        Expr::add(Expr::var("named_macro_idx"), Expr::var("named_repl_size")),
                        "named-macro-replacement-range-out-of-bounds",
                    )],
                ),
                Node::let_bind("named_has_open_paren", Expr::u32(0)),
                Node::if_then(
                    Expr::lt(
                        Expr::add(Expr::var("named_i"), Expr::u32(1)),
                        num_tokens.clone(),
                    ),
                    vec![Node::if_then(
                        Expr::eq(
                            Expr::load(in_tok_types, Expr::add(Expr::var("named_i"), Expr::u32(1))),
                            Expr::u32(TOK_LPAREN),
                        ),
                        vec![Node::assign("named_has_open_paren", Expr::u32(1))],
                    )],
                ),
            ];

            expanded.push(Node::if_then_else(
                Expr::eq(
                    Expr::var("named_macro_kind"),
                    Expr::u32(C_MACRO_KIND_OBJECT_LIKE),
                ),
                emit_object_like_replacement(
                    macro_vals,
                    macro_replacement_params,
                    out_tok_types,
                    max_out_tokens,
                ),
                vec![Node::if_then_else(
                    Expr::eq(Expr::var("named_has_open_paren"), Expr::u32(0)),
                    {
                        let mut passthrough = emit_one_output_token(
                            out_tok_types,
                            Expr::var("named_tok"),
                            max_out_tokens,
                        );
                        passthrough.push(Node::assign(
                            "named_i",
                            Expr::add(Expr::var("named_i"), Expr::u32(1)),
                        ));
                        passthrough
                    },
                    emit_function_like_replacement(
                        in_tok_types,
                        macro_vals,
                        macro_replacement_params,
                        out_tok_types,
                        "macro_arg_starts",
                        "macro_arg_ends",
                        num_tokens.clone(),
                        max_out_tokens,
                    ),
                )],
            ));
            expanded
        },
    ));

    Program::wrapped(
        vec![
            BufferDecl::storage(in_tok_types, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_buffer_count),
            BufferDecl::storage(in_tok_starts, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_buffer_count),
            BufferDecl::storage(in_tok_lens, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_buffer_count),
            BufferDecl::storage(source_words, 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(source_count),
            BufferDecl::storage(macro_name_hashes, 4, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(macro_name_starts, 5, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(macro_name_lens, 6, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(macro_name_words, 7, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_NAME_BYTES),
            BufferDecl::storage(macro_vals, 8, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(macro_sizes, 9, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(macro_kinds, 10, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(
                macro_param_counts,
                11,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(
                macro_replacement_params,
                12,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(out_tok_types, 13, BufferAccess::ReadWrite, DataType::U32)
                .with_count(out_buffer_count),
            BufferDecl::storage(out_tok_counts, 14, BufferAccess::ReadWrite, DataType::U32)
                .with_count(1),
            BufferDecl::workgroup("macro_arg_starts", tok_buffer_count, DataType::U32),
            BufferDecl::workgroup("macro_arg_ends", tok_buffer_count, DataType::U32),
        ],
        [1, 1, 1],
        vec![wrap_anonymous(
            "vyre-libs::parsing::opt_named_macro_expansion",
            vec![Node::if_then(
                Expr::eq(t, Expr::u32(0)),
                vec![
                    Node::let_bind("named_i", Expr::u32(0)),
                    Node::let_bind("named_out_idx", Expr::u32(0)),
                    Node::loop_for(
                        "named_cursor",
                        Expr::u32(0),
                        num_tokens,
                        vec![Node::if_then(
                            Expr::eq(Expr::var("named_cursor"), Expr::var("named_i")),
                            process_current,
                        )],
                    ),
                    Node::store(out_tok_counts, Expr::u32(0), Expr::var("named_out_idx")),
                ],
            )],
        )],
    )
    .with_entry_op_id("vyre-libs::parsing::opt_named_macro_expansion")
    .with_non_composable_with_self(true)
}

#[allow(clippy::too_many_arguments)]
fn emit_materialized_object_like_replacement(
    macro_vals: &str,
    macro_replacement_params: &str,
    macro_replacement_starts: &str,
    macro_replacement_lens: &str,
    macro_replacement_words: &str,
    out_tok_types: &str,
    out_tok_starts: &str,
    out_tok_lens: &str,
    out_source_words: &str,
    macro_replacement_source_len: Expr,
    max_out_tokens: u32,
    max_out_source_bytes: u32,
) -> Vec<Node> {
    vec![
        Node::let_bind("named_skip_repl", Expr::u32(0)),
        Node::loop_for(
            "named_repl_i",
            Expr::u32(0),
            Expr::var("named_repl_size"),
            {
                vec![Node::if_then_else(
                    Expr::eq(Expr::var("named_skip_repl"), Expr::u32(1)),
                    vec![Node::assign("named_skip_repl", Expr::u32(0))],
                    {
                        let mut body = vec![
                            Node::let_bind(
                                "named_repl_offset",
                                Expr::add(Expr::var("named_macro_idx"), Expr::var("named_repl_i")),
                            ),
                            Node::let_bind(
                                "named_repl_param",
                                Expr::load(
                                    macro_replacement_params,
                                    Expr::var("named_repl_offset"),
                                ),
                            ),
                            Node::if_then(
                                Expr::ne(
                                    Expr::var("named_repl_param"),
                                    Expr::u32(C_MACRO_REPLACEMENT_LITERAL),
                                ),
                                vec![Node::trap(
                                    Expr::var("named_repl_param"),
                                    "object-like-macro-replacement-cannot-reference-parameters",
                                )],
                            ),
                            Node::let_bind(
                                "named_repl_tok",
                                Expr::load(macro_vals, Expr::var("named_repl_offset")),
                            ),
                        ];
                        body.push(Node::if_then_else(
                        Expr::eq(Expr::var("named_repl_tok"), Expr::u32(TOK_HASHHASH)),
                        {
                            let mut paste = vec![Node::if_then(
                                Expr::eq(Expr::var("named_out_idx"), Expr::u32(0)),
                                vec![Node::trap(
                                    Expr::var("named_repl_i"),
                                    "object-like-token-paste-missing-left-token",
                                )],
                            )];
                            paste.extend([
                            Node::if_then(
                                Expr::ge(
                                    Expr::add(Expr::var("named_repl_i"), Expr::u32(1)),
                                    Expr::var("named_repl_size"),
                                ),
                                vec![Node::trap(
                                    Expr::var("named_repl_i"),
                                    "object-like-token-paste-missing-right-token",
                                )],
                            ),
                            Node::let_bind(
                                "macro_paste_next_offset",
                                Expr::add(
                                    Expr::var("named_macro_idx"),
                                    Expr::add(Expr::var("named_repl_i"), Expr::u32(1)),
                                ),
                            ),
                            Node::let_bind(
                                "macro_paste_next_param",
                                Expr::load(
                                    macro_replacement_params,
                                    Expr::var("macro_paste_next_offset"),
                                ),
                            ),
                            Node::if_then(
                                Expr::ne(
                                    Expr::var("macro_paste_next_param"),
                                    Expr::u32(C_MACRO_REPLACEMENT_LITERAL),
                                ),
                                vec![Node::trap(
                                    Expr::var("macro_paste_next_param"),
                                    "object-like-token-paste-cannot-reference-parameters",
                                )],
                            ),
                            Node::let_bind(
                                "macro_paste_left_tok",
                                Expr::load(
                                    out_tok_types,
                                    Expr::sub(Expr::var("named_out_idx"), Expr::u32(1)),
                                ),
                            ),
                            Node::let_bind(
                                "macro_paste_right_tok",
                                Expr::load(macro_vals, Expr::var("macro_paste_next_offset")),
                            ),
                            Node::let_bind(
                                "macro_paste_synth_tok",
                                synthesized_paste_token(
                                    Expr::var("macro_paste_left_tok"),
                                    Expr::var("macro_paste_right_tok"),
                                ),
                            ),
                            Node::if_then(
                                Expr::eq(
                                    Expr::var("macro_paste_synth_tok"),
                                    Expr::u32(EMPTY_MACRO_SLOT),
                                ),
                                vec![Node::trap(
                                    Expr::var("macro_paste_right_tok"),
                                    "object-like-token-paste-cannot-synthesize-token-type-from-materialized-bytes",
                                )],
                            ),
                            Node::store(
                                out_tok_types,
                                Expr::sub(Expr::var("named_out_idx"), Expr::u32(1)),
                                Expr::var("macro_paste_synth_tok"),
                            ),
                            Node::let_bind(
                                "macro_paste_right_start",
                                Expr::load(
                                    macro_replacement_starts,
                                    Expr::var("macro_paste_next_offset"),
                                ),
                            ),
                            Node::let_bind(
                                "macro_paste_right_len",
                                Expr::load(
                                    macro_replacement_lens,
                                    Expr::var("macro_paste_next_offset"),
                                ),
                            ),
                            Node::if_then(
                                Expr::eq(Expr::var("macro_paste_right_len"), Expr::u32(0)),
                                vec![Node::trap(
                                    Expr::var("macro_paste_next_offset"),
                                    "object-like-token-paste-right-token-has-no-source-bytes",
                                )],
                            ),
                            ]);
                            paste.extend(append_to_previous_output_token(
                                "object_paste_rhs",
                                macro_replacement_words,
                                Expr::var("macro_paste_right_start"),
                                Expr::var("macro_paste_right_len"),
                                macro_replacement_source_len.clone(),
                                out_tok_starts,
                                out_tok_lens,
                                out_source_words,
                                max_out_source_bytes,
                                "object-like-token-paste-right-source-span-out-of-bounds",
                            ));
                            paste.push(
                            Node::assign("named_skip_repl", Expr::u32(1)),
                            );
                            paste
                        },
                        emit_materialized_output_token(
                            "object_literal",
                            Expr::var("named_repl_tok"),
                            macro_replacement_words,
                            Expr::load(macro_replacement_starts, Expr::var("named_repl_offset")),
                            Expr::load(macro_replacement_lens, Expr::var("named_repl_offset")),
                            macro_replacement_source_len.clone(),
                            out_tok_types,
                            out_tok_starts,
                            out_tok_lens,
                            out_source_words,
                            max_out_tokens,
                            max_out_source_bytes,
                            "object-like-replacement-source-span-out-of-bounds",
                        ),
                    ));
                        body
                    },
                )]
            },
        ),
        Node::assign("named_i", Expr::add(Expr::var("named_i"), Expr::u32(1))),
    ]
}

#[allow(clippy::too_many_arguments)]
fn emit_materialized_function_like_replacement(
    in_tok_types: &str,
    in_tok_starts: &str,
    in_tok_lens: &str,
    source_words: &str,
    macro_vals: &str,
    macro_replacement_params: &str,
    macro_replacement_starts: &str,
    macro_replacement_lens: &str,
    macro_replacement_words: &str,
    out_tok_types: &str,
    out_tok_starts: &str,
    out_tok_lens: &str,
    out_source_words: &str,
    macro_arg_starts: &str,
    macro_arg_ends: &str,
    num_tokens: Expr,
    source_len: Expr,
    macro_replacement_source_len: Expr,
    max_out_tokens: u32,
    max_out_source_bytes: u32,
) -> Vec<Node> {
    let mut nodes = emit_function_like_argument_scan(
        in_tok_types,
        macro_arg_starts,
        macro_arg_ends,
        num_tokens.clone(),
    );
    nodes.extend([
        Node::let_bind("named_skip_repl", Expr::u32(0)),
        Node::loop_for(
            "named_repl_i",
            Expr::u32(0),
            Expr::var("named_repl_size"),
            {
                vec![Node::if_then_else(
                    Expr::eq(Expr::var("named_skip_repl"), Expr::u32(1)),
                    vec![Node::assign("named_skip_repl", Expr::u32(0))],
                    {
                        let mut repl = vec![
                            Node::let_bind(
                                "named_repl_offset",
                                Expr::add(Expr::var("named_macro_idx"), Expr::var("named_repl_i")),
                            ),
                            Node::let_bind(
                                "named_repl_param",
                                Expr::load(
                                    macro_replacement_params,
                                    Expr::var("named_repl_offset"),
                                ),
                            ),
                            Node::let_bind(
                                "named_repl_tok",
                                Expr::load(macro_vals, Expr::var("named_repl_offset")),
                            ),
                        ];
                        repl.push(Node::if_then_else(
                            Expr::and(
                                Expr::eq(Expr::var("named_repl_tok"), Expr::u32(TOK_HASH)),
                                Expr::lt(
                                    Expr::add(Expr::var("named_repl_i"), Expr::u32(1)),
                                    Expr::var("named_repl_size"),
                                ),
                            ),
                            emit_materialized_stringification_branch(
                                macro_replacement_params,
                                macro_replacement_starts,
                                macro_replacement_lens,
                                macro_replacement_words,
                                macro_replacement_source_len.clone(),
                                macro_arg_starts,
                                macro_arg_ends,
                                in_tok_starts,
                                in_tok_lens,
                                source_words,
                                source_len.clone(),
                                out_tok_types,
                                out_tok_starts,
                                out_tok_lens,
                                out_source_words,
                                max_out_tokens,
                                max_out_source_bytes,
                                num_tokens.clone(),
                            ),
                            vec![Node::if_then_else(
                                Expr::eq(Expr::var("named_repl_tok"), Expr::u32(TOK_HASHHASH)),
                                emit_materialized_function_paste_branch(
                                    in_tok_types,
                                    in_tok_starts,
                                    in_tok_lens,
                                    source_words,
                                    macro_vals,
                                    macro_replacement_params,
                                    macro_replacement_starts,
                                    macro_replacement_lens,
                                    macro_replacement_words,
                                    out_tok_types,
                                    out_tok_starts,
                                    out_tok_lens,
                                    out_source_words,
                                    macro_arg_starts,
                                    macro_arg_ends,
                                    num_tokens.clone(),
                                    source_len.clone(),
                                    macro_replacement_source_len.clone(),
                                    max_out_tokens,
                                    max_out_source_bytes,
                                ),
                                emit_materialized_regular_replacement_branch(
                                    in_tok_types,
                                    in_tok_starts,
                                    in_tok_lens,
                                    source_words,
                                    macro_replacement_starts,
                                    macro_replacement_lens,
                                    macro_replacement_words,
                                    out_tok_types,
                                    out_tok_starts,
                                    out_tok_lens,
                                    out_source_words,
                                    macro_arg_starts,
                                    macro_arg_ends,
                                    num_tokens.clone(),
                                    source_len.clone(),
                                    macro_replacement_source_len.clone(),
                                    max_out_tokens,
                                    max_out_source_bytes,
                                ),
                            )],
                        ));
                        repl
                    },
                )]
            },
        ),
        Node::assign(
            "named_i",
            Expr::add(Expr::var("macro_close_idx"), Expr::u32(1)),
        ),
    ]);
    nodes
}

fn emit_function_like_argument_scan(
    in_tok_types: &str,
    macro_arg_starts: &str,
    macro_arg_ends: &str,
    num_tokens: Expr,
) -> Vec<Node> {
    let mut nodes = vec![
        Node::if_then(
            Expr::gt(Expr::var("named_param_count"), num_tokens.clone()),
            vec![Node::trap(
                Expr::var("named_param_count"),
                "function-like-macro-parameter-count-exceeds-token-capacity",
            )],
        ),
        Node::let_bind(
            "macro_scan_base",
            Expr::add(Expr::var("named_i"), Expr::u32(2)),
        ),
        Node::let_bind("macro_depth", Expr::u32(0)),
        Node::let_bind("macro_arg_index", Expr::u32(0)),
        Node::let_bind("macro_current_arg_start", Expr::var("macro_scan_base")),
        Node::let_bind("macro_found_close", Expr::u32(0)),
        Node::let_bind("macro_close_idx", num_tokens.clone()),
        Node::store(macro_arg_starts, Expr::u32(0), Expr::var("macro_scan_base")),
        Node::store(macro_arg_ends, Expr::u32(0), Expr::var("macro_scan_base")),
    ];
    let scan_body = vec![
        Node::let_bind(
            "macro_scan_idx",
            Expr::add(Expr::var("macro_scan_base"), Expr::var("macro_scan_rel")),
        ),
        Node::if_then(
            Expr::and(
                Expr::eq(Expr::var("macro_found_close"), Expr::u32(0)),
                Expr::ge(Expr::var("macro_scan_idx"), num_tokens.clone()),
            ),
            vec![Node::trap(
                Expr::var("macro_scan_idx"),
                "function-like-macro-invocation-missing-rparen",
            )],
        ),
        Node::if_then(
            Expr::and(
                Expr::eq(Expr::var("macro_found_close"), Expr::u32(0)),
                Expr::lt(Expr::var("macro_scan_idx"), num_tokens.clone()),
            ),
            vec![
                Node::let_bind(
                    "macro_scan_tok",
                    Expr::load(in_tok_types, Expr::var("macro_scan_idx")),
                ),
                Node::if_then(
                    Expr::eq(Expr::var("macro_scan_tok"), Expr::u32(TOK_LPAREN)),
                    vec![Node::assign(
                        "macro_depth",
                        Expr::add(Expr::var("macro_depth"), Expr::u32(1)),
                    )],
                ),
                Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("macro_scan_tok"), Expr::u32(TOK_COMMA)),
                        Expr::eq(Expr::var("macro_depth"), Expr::u32(0)),
                    ),
                    {
                        let mut comma = assign_arg_bound(
                            macro_arg_ends,
                            Expr::var("macro_arg_index"),
                            Expr::var("macro_scan_idx"),
                            num_tokens.clone(),
                            "function-like-macro-argument-count-overflow",
                        );
                        comma.extend([
                            Node::assign(
                                "macro_arg_index",
                                Expr::add(Expr::var("macro_arg_index"), Expr::u32(1)),
                            ),
                            Node::if_then(
                                Expr::ge(Expr::var("macro_arg_index"), num_tokens.clone()),
                                vec![Node::trap(
                                    Expr::var("macro_arg_index"),
                                    "function-like-macro-argument-count-overflow",
                                )],
                            ),
                            Node::assign(
                                "macro_current_arg_start",
                                Expr::add(Expr::var("macro_scan_idx"), Expr::u32(1)),
                            ),
                        ]);
                        comma.extend(assign_arg_bound(
                            macro_arg_starts,
                            Expr::var("macro_arg_index"),
                            Expr::var("macro_current_arg_start"),
                            num_tokens.clone(),
                            "function-like-macro-argument-count-overflow",
                        ));
                        comma
                    },
                ),
                Node::if_then(
                    Expr::eq(Expr::var("macro_scan_tok"), Expr::u32(TOK_RPAREN)),
                    vec![Node::if_then_else(
                        Expr::eq(Expr::var("macro_depth"), Expr::u32(0)),
                        {
                            let mut close = assign_arg_bound(
                                macro_arg_ends,
                                Expr::var("macro_arg_index"),
                                Expr::var("macro_scan_idx"),
                                num_tokens.clone(),
                                "function-like-macro-argument-count-overflow",
                            );
                            close.extend([
                                Node::assign("macro_found_close", Expr::u32(1)),
                                Node::assign("macro_close_idx", Expr::var("macro_scan_idx")),
                            ]);
                            close
                        },
                        vec![Node::assign(
                            "macro_depth",
                            Expr::sub(Expr::var("macro_depth"), Expr::u32(1)),
                        )],
                    )],
                ),
            ],
        ),
    ];
    nodes.push(Node::loop_for(
        "macro_scan_rel",
        Expr::u32(0),
        num_tokens.clone(),
        scan_body,
    ));
    nodes.extend([
        Node::if_then(
            Expr::eq(Expr::var("macro_found_close"), Expr::u32(0)),
            vec![Node::trap(
                Expr::var("named_i"),
                "function-like-macro-invocation-missing-rparen",
            )],
        ),
        Node::let_bind(
            "macro_seen_arg_count",
            Expr::add(Expr::var("macro_arg_index"), Expr::u32(1)),
        ),
        Node::if_then(
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("macro_close_idx"), Expr::var("macro_scan_base")),
                    Expr::eq(Expr::var("named_param_count"), Expr::u32(0)),
                ),
                Expr::eq(Expr::var("macro_arg_index"), Expr::u32(0)),
            ),
            vec![Node::assign("macro_seen_arg_count", Expr::u32(0))],
        ),
        Node::if_then(
            Expr::ne(
                Expr::var("macro_seen_arg_count"),
                Expr::var("named_param_count"),
            ),
            vec![Node::trap(
                Expr::var("macro_seen_arg_count"),
                "function-like-macro-argument-count-mismatch",
            )],
        ),
    ]);
    nodes
}

#[allow(clippy::too_many_arguments)]
fn emit_materialized_stringification_branch(
    macro_replacement_params: &str,
    macro_replacement_starts: &str,
    macro_replacement_lens: &str,
    macro_replacement_words: &str,
    macro_replacement_source_len: Expr,
    macro_arg_starts: &str,
    macro_arg_ends: &str,
    in_tok_starts: &str,
    in_tok_lens: &str,
    source_words: &str,
    source_len: Expr,
    out_tok_types: &str,
    out_tok_starts: &str,
    out_tok_lens: &str,
    out_source_words: &str,
    max_out_tokens: u32,
    max_out_source_bytes: u32,
    num_tokens: Expr,
) -> Vec<Node> {
    let mut stringify = vec![
        Node::let_bind(
            "macro_stringify_next_offset",
            Expr::add(
                Expr::var("named_macro_idx"),
                Expr::add(Expr::var("named_repl_i"), Expr::u32(1)),
            ),
        ),
        Node::let_bind(
            "macro_stringify_next_param",
            Expr::load(
                macro_replacement_params,
                Expr::var("macro_stringify_next_offset"),
            ),
        ),
    ];
    stringify.push(Node::if_then_else(
        Expr::eq(
            Expr::var("macro_stringify_next_param"),
            Expr::u32(C_MACRO_REPLACEMENT_LITERAL),
        ),
        emit_materialized_output_token(
            "function_hash_literal",
            Expr::var("named_repl_tok"),
            macro_replacement_words,
            Expr::load(macro_replacement_starts, Expr::var("named_repl_offset")),
            Expr::load(macro_replacement_lens, Expr::var("named_repl_offset")),
            macro_replacement_source_len,
            out_tok_types,
            out_tok_starts,
            out_tok_lens,
            out_source_words,
            max_out_tokens,
            max_out_source_bytes,
            "function-like-stringification-literal-hash-has-no-source-table",
        ),
        {
            let mut branch = vec![Node::if_then(
                Expr::ge(
                    Expr::var("macro_stringify_next_param"),
                    Expr::var("named_param_count"),
                ),
                vec![Node::trap(
                    Expr::var("macro_stringify_next_param"),
                    "function-like-stringification-parameter-out-of-range",
                )],
            )];
            branch.extend(emit_stringified_argument_token(
                "function_stringify",
                selected_arg_bound(macro_arg_starts, Expr::var("macro_stringify_next_param")),
                selected_arg_bound(macro_arg_ends, Expr::var("macro_stringify_next_param")),
                in_tok_starts,
                in_tok_lens,
                source_words,
                source_len,
                out_tok_types,
                out_tok_starts,
                out_tok_lens,
                out_source_words,
                max_out_tokens,
                max_out_source_bytes,
                num_tokens,
            ));
            branch.push(Node::assign("named_skip_repl", Expr::u32(1)));
            branch
        },
    ));
    stringify
}

#[allow(clippy::too_many_arguments)]
fn emit_materialized_regular_replacement_branch(
    in_tok_types: &str,
    in_tok_starts: &str,
    in_tok_lens: &str,
    source_words: &str,
    macro_replacement_starts: &str,
    macro_replacement_lens: &str,
    macro_replacement_words: &str,
    out_tok_types: &str,
    out_tok_starts: &str,
    out_tok_lens: &str,
    out_source_words: &str,
    macro_arg_starts: &str,
    macro_arg_ends: &str,
    num_tokens: Expr,
    source_len: Expr,
    macro_replacement_source_len: Expr,
    max_out_tokens: u32,
    max_out_source_bytes: u32,
) -> Vec<Node> {
    let regular_literal = emit_materialized_output_token(
        "function_literal",
        Expr::var("named_repl_tok"),
        macro_replacement_words,
        Expr::load(macro_replacement_starts, Expr::var("named_repl_offset")),
        Expr::load(macro_replacement_lens, Expr::var("named_repl_offset")),
        macro_replacement_source_len,
        out_tok_types,
        out_tok_starts,
        out_tok_lens,
        out_source_words,
        max_out_tokens,
        max_out_source_bytes,
        "function-like-replacement-source-span-out-of-bounds",
    );
    let arg_start = selected_arg_bound(macro_arg_starts, Expr::var("named_repl_param"));
    let arg_end = selected_arg_bound(macro_arg_ends, Expr::var("named_repl_param"));
    vec![Node::if_then_else(
        Expr::eq(
            Expr::var("named_repl_param"),
            Expr::u32(C_MACRO_REPLACEMENT_LITERAL),
        ),
        regular_literal,
        {
            let mut arg = vec![
                Node::if_then(
                    Expr::ge(
                        Expr::var("named_repl_param"),
                        Expr::var("named_param_count"),
                    ),
                    vec![Node::trap(
                        Expr::var("named_repl_param"),
                        "function-like-macro-replacement-parameter-out-of-range",
                    )],
                ),
                Node::let_bind("macro_sub_arg_start", arg_start),
                Node::let_bind("macro_sub_arg_end", arg_end),
            ];
            arg.push(Node::loop_for(
                "macro_sub_arg_rel",
                Expr::u32(0),
                num_tokens.clone(),
                vec![Node::if_then(
                    Expr::lt(
                        Expr::add(
                            Expr::var("macro_sub_arg_start"),
                            Expr::var("macro_sub_arg_rel"),
                        ),
                        Expr::var("macro_sub_arg_end"),
                    ),
                    {
                        let mut copy = vec![Node::let_bind(
                            "macro_sub_arg_tok_idx",
                            Expr::add(
                                Expr::var("macro_sub_arg_start"),
                                Expr::var("macro_sub_arg_rel"),
                            ),
                        )];
                        copy.extend(emit_materialized_output_token(
                            "function_arg_token",
                            Expr::load(in_tok_types, Expr::var("macro_sub_arg_tok_idx")),
                            source_words,
                            Expr::load(in_tok_starts, Expr::var("macro_sub_arg_tok_idx")),
                            Expr::load(in_tok_lens, Expr::var("macro_sub_arg_tok_idx")),
                            source_len.clone(),
                            out_tok_types,
                            out_tok_starts,
                            out_tok_lens,
                            out_source_words,
                            max_out_tokens,
                            max_out_source_bytes,
                            "function-like-argument-source-span-out-of-bounds",
                        ));
                        copy
                    },
                )],
            ));
            arg
        },
    )]
}

#[allow(clippy::too_many_arguments)]
fn emit_materialized_function_paste_branch(
    in_tok_types: &str,
    in_tok_starts: &str,
    in_tok_lens: &str,
    source_words: &str,
    macro_vals: &str,
    macro_replacement_params: &str,
    macro_replacement_starts: &str,
    macro_replacement_lens: &str,
    macro_replacement_words: &str,
    out_tok_types: &str,
    out_tok_starts: &str,
    out_tok_lens: &str,
    out_source_words: &str,
    macro_arg_starts: &str,
    macro_arg_ends: &str,
    num_tokens: Expr,
    source_len: Expr,
    macro_replacement_source_len: Expr,
    max_out_tokens: u32,
    max_out_source_bytes: u32,
) -> Vec<Node> {
    let mut paste = vec![
        Node::if_then(
            Expr::eq(Expr::var("named_out_idx"), Expr::u32(0)),
            vec![Node::trap(
                Expr::var("named_repl_i"),
                "function-like-token-paste-missing-left-token",
            )],
        ),
        Node::if_then(
            Expr::ge(
                Expr::add(Expr::var("named_repl_i"), Expr::u32(1)),
                Expr::var("named_repl_size"),
            ),
            vec![Node::trap(
                Expr::var("named_repl_i"),
                "function-like-token-paste-missing-right-token",
            )],
        ),
        Node::let_bind(
            "macro_paste_next_offset",
            Expr::add(
                Expr::var("named_macro_idx"),
                Expr::add(Expr::var("named_repl_i"), Expr::u32(1)),
            ),
        ),
        Node::let_bind(
            "macro_paste_next_param",
            Expr::load(
                macro_replacement_params,
                Expr::var("macro_paste_next_offset"),
            ),
        ),
        Node::let_bind("macro_paste_right_tok", Expr::u32(0)),
        Node::let_bind("macro_paste_right_start", Expr::u32(0)),
        Node::let_bind("macro_paste_right_len", Expr::u32(0)),
        Node::let_bind("macro_paste_right_source_limit", Expr::u32(0)),
        Node::let_bind("macro_paste_right_from_argument", Expr::u32(0)),
        Node::let_bind("macro_paste_arg_start", Expr::u32(0)),
        Node::let_bind("macro_paste_arg_end", Expr::u32(0)),
    ];
    paste.push(Node::if_then_else(
        Expr::eq(
            Expr::var("macro_paste_next_param"),
            Expr::u32(C_MACRO_REPLACEMENT_LITERAL),
        ),
        vec![
            Node::assign(
                "macro_paste_right_tok",
                Expr::load(macro_vals, Expr::var("macro_paste_next_offset")),
            ),
            Node::assign(
                "macro_paste_right_start",
                Expr::load(
                    macro_replacement_starts,
                    Expr::var("macro_paste_next_offset"),
                ),
            ),
            Node::assign(
                "macro_paste_right_len",
                Expr::load(macro_replacement_lens, Expr::var("macro_paste_next_offset")),
            ),
            Node::assign(
                "macro_paste_right_source_limit",
                macro_replacement_source_len.clone(),
            ),
        ],
        {
            let arg_start =
                selected_arg_bound(macro_arg_starts, Expr::var("macro_paste_next_param"));
            let arg_end = selected_arg_bound(macro_arg_ends, Expr::var("macro_paste_next_param"));
            vec![
                Node::if_then(
                    Expr::ge(
                        Expr::var("macro_paste_next_param"),
                        Expr::var("named_param_count"),
                    ),
                    vec![Node::trap(
                        Expr::var("macro_paste_next_param"),
                        "function-like-token-paste-parameter-out-of-range",
                    )],
                ),
                Node::assign("macro_paste_arg_start", arg_start),
                Node::assign("macro_paste_arg_end", arg_end),
                Node::if_then(
                    Expr::ge(
                        Expr::var("macro_paste_arg_start"),
                        Expr::var("macro_paste_arg_end"),
                    ),
                    vec![Node::trap(
                        Expr::var("macro_paste_next_param"),
                        "function-like-token-paste-empty-argument",
                    )],
                ),
                Node::assign(
                    "macro_paste_right_tok",
                    Expr::load(in_tok_types, Expr::var("macro_paste_arg_start")),
                ),
                Node::assign(
                    "macro_paste_right_start",
                    Expr::load(in_tok_starts, Expr::var("macro_paste_arg_start")),
                ),
                Node::assign(
                    "macro_paste_right_len",
                    Expr::load(in_tok_lens, Expr::var("macro_paste_arg_start")),
                ),
                Node::assign("macro_paste_right_source_limit", source_len.clone()),
                Node::assign("macro_paste_right_from_argument", Expr::u32(1)),
            ]
        },
    ));
    paste.extend([
        Node::if_then(
            Expr::eq(Expr::var("macro_paste_right_len"), Expr::u32(0)),
            vec![Node::trap(
                Expr::var("macro_paste_next_offset"),
                "function-like-token-paste-right-token-has-no-source-bytes",
            )],
        ),
        Node::let_bind(
            "macro_paste_left_tok",
            Expr::load(
                out_tok_types,
                Expr::sub(Expr::var("named_out_idx"), Expr::u32(1)),
            ),
        ),
        Node::let_bind(
            "macro_paste_synth_tok",
            synthesized_paste_token(
                Expr::var("macro_paste_left_tok"),
                Expr::var("macro_paste_right_tok"),
            ),
        ),
        Node::if_then(
            Expr::eq(
                Expr::var("macro_paste_synth_tok"),
                Expr::u32(EMPTY_MACRO_SLOT),
            ),
            vec![Node::trap(
                Expr::var("macro_paste_right_tok"),
                "function-like-token-paste-cannot-synthesize-token-type-from-materialized-bytes",
            )],
        ),
        Node::store(
            out_tok_types,
            Expr::sub(Expr::var("named_out_idx"), Expr::u32(1)),
            Expr::var("macro_paste_synth_tok"),
        ),
    ]);
    paste.push(Node::if_then_else(
        Expr::eq(Expr::var("macro_paste_right_from_argument"), Expr::u32(1)),
        append_to_previous_output_token(
            "function_paste_arg_rhs",
            source_words,
            Expr::var("macro_paste_right_start"),
            Expr::var("macro_paste_right_len"),
            source_len.clone(),
            out_tok_starts,
            out_tok_lens,
            out_source_words,
            max_out_source_bytes,
            "function-like-token-paste-argument-source-span-out-of-bounds",
        ),
        append_to_previous_output_token(
            "function_paste_literal_rhs",
            macro_replacement_words,
            Expr::var("macro_paste_right_start"),
            Expr::var("macro_paste_right_len"),
            macro_replacement_source_len.clone(),
            out_tok_starts,
            out_tok_lens,
            out_source_words,
            max_out_source_bytes,
            "function-like-token-paste-literal-source-span-out-of-bounds",
        ),
    ));
    paste.push(Node::if_then(
        Expr::eq(Expr::var("macro_paste_right_from_argument"), Expr::u32(1)),
        vec![Node::loop_for(
            "macro_paste_rhs_rest_rel",
            Expr::u32(1),
            num_tokens.clone(),
            vec![Node::if_then(
                Expr::lt(
                    Expr::add(
                        Expr::var("macro_paste_arg_start"),
                        Expr::var("macro_paste_rhs_rest_rel"),
                    ),
                    Expr::var("macro_paste_arg_end"),
                ),
                {
                    let mut copy = vec![Node::let_bind(
                        "macro_paste_rhs_rest_idx",
                        Expr::add(
                            Expr::var("macro_paste_arg_start"),
                            Expr::var("macro_paste_rhs_rest_rel"),
                        ),
                    )];
                    copy.extend(emit_materialized_output_token(
                        "function_paste_rhs_rest",
                        Expr::load(in_tok_types, Expr::var("macro_paste_rhs_rest_idx")),
                        source_words,
                        Expr::load(in_tok_starts, Expr::var("macro_paste_rhs_rest_idx")),
                        Expr::load(in_tok_lens, Expr::var("macro_paste_rhs_rest_idx")),
                        source_len.clone(),
                        out_tok_types,
                        out_tok_starts,
                        out_tok_lens,
                        out_source_words,
                        max_out_tokens,
                        max_out_source_bytes,
                        "function-like-token-paste-rest-source-span-out-of-bounds",
                    ));
                    copy
                },
            )],
        )],
    ));
    paste.push(Node::assign("named_skip_repl", Expr::u32(1)));
    paste
}

/// C macro expansion that materializes output source bytes.
///
/// This is the source-fidelity form of named macro expansion. Every emitted
/// token receives a start/length pair into `out_source_words`; literal
/// replacement tokens copy from the replacement source side table, parameter
/// substitutions copy from the input source, `#` builds escaped string literal
/// bytes, and `##` rewrites the previous token by appending the right operand's
/// bytes. Unsupported pastes trap instead of emitting token-kind-only guesses.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn opt_named_macro_expansion_materialized(
    in_tok_types: &str,
    in_tok_starts: &str,
    in_tok_lens: &str,
    source_words: &str,
    macro_name_hashes: &str,
    macro_name_starts: &str,
    macro_name_lens: &str,
    macro_name_words: &str,
    macro_vals: &str,
    macro_sizes: &str,
    macro_kinds: &str,
    macro_param_counts: &str,
    macro_replacement_params: &str,
    macro_replacement_starts: &str,
    macro_replacement_lens: &str,
    macro_replacement_words: &str,
    out_tok_types: &str,
    out_tok_starts: &str,
    out_tok_lens: &str,
    out_source_words: &str,
    out_tok_counts: &str,
    out_source_counts: &str,
    num_tokens: Expr,
    source_len: Expr,
    macro_replacement_source_len: Expr,
    max_out_tokens: u32,
    max_out_source_bytes: u32,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let tok_count = match &num_tokens {
        Expr::LitU32(n) => *n,
        _ => 1,
    };
    let tok_buffer_count = tok_count.max(1);
    let source_count = match &source_len {
        Expr::LitU32(n) => *n,
        _ => 1,
    }
    .max(1);
    let replacement_source_count = match &macro_replacement_source_len {
        Expr::LitU32(n) => *n,
        _ => 1,
    }
    .max(1);
    let out_buffer_count = max_out_tokens.max(1);
    let out_source_count = max_out_source_bytes.max(1);

    let mut process_current = vec![
        Node::let_bind("named_tok", Expr::load(in_tok_types, Expr::var("named_i"))),
        Node::let_bind("named_macro_slot", Expr::u32(EMPTY_MACRO_SLOT)),
        Node::let_bind("named_macro_idx", Expr::u32(EMPTY_MACRO_SLOT)),
        Node::let_bind("named_macro_kind", Expr::u32(C_MACRO_KIND_OBJECT_LIKE)),
        Node::let_bind("named_param_count", Expr::u32(0)),
    ];
    process_current.push(Node::if_then(
        Expr::eq(Expr::var("named_tok"), Expr::u32(TOK_IDENTIFIER)),
        {
            let mut ident = emit_source_span_hash(
                "named",
                Expr::var("named_i"),
                in_tok_starts,
                in_tok_lens,
                source_words,
                source_len.clone(),
                "named_name_hash",
            );
            ident.extend(emit_macro_hash_lookup(
                "named_lookup",
                Expr::var("named_name_hash"),
                Expr::var("named_start"),
                Expr::var("named_len"),
                source_words,
                macro_name_hashes,
                macro_name_starts,
                macro_name_lens,
                macro_name_words,
                "named_macro_slot",
            ));
            ident
        },
    ));
    process_current.push(Node::if_then(
        Expr::ne(Expr::var("named_macro_slot"), Expr::u32(EMPTY_MACRO_SLOT)),
        vec![
            Node::assign(
                "named_macro_idx",
                Expr::load(macro_vals, Expr::var("named_macro_slot")),
            ),
            Node::assign(
                "named_macro_kind",
                Expr::load(macro_kinds, Expr::var("named_macro_slot")),
            ),
            Node::assign(
                "named_param_count",
                Expr::load(macro_param_counts, Expr::var("named_macro_slot")),
            ),
            Node::if_then(
                Expr::and(
                    Expr::ne(
                        Expr::var("named_macro_kind"),
                        Expr::u32(C_MACRO_KIND_OBJECT_LIKE),
                    ),
                    Expr::ne(
                        Expr::var("named_macro_kind"),
                        Expr::u32(C_MACRO_KIND_FUNCTION_LIKE),
                    ),
                ),
                vec![Node::trap(
                    Expr::var("named_macro_kind"),
                    "named-macro-kind-invalid",
                )],
            ),
        ],
    ));
    process_current.push(Node::if_then_else(
        Expr::eq(Expr::var("named_macro_slot"), Expr::u32(EMPTY_MACRO_SLOT)),
        {
            let mut passthrough = emit_materialized_output_token(
                "passthrough",
                Expr::var("named_tok"),
                source_words,
                Expr::load(in_tok_starts, Expr::var("named_i")),
                Expr::load(in_tok_lens, Expr::var("named_i")),
                source_len.clone(),
                out_tok_types,
                out_tok_starts,
                out_tok_lens,
                out_source_words,
                max_out_tokens,
                max_out_source_bytes,
                "passthrough-token-source-span-out-of-bounds",
            );
            passthrough.push(Node::assign(
                "named_i",
                Expr::add(Expr::var("named_i"), Expr::u32(1)),
            ));
            passthrough
        },
        {
            let mut expanded = vec![
                Node::let_bind(
                    "named_repl_size",
                    Expr::load(macro_sizes, Expr::var("named_macro_idx")),
                ),
                Node::if_then(
                    Expr::gt(
                        Expr::add(Expr::var("named_macro_idx"), Expr::var("named_repl_size")),
                        Expr::u32(MACRO_TABLE_SLOTS),
                    ),
                    vec![Node::trap(
                        Expr::add(Expr::var("named_macro_idx"), Expr::var("named_repl_size")),
                        "named-macro-replacement-range-out-of-bounds",
                    )],
                ),
                Node::let_bind("named_has_open_paren", Expr::u32(0)),
                Node::if_then(
                    Expr::lt(
                        Expr::add(Expr::var("named_i"), Expr::u32(1)),
                        num_tokens.clone(),
                    ),
                    vec![Node::if_then(
                        Expr::eq(
                            Expr::load(in_tok_types, Expr::add(Expr::var("named_i"), Expr::u32(1))),
                            Expr::u32(TOK_LPAREN),
                        ),
                        vec![Node::assign("named_has_open_paren", Expr::u32(1))],
                    )],
                ),
            ];
            expanded.push(Node::if_then_else(
                Expr::eq(
                    Expr::var("named_macro_kind"),
                    Expr::u32(C_MACRO_KIND_OBJECT_LIKE),
                ),
                emit_materialized_object_like_replacement(
                    macro_vals,
                    macro_replacement_params,
                    macro_replacement_starts,
                    macro_replacement_lens,
                    macro_replacement_words,
                    out_tok_types,
                    out_tok_starts,
                    out_tok_lens,
                    out_source_words,
                    macro_replacement_source_len.clone(),
                    max_out_tokens,
                    max_out_source_bytes,
                ),
                vec![Node::if_then_else(
                    Expr::eq(Expr::var("named_has_open_paren"), Expr::u32(0)),
                    {
                        let mut passthrough = emit_materialized_output_token(
                            "function_name_passthrough",
                            Expr::var("named_tok"),
                            source_words,
                            Expr::load(in_tok_starts, Expr::var("named_i")),
                            Expr::load(in_tok_lens, Expr::var("named_i")),
                            source_len.clone(),
                            out_tok_types,
                            out_tok_starts,
                            out_tok_lens,
                            out_source_words,
                            max_out_tokens,
                            max_out_source_bytes,
                            "function-name-passthrough-source-span-out-of-bounds",
                        );
                        passthrough.push(Node::assign(
                            "named_i",
                            Expr::add(Expr::var("named_i"), Expr::u32(1)),
                        ));
                        passthrough
                    },
                    emit_materialized_function_like_replacement(
                        in_tok_types,
                        in_tok_starts,
                        in_tok_lens,
                        source_words,
                        macro_vals,
                        macro_replacement_params,
                        macro_replacement_starts,
                        macro_replacement_lens,
                        macro_replacement_words,
                        out_tok_types,
                        out_tok_starts,
                        out_tok_lens,
                        out_source_words,
                        "macro_arg_starts",
                        "macro_arg_ends",
                        num_tokens.clone(),
                        source_len.clone(),
                        macro_replacement_source_len.clone(),
                        max_out_tokens,
                        max_out_source_bytes,
                    ),
                )],
            ));
            expanded
        },
    ));

    Program::wrapped(
        vec![
            BufferDecl::storage(in_tok_types, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_buffer_count),
            BufferDecl::storage(in_tok_starts, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_buffer_count),
            BufferDecl::storage(in_tok_lens, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_buffer_count),
            BufferDecl::storage(source_words, 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(source_count),
            BufferDecl::storage(macro_name_hashes, 4, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(macro_name_starts, 5, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(macro_name_lens, 6, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(macro_name_words, 7, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_NAME_BYTES),
            BufferDecl::storage(macro_vals, 8, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(macro_sizes, 9, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(macro_kinds, 10, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(
                macro_param_counts,
                11,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(
                macro_replacement_params,
                12,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(
                macro_replacement_starts,
                13,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(
                macro_replacement_lens,
                14,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(
                macro_replacement_words,
                15,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(replacement_source_count),
            BufferDecl::storage(out_tok_types, 16, BufferAccess::ReadWrite, DataType::U32)
                .with_count(out_buffer_count),
            BufferDecl::storage(out_tok_starts, 17, BufferAccess::ReadWrite, DataType::U32)
                .with_count(out_buffer_count),
            BufferDecl::storage(out_tok_lens, 18, BufferAccess::ReadWrite, DataType::U32)
                .with_count(out_buffer_count),
            BufferDecl::storage(out_source_words, 19, BufferAccess::ReadWrite, DataType::U32)
                .with_count(out_source_count),
            BufferDecl::storage(out_tok_counts, 20, BufferAccess::ReadWrite, DataType::U32)
                .with_count(1),
            BufferDecl::storage(
                out_source_counts,
                21,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(1),
            BufferDecl::workgroup("macro_arg_starts", tok_buffer_count, DataType::U32),
            BufferDecl::workgroup("macro_arg_ends", tok_buffer_count, DataType::U32),
        ],
        [1, 1, 1],
        vec![wrap_anonymous(
            "vyre-libs::parsing::opt_named_macro_expansion_materialized",
            vec![Node::if_then(
                Expr::eq(t, Expr::u32(0)),
                vec![
                    Node::let_bind("named_i", Expr::u32(0)),
                    Node::let_bind("named_out_idx", Expr::u32(0)),
                    Node::let_bind("named_source_out_idx", Expr::u32(0)),
                    Node::loop_for(
                        "named_cursor",
                        Expr::u32(0),
                        num_tokens,
                        vec![Node::if_then(
                            Expr::eq(Expr::var("named_cursor"), Expr::var("named_i")),
                            process_current,
                        )],
                    ),
                    Node::store(out_tok_counts, Expr::u32(0), Expr::var("named_out_idx")),
                    Node::store(
                        out_source_counts,
                        Expr::u32(C_MACRO_SOURCE_COUNT_BYTES),
                        Expr::var("named_source_out_idx"),
                    ),
                ],
            )],
        )],
    )
    .with_entry_op_id("vyre-libs::parsing::opt_named_macro_expansion_materialized")
    .with_non_composable_with_self(true)
}

/// LEGO Block 2: GPU-Native Conditional Evaluator (#if / #ifdef) (Tier-3)
///
/// General Purpose Logic Masking engine. Valid for any language conditional graph.
/// In conditional-compilation logic, the preprocessor evaluates tree-depth masks. Instead of
/// doing this sequentially on the CPU, the GPU traces block depth offsets
/// and maps "dead" logic tokens (e.g. #else blocks that didn't match) into an inactive stream.
#[must_use]
pub fn opt_conditional_mask(tok_types: &str, out_mask: &str, num_tokens: Expr) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let tok_count = match &num_tokens {
        Expr::LitU32(n) => *n,
        _ => 1,
    };
    let tok_buffer_count = tok_count.max(1);
    let entry = if tok_count == 0 {
        vec![Node::trap(
            Expr::u32(0),
            "conditional-mask-empty-token-stream",
        )]
    } else {
        vec![Node::if_then(
            Expr::lt(t.clone(), num_tokens),
            vec![
                Node::store(out_mask, t.clone(), Expr::u32(1)), // Base mask
            ],
        )]
    };
    Program::wrapped(
        vec![
            BufferDecl::storage(tok_types, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_buffer_count),
            BufferDecl::storage(out_mask, 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(tok_buffer_count),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(
            "vyre-libs::parsing::opt_conditional_mask",
            entry,
        )],
    )
    .with_entry_op_id("vyre-libs::parsing::opt_conditional_mask")
    .with_non_composable_with_self(true)
}

fn lower_depth_mask(depth: Expr) -> Expr {
    Expr::sub(Expr::shl(Expr::u32(1), depth), Expr::u32(1))
}

fn all_enclosing_active(active_bits: Expr, depth: Expr) -> Expr {
    let mask = lower_depth_mask(depth);
    Expr::eq(Expr::bitand(active_bits, mask.clone()), mask)
}

fn directive_is_conditional_open(kind: Expr) -> Expr {
    Expr::or(
        Expr::eq(kind.clone(), Expr::u32(TOK_PP_IF)),
        Expr::or(
            Expr::eq(kind.clone(), Expr::u32(TOK_PP_IFDEF)),
            Expr::eq(kind, Expr::u32(TOK_PP_IFNDEF)),
        ),
    )
}

/// GPU conditional-compilation mask over classified preprocessor directives.
#[must_use]
pub fn opt_conditional_mask_with_directives(
    tok_types: &str,
    directive_kinds: &str,
    directive_values: &str,
    out_mask: &str,
    num_tokens: Expr,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let tok_count = match &num_tokens {
        Expr::LitU32(n) => *n,
        _ => 1,
    };
    let tok_buffer_count = tok_count.max(1);

    let mut per_token = vec![
        Node::let_bind("tok", Expr::load(tok_types, Expr::var("i"))),
        Node::let_bind("kind", Expr::load(directive_kinds, Expr::var("i"))),
        Node::let_bind("value", Expr::load(directive_values, Expr::var("i"))),
        Node::let_bind(
            "current_active",
            all_enclosing_active(Expr::var("active_bits"), Expr::var("depth")),
        ),
        Node::let_bind(
            "is_control_directive",
            Expr::and(
                Expr::eq(Expr::var("tok"), Expr::u32(TOK_PREPROC)),
                Expr::or(
                    directive_is_conditional_open(Expr::var("kind")),
                    Expr::or(
                        Expr::eq(Expr::var("kind"), Expr::u32(TOK_PP_ELIF)),
                        Expr::or(
                            Expr::eq(Expr::var("kind"), Expr::u32(TOK_PP_ELSE)),
                            Expr::eq(Expr::var("kind"), Expr::u32(TOK_PP_ENDIF)),
                        ),
                    ),
                ),
            ),
        ),
        Node::store(
            out_mask,
            Expr::var("i"),
            Expr::select(
                Expr::var("is_control_directive"),
                Expr::u32(1),
                Expr::select(Expr::var("current_active"), Expr::u32(1), Expr::u32(0)),
            ),
        ),
    ];

    per_token.extend([
        Node::if_then(
            directive_is_conditional_open(Expr::var("kind")),
            vec![
                Node::if_then(
                    Expr::ge(Expr::var("depth"), Expr::u32(31)),
                    vec![Node::trap(
                        Expr::var("i"),
                        "c-preprocess-conditional-nesting-overflow",
                    )],
                ),
                Node::let_bind("open_bit", Expr::shl(Expr::u32(1), Expr::var("depth"))),
                Node::let_bind(
                    "open_active",
                    Expr::and(
                        Expr::var("current_active"),
                        Expr::ne(Expr::var("value"), Expr::u32(0)),
                    ),
                ),
                Node::assign(
                    "active_bits",
                    Expr::bitor(
                        Expr::bitand(
                            Expr::var("active_bits"),
                            Expr::bitnot(Expr::var("open_bit")),
                        ),
                        Expr::select(
                            Expr::var("open_active"),
                            Expr::var("open_bit"),
                            Expr::u32(0),
                        ),
                    ),
                ),
                Node::assign(
                    "taken_bits",
                    Expr::bitor(
                        Expr::bitand(Expr::var("taken_bits"), Expr::bitnot(Expr::var("open_bit"))),
                        Expr::select(
                            Expr::ne(Expr::var("value"), Expr::u32(0)),
                            Expr::var("open_bit"),
                            Expr::u32(0),
                        ),
                    ),
                ),
                Node::assign("depth", Expr::add(Expr::var("depth"), Expr::u32(1))),
            ],
        ),
        Node::if_then(
            Expr::eq(Expr::var("kind"), Expr::u32(TOK_PP_ELIF)),
            vec![
                Node::if_then(
                    Expr::eq(Expr::var("depth"), Expr::u32(0)),
                    vec![Node::trap(
                        Expr::var("i"),
                        "c-preprocess-elif-without-open-conditional",
                    )],
                ),
                Node::let_bind("slot_depth", Expr::sub(Expr::var("depth"), Expr::u32(1))),
                Node::let_bind("slot_bit", Expr::shl(Expr::u32(1), Expr::var("slot_depth"))),
                Node::let_bind(
                    "parent_active",
                    all_enclosing_active(Expr::var("active_bits"), Expr::var("slot_depth")),
                ),
                Node::let_bind(
                    "slot_taken",
                    Expr::ne(
                        Expr::bitand(Expr::var("taken_bits"), Expr::var("slot_bit")),
                        Expr::u32(0),
                    ),
                ),
                Node::let_bind(
                    "elif_active",
                    Expr::and(
                        Expr::and(
                            Expr::var("parent_active"),
                            Expr::not(Expr::var("slot_taken")),
                        ),
                        Expr::ne(Expr::var("value"), Expr::u32(0)),
                    ),
                ),
                Node::assign(
                    "active_bits",
                    Expr::bitor(
                        Expr::bitand(
                            Expr::var("active_bits"),
                            Expr::bitnot(Expr::var("slot_bit")),
                        ),
                        Expr::select(
                            Expr::var("elif_active"),
                            Expr::var("slot_bit"),
                            Expr::u32(0),
                        ),
                    ),
                ),
                Node::assign(
                    "taken_bits",
                    Expr::bitor(
                        Expr::var("taken_bits"),
                        Expr::select(
                            Expr::ne(Expr::var("value"), Expr::u32(0)),
                            Expr::var("slot_bit"),
                            Expr::u32(0),
                        ),
                    ),
                ),
            ],
        ),
        Node::if_then(
            Expr::eq(Expr::var("kind"), Expr::u32(TOK_PP_ELSE)),
            vec![
                Node::if_then(
                    Expr::eq(Expr::var("depth"), Expr::u32(0)),
                    vec![Node::trap(
                        Expr::var("i"),
                        "c-preprocess-else-without-open-conditional",
                    )],
                ),
                Node::let_bind(
                    "else_slot_depth",
                    Expr::sub(Expr::var("depth"), Expr::u32(1)),
                ),
                Node::let_bind(
                    "else_slot_bit",
                    Expr::shl(Expr::u32(1), Expr::var("else_slot_depth")),
                ),
                Node::let_bind(
                    "else_parent_active",
                    all_enclosing_active(Expr::var("active_bits"), Expr::var("else_slot_depth")),
                ),
                Node::let_bind(
                    "else_taken",
                    Expr::ne(
                        Expr::bitand(Expr::var("taken_bits"), Expr::var("else_slot_bit")),
                        Expr::u32(0),
                    ),
                ),
                Node::let_bind(
                    "else_active",
                    Expr::and(
                        Expr::var("else_parent_active"),
                        Expr::not(Expr::var("else_taken")),
                    ),
                ),
                Node::assign(
                    "active_bits",
                    Expr::bitor(
                        Expr::bitand(
                            Expr::var("active_bits"),
                            Expr::bitnot(Expr::var("else_slot_bit")),
                        ),
                        Expr::select(
                            Expr::var("else_active"),
                            Expr::var("else_slot_bit"),
                            Expr::u32(0),
                        ),
                    ),
                ),
                Node::assign(
                    "taken_bits",
                    Expr::bitor(Expr::var("taken_bits"), Expr::var("else_slot_bit")),
                ),
            ],
        ),
        Node::if_then(
            Expr::eq(Expr::var("kind"), Expr::u32(TOK_PP_ENDIF)),
            vec![
                Node::if_then(
                    Expr::eq(Expr::var("depth"), Expr::u32(0)),
                    vec![Node::trap(
                        Expr::var("i"),
                        "c-preprocess-endif-without-open-conditional",
                    )],
                ),
                Node::assign("depth", Expr::sub(Expr::var("depth"), Expr::u32(1))),
                Node::let_bind("close_bit", Expr::shl(Expr::u32(1), Expr::var("depth"))),
                Node::assign(
                    "active_bits",
                    Expr::bitand(
                        Expr::var("active_bits"),
                        Expr::bitnot(Expr::var("close_bit")),
                    ),
                ),
                Node::assign(
                    "taken_bits",
                    Expr::bitand(
                        Expr::var("taken_bits"),
                        Expr::bitnot(Expr::var("close_bit")),
                    ),
                ),
            ],
        ),
    ]);

    Program::wrapped(
        vec![
            BufferDecl::storage(tok_types, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_buffer_count),
            BufferDecl::storage(directive_kinds, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_buffer_count),
            BufferDecl::storage(directive_values, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_buffer_count),
            BufferDecl::storage(out_mask, 3, BufferAccess::ReadWrite, DataType::U32)
                .with_count(tok_buffer_count),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(
            "vyre-libs::parsing::opt_conditional_mask_with_directives",
            vec![Node::if_then(
                Expr::eq(t, Expr::u32(0)),
                vec![
                    Node::let_bind("depth", Expr::u32(0)),
                    Node::let_bind("active_bits", Expr::u32(0)),
                    Node::let_bind("taken_bits", Expr::u32(0)),
                    Node::loop_for("i", Expr::u32(0), num_tokens, per_token),
                    Node::if_then(
                        Expr::ne(Expr::var("depth"), Expr::u32(0)),
                        vec![Node::trap(
                            Expr::var("depth"),
                            "c-preprocess-unclosed-conditional-directive",
                        )],
                    ),
                ],
            )],
        )],
    )
    .with_entry_op_id("vyre-libs::parsing::opt_conditional_mask_with_directives")
    .with_non_composable_with_self(true)
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::parsing::opt_conditional_mask_with_directives",
        build: || opt_conditional_mask_with_directives(
            "tok_types", "directive_kinds", "directive_values", "out_mask", Expr::u32(3)
        ),
        test_inputs: Some(|| {
            vec![vec![
                vec![TOK_PREPROC, TOK_IDENTIFIER, TOK_PREPROC]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect(),
                vec![TOK_PP_IF, 0, TOK_PP_ENDIF]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect(),
                vec![0u32, 0, 0]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect(),
                vec![0u8; 4 * 3],
            ]]
        }),
        expected_output: Some(|| {
            vec![vec![
                vec![1u32, 0, 1]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect()
            ]]
        }),
    }
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::parsing::opt_dynamic_macro_expansion",
        build: || opt_dynamic_macro_expansion(
            "in_tok_types", "macro_keys", "macro_vals", "macro_sizes",
            "out_tok_types", "out_tok_counts", Expr::u32(4), 16
        ),
        test_inputs: Some(|| {
            let mut keys = vec![0u8; 4 * MACRO_TABLE_SLOTS as usize];
            for slot in 0..MACRO_TABLE_SLOTS as usize {
                keys[slot * 4..slot * 4 + 4].copy_from_slice(&EMPTY_MACRO_SLOT.to_le_bytes());
            }
            vec![vec![
                vec![0u8; 4 * 4],
                keys,
                vec![0u8; 4 * MACRO_TABLE_SLOTS as usize],
                vec![0u8; 4 * MACRO_TABLE_SLOTS as usize],
                vec![0u8; 4 * 16],
                vec![0u8; 4],
            ]]
        }),
        expected_output: Some(|| {
            let mut count = vec![0u8; 4];
            count.copy_from_slice(&4u32.to_le_bytes());
            vec![vec![vec![0u8; 4 * 16], count]]
        }),
    }
}
