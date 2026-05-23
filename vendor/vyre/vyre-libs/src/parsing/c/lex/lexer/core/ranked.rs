use super::*;
use crate::parsing::c::lex::lexer::sections;

pub fn c11_lexer_regular_ranked(
    haystack: &str,
    out_tok_types: &str,
    out_tok_starts: &str,
    out_tok_lens: &str,
    out_counts: &str,
    haystack_len: u32,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let byte_at = |index: Expr| byte_at_or_zero(haystack, index, haystack_len);
    let is_space = |value: Expr| {
        Expr::or(
            byte_eq(value.clone(), b' '),
            Expr::or(
                byte_eq(value.clone(), b'\n'),
                Expr::or(byte_eq(value.clone(), b'\r'), byte_eq(value, b'\t')),
            ),
        )
    };
    let is_operator_tail = |index: Expr| {
        let b = byte_at(index.clone());
        let prev = Expr::select(
            Expr::gt(index.clone(), Expr::u32(0)),
            byte_at(Expr::saturating_sub(index.clone(), Expr::u32(1))),
            Expr::u32(0),
        );
        let prev2 = Expr::select(
            Expr::gt(index.clone(), Expr::u32(1)),
            byte_at(Expr::saturating_sub(index.clone(), Expr::u32(2))),
            Expr::u32(0),
        );
        Expr::or(
            Expr::and(byte_eq(b.clone(), b'>'), byte_eq(prev.clone(), b'-')),
            Expr::or(
                Expr::and(
                    byte_eq(b.clone(), b'='),
                    Expr::or(
                        byte_eq(prev.clone(), b'+'),
                        Expr::or(
                            byte_eq(prev.clone(), b'-'),
                            Expr::or(
                                byte_eq(prev.clone(), b'*'),
                                Expr::or(
                                    byte_eq(prev.clone(), b'/'),
                                    Expr::or(
                                        byte_eq(prev.clone(), b'%'),
                                        Expr::or(
                                            byte_eq(prev.clone(), b'&'),
                                            Expr::or(
                                                byte_eq(prev.clone(), b'|'),
                                                Expr::or(
                                                    byte_eq(prev.clone(), b'^'),
                                                    Expr::or(
                                                        byte_eq(prev.clone(), b'='),
                                                        Expr::or(
                                                            byte_eq(prev.clone(), b'!'),
                                                            Expr::or(
                                                                byte_eq(prev.clone(), b'<'),
                                                                byte_eq(prev.clone(), b'>'),
                                                            ),
                                                        ),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
                Expr::or(
                    Expr::and(byte_eq(b.clone(), b'+'), byte_eq(prev.clone(), b'+')),
                    Expr::or(
                        Expr::and(byte_eq(b.clone(), b'-'), byte_eq(prev.clone(), b'-')),
                        Expr::or(
                            Expr::and(byte_eq(b.clone(), b'&'), byte_eq(prev.clone(), b'&')),
                            Expr::or(
                                Expr::and(byte_eq(b.clone(), b'|'), byte_eq(prev.clone(), b'|')),
                                Expr::or(
                                    Expr::and(
                                        byte_eq(b.clone(), b'<'),
                                        byte_eq(prev.clone(), b'<'),
                                    ),
                                    Expr::or(
                                        Expr::and(
                                            byte_eq(b.clone(), b'>'),
                                            byte_eq(prev.clone(), b'>'),
                                        ),
                                        Expr::and(
                                            byte_eq(b, b'='),
                                            Expr::or(
                                                Expr::and(
                                                    byte_eq(prev.clone(), b'<'),
                                                    byte_eq(prev2.clone(), b'<'),
                                                ),
                                                Expr::and(
                                                    byte_eq(prev, b'>'),
                                                    byte_eq(prev2, b'>'),
                                                ),
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
    };
    let is_token_start_at = |index: Expr| {
        let b = byte_at(index.clone());
        let prev = Expr::select(
            Expr::gt(index.clone(), Expr::u32(0)),
            byte_at(Expr::saturating_sub(index.clone(), Expr::u32(1))),
            Expr::u32(0),
        );
        Expr::and(
            Expr::lt(index.clone(), Expr::buf_len(haystack)),
            Expr::and(
                Expr::not(is_space(b.clone())),
                Expr::and(
                    Expr::not(Expr::and(is_ident_continue(b), is_ident_continue(prev))),
                    Expr::not(is_operator_tail(index)),
                ),
            ),
        )
    };

    let mut classify_at_pos = vec![
        Node::let_bind("pos", t.clone()),
        Node::let_bind("byte", byte_at(t.clone())),
        Node::let_bind(
            "prev_byte",
            Expr::select(
                Expr::gt(t.clone(), Expr::u32(0)),
                byte_at(Expr::saturating_sub(t.clone(), Expr::u32(1))),
                Expr::u32(0),
            ),
        ),
        Node::let_bind("next_byte", byte_at(Expr::add(t.clone(), Expr::u32(1)))),
        Node::let_bind("next2_byte", byte_at(Expr::add(t.clone(), Expr::u32(2)))),
        Node::let_bind("emit", Expr::u32(0)),
        Node::let_bind("tok_type", Expr::u32(TOK_WHITESPACE)),
        Node::let_bind("tok_len", Expr::u32(1)),
        Node::let_bind("rank", Expr::u32(0)),
        Node::loop_for(
            "rank_scan",
            Expr::u32(0),
            t.clone(),
            vec![Node::if_then(
                is_token_start_at(Expr::var("rank_scan")),
                vec![Node::assign(
                    "rank",
                    Expr::add(Expr::var("rank"), Expr::u32(1)),
                )],
            )],
        ),
    ];

    classify_at_pos.push(set_token(
        Expr::and(
            is_ident_start(Expr::var("byte")),
            Expr::not(is_ident_continue(Expr::var("prev_byte"))),
        ),
        TOK_IDENTIFIER,
        Expr::u32(1),
    ));
    classify_at_pos.push(Node::if_then(
        Expr::eq(Expr::var("tok_type"), Expr::u32(TOK_IDENTIFIER)),
        vec![
            Node::let_bind("ranked_ident_done", Expr::u32(0)),
            Node::loop_for(
                "ranked_scan_ident",
                Expr::add(Expr::var("pos"), Expr::u32(1)),
                scan_upper_bound_with_cap(
                    haystack,
                    Expr::add(Expr::var("pos"), Expr::u32(1)),
                    MAX_IDENT_SCAN,
                ),
                vec![Node::if_then(
                    Expr::eq(Expr::var("ranked_ident_done"), Expr::u32(0)),
                    vec![
                        Node::let_bind("scan_byte", byte_at(Expr::var("ranked_scan_ident"))),
                        Node::if_then_else(
                            is_ident_continue(Expr::var("scan_byte")),
                            vec![Node::assign(
                                "tok_len",
                                Expr::add(Expr::var("tok_len"), Expr::u32(1)),
                            )],
                            vec![Node::assign("ranked_ident_done", Expr::u32(1))],
                        ),
                    ],
                )],
            ),
        ],
    ));
    classify_at_pos.push(set_token(
        Expr::and(
            is_digit(Expr::var("byte")),
            Expr::not(is_ident_continue(Expr::var("prev_byte"))),
        ),
        TOK_INTEGER,
        Expr::u32(1),
    ));
    classify_at_pos.push(Node::if_then(
        Expr::eq(Expr::var("tok_type"), Expr::u32(TOK_INTEGER)),
        vec![
            Node::let_bind("ranked_number_done", Expr::u32(0)),
            Node::loop_for(
                "ranked_scan_number",
                Expr::add(Expr::var("pos"), Expr::u32(1)),
                scan_upper_bound_with_cap(
                    haystack,
                    Expr::add(Expr::var("pos"), Expr::u32(1)),
                    MAX_NUMBER_SCAN,
                ),
                vec![Node::if_then(
                    Expr::eq(Expr::var("ranked_number_done"), Expr::u32(0)),
                    vec![
                        Node::let_bind("scan_byte", byte_at(Expr::var("ranked_scan_number"))),
                        Node::if_then_else(
                            is_digit(Expr::var("scan_byte")),
                            vec![Node::assign(
                                "tok_len",
                                Expr::add(Expr::var("tok_len"), Expr::u32(1)),
                            )],
                            vec![Node::assign("ranked_number_done", Expr::u32(1))],
                        ),
                    ],
                )],
            ),
        ],
    ));
    classify_at_pos.extend(sections::operator_punct_pushes());
    classify_at_pos.push(Node::if_then(
        Expr::eq(Expr::var("emit"), Expr::u32(1)),
        vec![
            Node::store(out_tok_types, Expr::var("rank"), Expr::var("tok_type")),
            Node::store(out_tok_starts, Expr::var("rank"), Expr::var("pos")),
            Node::store(out_tok_lens, Expr::var("rank"), Expr::var("tok_len")),
        ],
    ));

    Program::wrapped(
        vec![
            BufferDecl::storage(haystack, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(haystack_len.max(1)),
            BufferDecl::storage(out_tok_types, 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(haystack_len.max(1)),
            BufferDecl::storage(out_tok_starts, 2, BufferAccess::ReadWrite, DataType::U32)
                .with_count(haystack_len.max(1)),
            BufferDecl::storage(out_tok_lens, 3, BufferAccess::ReadWrite, DataType::U32)
                .with_count(haystack_len.max(1)),
            BufferDecl::storage(out_counts, 4, BufferAccess::ReadWrite, DataType::U32)
                .with_count(1),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(
            "vyre-libs::parsing::c_lexer_regular_ranked",
            vec![
                Node::if_then(
                    Expr::lt(t.clone(), Expr::buf_len(haystack)),
                    vec![Node::if_then(is_token_start_at(t.clone()), classify_at_pos)],
                ),
                Node::if_then(
                    Expr::eq(t, Expr::u32(0)),
                    vec![
                        Node::let_bind("token_count", Expr::u32(0)),
                        Node::loop_for(
                            "count_scan",
                            Expr::u32(0),
                            Expr::buf_len(haystack),
                            vec![Node::if_then(
                                is_token_start_at(Expr::var("count_scan")),
                                vec![Node::assign(
                                    "token_count",
                                    Expr::add(Expr::var("token_count"), Expr::u32(1)),
                                )],
                            )],
                        ),
                        Node::store(out_counts, Expr::u32(0), Expr::var("token_count")),
                    ],
                ),
            ],
        )],
    )
    .with_entry_op_id("vyre-libs::parsing::c_lexer_regular_ranked")
    .with_non_composable_with_self(true)
}
