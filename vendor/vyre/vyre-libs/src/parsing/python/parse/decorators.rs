use super::{find_matching_delimiter, load_u32, search_next_token};
use crate::parsing::python::lex::{
    TOK_ASYNC, TOK_AT, TOK_CLASS, TOK_DEF, TOK_DOT, TOK_IDENTIFIER, TOK_LPAREN, TOK_RPAREN,
};
use crate::parsing::python::{DECORATOR_RECORD_WORDS, INVALID_POS, MAX_DOTTED_SEGMENTS};
use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

fn store_words(buffer: &str, base_var: &str, words: &[Expr]) -> Vec<Node> {
    words
        .iter()
        .enumerate()
        .map(|(idx, value)| {
            Node::store(
                buffer,
                Expr::add(Expr::var(base_var), Expr::u32(idx as u32)),
                value.clone(),
            )
        })
        .collect()
}

/// Extract decorator occurrences and their immediate target.
#[must_use]
pub fn python312_extract_decorators(
    tok_types: &str,
    tok_starts: &str,
    tok_lens: &str,
    out_records: &str,
    out_counts: &str,
    haystack_len: u32,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let mut body = Vec::new();
    body.extend(search_next_token(
        "decorator_name",
        Expr::add(t.clone(), Expr::u32(1)),
        tok_types,
        haystack_len,
    ));
    body.push(Node::let_bind("tok", load_u32(tok_types, t.clone())));
    body.push(Node::if_then(
        Expr::and(
            Expr::eq(Expr::var("tok"), Expr::u32(TOK_AT)),
            Expr::eq(
                load_u32(tok_types, Expr::var("decorator_name")),
                Expr::u32(TOK_IDENTIFIER),
            ),
        ),
        vec![
            Node::let_bind("decorator_end", Expr::var("decorator_name")),
            Node::let_bind("cursor", Expr::var("decorator_name")),
            Node::loop_for(
                "seg",
                Expr::u32(0),
                Expr::u32(MAX_DOTTED_SEGMENTS),
                vec![
                    Node::let_bind("dot_pos", Expr::u32(INVALID_POS)),
                    Node::let_bind("after_dot", Expr::u32(INVALID_POS)),
                ]
                .into_iter()
                .chain(search_next_token(
                    "dot_pos",
                    Expr::add(Expr::var("cursor"), Expr::u32(1)),
                    tok_types,
                    haystack_len,
                ))
                .chain(vec![Node::if_then(
                    Expr::eq(
                        load_u32(tok_types, Expr::var("dot_pos")),
                        Expr::u32(TOK_DOT),
                    ),
                    search_next_token(
                        "after_dot",
                        Expr::add(Expr::var("dot_pos"), Expr::u32(1)),
                        tok_types,
                        haystack_len,
                    ),
                )])
                .chain(vec![
                    Node::if_then(
                        Expr::eq(
                            load_u32(tok_types, Expr::var("after_dot")),
                            Expr::u32(TOK_IDENTIFIER),
                        ),
                        vec![
                            Node::assign("decorator_end", Expr::var("after_dot")),
                            Node::assign("cursor", Expr::var("after_dot")),
                        ],
                    ),
                    Node::if_then(
                        Expr::ne(
                            load_u32(tok_types, Expr::var("after_dot")),
                            Expr::u32(TOK_IDENTIFIER),
                        ),
                        vec![Node::assign("cursor", Expr::u32(INVALID_POS))],
                    ),
                ])
                .collect(),
            ),
        ]
        .into_iter()
        .chain(search_next_token(
            "after_decorator",
            Expr::add(Expr::var("decorator_end"), Expr::u32(1)),
            tok_types,
            haystack_len,
        ))
        .chain(find_matching_delimiter(
            "decorator_rparen",
            Expr::var("after_decorator"),
            tok_types,
            haystack_len,
            TOK_LPAREN,
            TOK_RPAREN,
        ))
        .chain(vec![Node::if_then_else(
            Expr::eq(
                load_u32(tok_types, Expr::var("after_decorator")),
                Expr::u32(TOK_LPAREN),
            ),
            search_next_token(
                "target_tok",
                Expr::add(Expr::var("decorator_rparen"), Expr::u32(1)),
                tok_types,
                haystack_len,
            ),
            search_next_token(
                "target_tok",
                Expr::add(Expr::var("decorator_end"), Expr::u32(1)),
                tok_types,
                haystack_len,
            ),
        )])
        .chain(vec![
            Node::let_bind("target_name", Expr::u32(INVALID_POS)),
            Node::let_bind("target_kind", Expr::u32(0)),
            Node::if_then(
                Expr::eq(
                    load_u32(tok_types, Expr::var("target_tok")),
                    Expr::u32(TOK_DEF),
                ),
                vec![
                    Node::assign("target_kind", Expr::u32(1)),
                    Node::assign("target_name", Expr::u32(INVALID_POS)),
                ]
                .into_iter()
                .chain(search_next_token(
                    "target_name",
                    Expr::add(Expr::var("target_tok"), Expr::u32(1)),
                    tok_types,
                    haystack_len,
                ))
                .collect(),
            ),
            Node::if_then(
                Expr::eq(
                    load_u32(tok_types, Expr::var("target_tok")),
                    Expr::u32(TOK_CLASS),
                ),
                vec![
                    Node::assign("target_kind", Expr::u32(3)),
                    Node::assign("target_name", Expr::u32(INVALID_POS)),
                ]
                .into_iter()
                .chain(search_next_token(
                    "target_name",
                    Expr::add(Expr::var("target_tok"), Expr::u32(1)),
                    tok_types,
                    haystack_len,
                ))
                .collect(),
            ),
            Node::if_then(
                Expr::eq(
                    load_u32(tok_types, Expr::var("target_tok")),
                    Expr::u32(TOK_ASYNC),
                ),
                vec![
                    Node::assign("target_kind", Expr::u32(2)),
                    Node::assign("target_name", Expr::u32(INVALID_POS)),
                ]
                .into_iter()
                .chain(search_next_token(
                    "async_def",
                    Expr::add(Expr::var("target_tok"), Expr::u32(1)),
                    tok_types,
                    haystack_len,
                ))
                .chain(search_next_token(
                    "target_name",
                    Expr::add(Expr::var("async_def"), Expr::u32(1)),
                    tok_types,
                    haystack_len,
                ))
                .collect(),
            ),
            Node::let_bind(
                "slot",
                Expr::atomic_add(out_counts, Expr::u32(0), Expr::u32(DECORATOR_RECORD_WORDS)),
            ),
        ])
        .chain(store_words(
            out_records,
            "slot",
            &[
                load_u32(tok_starts, Expr::var("decorator_name")),
                Expr::add(
                    Expr::sub(
                        load_u32(tok_starts, Expr::var("decorator_end")),
                        load_u32(tok_starts, Expr::var("decorator_name")),
                    ),
                    load_u32(tok_lens, Expr::var("decorator_end")),
                ),
                Expr::var("target_kind"),
                load_u32(tok_starts, Expr::var("target_name")),
                load_u32(tok_lens, Expr::var("target_name")),
                Expr::var("target_tok"),
            ],
        ))
        .collect(),
    ));

    Program::wrapped(
        vec![
            BufferDecl::storage(tok_types, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(haystack_len),
            BufferDecl::storage(tok_starts, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(haystack_len),
            BufferDecl::storage(tok_lens, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(haystack_len),
            BufferDecl::storage(out_records, 3, BufferAccess::ReadWrite, DataType::U32)
                .with_count(haystack_len.saturating_mul(DECORATOR_RECORD_WORDS)),
            BufferDecl::storage(out_counts, 4, BufferAccess::ReadWrite, DataType::U32)
                .with_count(1),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(
            "vyre-libs::parsing::python312_extract_decorators",
            vec![Node::if_then(
                Expr::lt(t.clone(), Expr::u32(haystack_len)),
                body,
            )],
        )],
    )
    .with_entry_op_id("vyre-libs::parsing::python312_extract_decorators")
    .with_non_composable_with_self(true)
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::parsing::python312_extract_decorators",
        build: || python312_extract_decorators("tok_types", "tok_starts", "tok_lens", "out_records", "out_counts", 16),
        test_inputs: Some(|| vec![vec![
            vec![0u8; 16 * 4],
            vec![0u8; 16 * 4],
            vec![0u8; 16 * 4],
            vec![0u8; 16 * DECORATOR_RECORD_WORDS as usize * 4],
            vec![0u8; 4],
        ]]),
        expected_output: Some(|| vec![vec![
            vec![0u8; 16 * DECORATOR_RECORD_WORDS as usize * 4],
            vec![0u8; 4],
        ]]),
    }
}
