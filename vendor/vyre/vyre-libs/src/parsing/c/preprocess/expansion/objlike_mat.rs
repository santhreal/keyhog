//! Materialized object-like macro expansion builder.

use crate::parsing::c::lex::tokens::*;
use crate::parsing::c::preprocess::materialization::*;
use vyre::ir::{Expr, Node};

use super::helpers::*;
use super::*;

pub(super) fn emit_materialized_object_like_replacement(
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
