//! Audit-fix A35 `expansion/objlike.rs` extract.

use crate::parsing::c::lex::tokens::*;
use vyre::ir::{Expr, Node};

use super::helpers::*;
use super::*;

pub(super) fn emit_object_like_replacement(
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
