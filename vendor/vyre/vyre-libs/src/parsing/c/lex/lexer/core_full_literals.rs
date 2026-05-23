#![allow(missing_docs)]
use crate::parsing::c::lex::tokens::*;
use vyre::ir::{Expr, Node};

use super::helpers::{ascii, byte_eq, byte_load, is_valid_escape_byte, set_token};

pub(super) fn full_literal_pushes(haystack: &str, haystack_len: u32) -> Vec<Node> {
    let mut nodes = Vec::new();



    nodes.push(set_token(
        byte_eq(Expr::var("byte"), b'"'),
        TOK_STRING,
        Expr::u32(1),
    ));
    nodes.push(set_token(
        byte_eq(Expr::var("byte"), b'\''),
        TOK_CHAR,
        Expr::u32(1),
    ));
    nodes.push(Node::if_then(
        Expr::or(
            Expr::eq(Expr::var("tok_type"), Expr::u32(TOK_STRING)),
            Expr::eq(Expr::var("tok_type"), Expr::u32(TOK_CHAR)),
        ),
        vec![
            Node::let_bind(
                "literal_quote_offset",
                Expr::select(
                    Expr::or(
                        byte_eq(Expr::var("byte"), b'"'),
                        byte_eq(Expr::var("byte"), b'\''),
                    ),
                    Expr::u32(0),
                    Expr::select(
                        Expr::and(
                            byte_eq(Expr::var("byte"), b'u'),
                            byte_eq(Expr::var("next_byte"), b'8'),
                        ),
                        Expr::u32(2),
                        Expr::u32(1),
                    ),
                ),
            ),
            Node::let_bind(
                "quote",
                byte_load(
                    haystack,
                    Expr::add(Expr::var("pos"), Expr::var("literal_quote_offset")),
                ),
            ),
            Node::let_bind("literal_done", Expr::u32(0)),
            Node::let_bind("escaped", Expr::u32(0)),
            Node::let_bind("literal_unterminated", Expr::u32(0)),
            Node::let_bind("invalid_escape", Expr::u32(0)),
            Node::loop_for(
                "scan_literal",
                Expr::add(
                    Expr::add(Expr::var("pos"), Expr::var("literal_quote_offset")),
                    Expr::u32(1),
                ),
                Expr::buf_len("haystack"),
                vec![Node::if_then(
                    Expr::eq(Expr::var("literal_done"), Expr::u32(0)),
                    vec![
                        Node::assign("tok_len", Expr::add(Expr::var("tok_len"), Expr::u32(1))),
                        Node::let_bind("scan_byte", byte_load(haystack, Expr::var("scan_literal"))),
                        Node::if_then_else(
                            Expr::eq(Expr::var("escaped"), Expr::u32(1)),
                            vec![
                                Node::if_then(
                                    Expr::not(is_valid_escape_byte(
                                        haystack,
                                        Expr::var("scan_literal"),
                                        Expr::var("scan_byte"),
                                        haystack_len,
                                    )),
                                    vec![Node::assign("invalid_escape", Expr::u32(1))],
                                ),
                                Node::assign("escaped", Expr::u32(0)),
                            ],
                            vec![Node::if_then_else(
                                byte_eq(Expr::var("scan_byte"), b'\\'),
                                vec![Node::assign("escaped", Expr::u32(1))],
                                vec![Node::if_then_else(
                                    Expr::eq(Expr::var("scan_byte"), Expr::var("quote")),
                                    vec![Node::assign("literal_done", Expr::u32(1))],
                                    vec![Node::if_then(
                                        Expr::or(
                                            byte_eq(Expr::var("scan_byte"), b'\n'),
                                            byte_eq(Expr::var("scan_byte"), b'\r'),
                                        ),
                                        vec![
                                            Node::assign("literal_unterminated", Expr::u32(1)),
                                            Node::assign("literal_done", Expr::u32(1)),
                                        ],
                                    )],
                                )],
                            )],
                        ),
                    ],
                )],
            ),
            Node::if_then(
                Expr::eq(Expr::var("literal_done"), Expr::u32(0)),
                vec![Node::assign("literal_unterminated", Expr::u32(1))],
            ),
            Node::if_then(
                Expr::eq(Expr::var("literal_unterminated"), Expr::u32(1)),
                vec![Node::assign(
                    "tok_type",
                    Expr::select(
                        Expr::eq(Expr::var("quote"), ascii(b'"')),
                        Expr::u32(TOK_ERR_UNTERMINATED_STRING),
                        Expr::u32(TOK_ERR_UNTERMINATED_CHAR),
                    ),
                )],
            ),
            Node::if_then(
                Expr::and(
                    Expr::eq(Expr::var("literal_unterminated"), Expr::u32(0)),
                    Expr::eq(Expr::var("invalid_escape"), Expr::u32(1)),
                ),
                vec![Node::assign("tok_type", Expr::u32(TOK_ERR_INVALID_ESCAPE))],
            ),
        ],
    ));
    nodes
}

pub(super) fn full_prefixed_literal_pushes() -> Vec<Node> {
    let mut nodes = Vec::new();



    nodes.push(set_token(
        Expr::or(
            Expr::and(
                Expr::or(
                    byte_eq(Expr::var("byte"), b'L'),
                    Expr::or(
                        byte_eq(Expr::var("byte"), b'u'),
                        byte_eq(Expr::var("byte"), b'U'),
                    ),
                ),
                byte_eq(Expr::var("next_byte"), b'"'),
            ),
            Expr::and(
                Expr::and(
                    byte_eq(Expr::var("byte"), b'u'),
                    byte_eq(Expr::var("next_byte"), b'8'),
                ),
                byte_eq(Expr::var("next2_byte"), b'"'),
            ),
        ),
        TOK_STRING,
        Expr::select(
            Expr::and(
                byte_eq(Expr::var("byte"), b'u'),
                byte_eq(Expr::var("next_byte"), b'8'),
            ),
            Expr::u32(3),
            Expr::u32(2),
        ),
    ));
    nodes.push(set_token(
        Expr::or(
            Expr::and(
                Expr::or(
                    byte_eq(Expr::var("byte"), b'L'),
                    Expr::or(
                        byte_eq(Expr::var("byte"), b'u'),
                        byte_eq(Expr::var("byte"), b'U'),
                    ),
                ),
                byte_eq(Expr::var("next_byte"), b'\''),
            ),
            Expr::and(
                Expr::and(
                    byte_eq(Expr::var("byte"), b'u'),
                    byte_eq(Expr::var("next_byte"), b'8'),
                ),
                byte_eq(Expr::var("next2_byte"), b'\''),
            ),
        ),
        TOK_CHAR,
        Expr::select(
            Expr::and(
                byte_eq(Expr::var("byte"), b'u'),
                byte_eq(Expr::var("next_byte"), b'8'),
            ),
            Expr::u32(3),
            Expr::u32(2),
        ),
    ));
    nodes
}
