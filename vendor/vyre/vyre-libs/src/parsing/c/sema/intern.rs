use crate::parsing::c::lex::tokens::TOK_IDENTIFIER;
use vyre::ir::{Expr, Node};

/// Emit IR that interns an identifier token by hashing its source bytes.
pub fn emit_identifier_intern(
    tok_starts: &str,
    tok_lens: &str,
    haystack: &str,
    node_idx: Expr,
) -> Vec<Node> {
    vec![
        Node::let_bind("identifier_intern_id", Expr::u32(0)),
        Node::if_then(
            Expr::eq(Expr::var("tok_type"), Expr::u32(TOK_IDENTIFIER)),
            vec![
                Node::let_bind("start", Expr::load(tok_starts, node_idx.clone())),
                Node::let_bind("len", Expr::load(tok_lens, node_idx)),
                Node::let_bind("hash", Expr::u32(0x811c_9dc5)),
                Node::loop_for(
                    "intern_scan",
                    Expr::u32(0),
                    Expr::var("len"),
                    vec![
                        Node::let_bind(
                            "byte",
                            Expr::load(
                                haystack,
                                Expr::add(Expr::var("start"), Expr::var("intern_scan")),
                            ),
                        ),
                        Node::assign("hash", Expr::bitxor(Expr::var("hash"), Expr::var("byte"))),
                        Node::assign("hash", Expr::mul(Expr::var("hash"), Expr::u32(0x0100_0193))),
                    ],
                ),
                Node::assign("identifier_intern_id", Expr::var("hash")),
            ],
        ),
    ]
}
