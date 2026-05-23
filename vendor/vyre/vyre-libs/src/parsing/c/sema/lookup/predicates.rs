use crate::parsing::c::lex::tokens::{
    TOK_AUTO, TOK_CHAR_KW, TOK_COMMA, TOK_CONST, TOK_DOUBLE, TOK_ENUM, TOK_EXTERN, TOK_FLOAT_KW,
    TOK_INLINE, TOK_INT, TOK_LONG, TOK_LPAREN, TOK_REGISTER, TOK_RESTRICT, TOK_RPAREN,
    TOK_SEMICOLON, TOK_SHORT, TOK_SIGNED, TOK_STAR, TOK_STATIC, TOK_STRUCT, TOK_THREAD_LOCAL,
    TOK_TYPEDEF, TOK_UNION, TOK_UNSIGNED, TOK_VOID, TOK_VOLATILE,
};
use vyre::ir::Expr;

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

pub(super) fn tag_keyword(token: Expr) -> Expr {
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
pub(super) fn declaration_context(prev_tok: Expr) -> Expr {
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
