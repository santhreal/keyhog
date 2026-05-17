use super::super::*;
use crate::parsing::c::lex::tokens::*;
use vyre::ir::Expr;

pub(crate) fn is_gnu_typeof_symbol_hash(symbol_hash: Expr) -> Expr {
    C_GNU_TYPEOF_HASHES
        .iter()
        .copied()
        .fold(Expr::bool(false), |acc, hash| {
            Expr::or(acc, Expr::eq(symbol_hash.clone(), Expr::u32(hash)))
        })
}

pub(crate) fn is_typeof_operator_token(token: Expr, symbol_hash: Expr) -> Expr {
    Expr::or(
        Expr::or(
            Expr::eq(token.clone(), Expr::u32(TOK_GNU_TYPEOF)),
            Expr::eq(token.clone(), Expr::u32(TOK_GNU_TYPEOF_UNQUAL)),
        ),
        Expr::and(
            Expr::eq(token, Expr::u32(TOK_IDENTIFIER)),
            is_gnu_typeof_symbol_hash(symbol_hash),
        ),
    )
}

pub(crate) fn is_gnu_auto_type_symbol_hash(symbol_hash: Expr) -> Expr {
    Expr::eq(symbol_hash, Expr::u32(C_GNU_AUTO_TYPE_HASH))
}

pub(crate) fn c_attribute_kind_from_hash(symbol_hash: Expr) -> Expr {
    C_ATTRIBUTE_KIND_HASHES
        .iter()
        .rev()
        .fold(Expr::u32(0), |fallback, (hash, kind)| {
            Expr::select(
                Expr::eq(symbol_hash.clone(), Expr::u32(*hash)),
                Expr::u32(*kind),
                fallback,
            )
        })
}
