use super::super::*;
use super::*;
use crate::parsing::c::lex::tokens::*;
use vyre::ir::Expr;

pub(crate) fn is_type_name_start_token(token: Expr) -> Expr {
    any_token_eq(
        token,
        &[
            TOK_CONST,
            TOK_RESTRICT,
            TOK_VOLATILE,
            TOK_STRUCT,
            TOK_UNION,
            TOK_ENUM,
            TOK_VOID,
            TOK_CHAR_KW,
            TOK_INT,
            TOK_LONG,
            TOK_SHORT,
            TOK_SIGNED,
            TOK_UNSIGNED,
            TOK_FLOAT_KW,
            TOK_DOUBLE,
            TOK_BOOL,
            TOK_COMPLEX,
            TOK_IMAGINARY,
            TOK_ATOMIC,
            TOK_GNU_TYPEOF,
            TOK_GNU_TYPEOF_UNQUAL,
            TOK_GNU_INT128,
            TOK_GNU_BUILTIN_VA_LIST,
        ],
    )
}

pub(crate) fn is_decl_prefix_token(token: Expr) -> Expr {
    any_token_eq(
        token,
        &[
            TOK_TYPEDEF,
            TOK_EXTERN,
            TOK_STATIC,
            TOK_INLINE,
            TOK_CONST,
            TOK_RESTRICT,
            TOK_VOLATILE,
            TOK_STRUCT,
            TOK_UNION,
            TOK_ENUM,
            TOK_VOID,
            TOK_CHAR_KW,
            TOK_INT,
            TOK_LONG,
            TOK_SHORT,
            TOK_SIGNED,
            TOK_UNSIGNED,
            TOK_FLOAT_KW,
            TOK_DOUBLE,
            TOK_BOOL,
            TOK_COMPLEX,
            TOK_IMAGINARY,
            TOK_ALIGNAS,
            TOK_ATOMIC,
            TOK_NORETURN,
            TOK_STATIC_ASSERT,
            TOK_THREAD_LOCAL,
            TOK_GNU_TYPEOF,
            TOK_GNU_TYPEOF_UNQUAL,
            TOK_GNU_AUTO_TYPE,
            TOK_GNU_INT128,
            TOK_GNU_BUILTIN_VA_LIST,
            TOK_GNU_ADDRESS_SPACE,
            TOK_GNU_EXTENSION,
        ],
    )
}

pub(crate) fn is_decl_prefix_token_or_gnu_type_hash(token: Expr, symbol_hash: Expr) -> Expr {
    Expr::or(
        is_decl_prefix_token(token.clone()),
        Expr::or(
            is_typeof_operator_token(token.clone(), symbol_hash.clone()),
            Expr::and(
                Expr::eq(token, Expr::u32(TOK_IDENTIFIER)),
                is_gnu_auto_type_symbol_hash(symbol_hash),
            ),
        ),
    )
}

pub(crate) fn is_decl_prefix_reset_token(token: Expr) -> Expr {
    any_token_eq(
        token,
        &[TOK_SEMICOLON, TOK_LBRACE, TOK_RBRACE, TOK_ASSIGN, TOK_COLON],
    )
}

pub(crate) fn is_typedef_name_annotation(flags: Expr) -> Expr {
    Expr::ne(
        Expr::bitand(flags, Expr::u32(C_TYPEDEF_FLAG_VISIBLE_TYPEDEF_NAME)),
        Expr::u32(0),
    )
}

pub(crate) fn is_typedef_declarator_annotation(flags: Expr) -> Expr {
    Expr::ne(
        Expr::bitand(flags, Expr::u32(C_TYPEDEF_FLAG_TYPEDEF_DECLARATOR)),
        Expr::u32(0),
    )
}

pub(crate) fn is_ordinary_declarator_annotation(flags: Expr) -> Expr {
    Expr::ne(
        Expr::bitand(flags, Expr::u32(C_TYPEDEF_FLAG_ORDINARY_DECLARATOR)),
        Expr::u32(0),
    )
}

pub(crate) fn is_type_name_identifier(flags: Expr, fallback_has_prior_typedef: Expr) -> Expr {
    Expr::or(
        is_typedef_name_annotation(flags),
        fallback_has_prior_typedef,
    )
}

pub(crate) fn is_aggregate_specifier_body_open(
    open_kind: Expr,
    prev_kind: Expr,
    prev_prev_kind: Expr,
) -> Expr {
    Expr::and(
        Expr::eq(open_kind, Expr::u32(TOK_LBRACE)),
        Expr::or(
            any_token_eq(prev_kind.clone(), &[TOK_STRUCT, TOK_UNION, TOK_ENUM]),
            Expr::and(
                Expr::eq(prev_kind, Expr::u32(TOK_IDENTIFIER)),
                any_token_eq(prev_prev_kind, &[TOK_STRUCT, TOK_UNION, TOK_ENUM]),
            ),
        ),
    )
}
