use crate::parsing::c::lex::tokens::*;
use vyre::ir::{Expr, Node};

pub(super) fn byte_load(buffer: &str, index: Expr) -> Expr {
    Expr::bitand(Expr::load(buffer, index), Expr::u32(0xFF))
}

pub(super) fn ascii(byte: u8) -> Expr {
    Expr::u32(u32::from(byte))
}

pub(super) fn byte_eq(value: Expr, byte: u8) -> Expr {
    Expr::eq(value, ascii(byte))
}

pub(super) fn byte_at_or_zero(haystack: &str, index: Expr, haystack_len: u32) -> Expr {
    Expr::select(
        Expr::lt(index.clone(), Expr::u32(haystack_len)),
        byte_load(haystack, index),
        Expr::u32(0),
    )
}

pub(super) fn byte_between(value: Expr, low: u8, high: u8) -> Expr {
    Expr::and(
        Expr::ge(value.clone(), ascii(low)),
        Expr::le(value, ascii(high)),
    )
}

pub(super) fn is_alpha(value: Expr) -> Expr {
    Expr::or(
        byte_between(value.clone(), b'a', b'z'),
        byte_between(value, b'A', b'Z'),
    )
}

pub(super) fn is_digit(value: Expr) -> Expr {
    byte_between(value, b'0', b'9')
}

pub(super) fn is_octal_digit(value: Expr) -> Expr {
    byte_between(value, b'0', b'7')
}

pub(super) fn is_hex_digit(value: Expr) -> Expr {
    Expr::or(
        is_digit(value.clone()),
        Expr::or(
            byte_between(value.clone(), b'a', b'f'),
            byte_between(value, b'A', b'F'),
        ),
    )
}

pub(super) fn has_hex_digits_after(
    haystack: &str,
    escape_pos: Expr,
    digits: u32,
    haystack_len: u32,
) -> Expr {
    let mut expr = Expr::bool(true);
    for offset in 1..=digits {
        expr = Expr::and(
            expr,
            is_hex_digit(byte_at_or_zero(
                haystack,
                Expr::add(escape_pos.clone(), Expr::u32(offset)),
                haystack_len,
            )),
        );
    }
    expr
}

pub(super) fn is_valid_escape_byte(
    haystack: &str,
    escape_pos: Expr,
    escaped_byte: Expr,
    haystack_len: u32,
) -> Expr {
    let simple_escape = [
        b'\'', b'"', b'?', b'\\', b'a', b'b', b'f', b'n', b'r', b't', b'v', b'\n', b'\r',
    ]
    .into_iter()
    .fold(Expr::bool(false), |acc, byte| {
        Expr::or(acc, byte_eq(escaped_byte.clone(), byte))
    });

    Expr::or(
        simple_escape,
        Expr::or(
            is_octal_digit(escaped_byte.clone()),
            Expr::or(
                Expr::and(
                    Expr::or(
                        byte_eq(escaped_byte.clone(), b'x'),
                        byte_eq(escaped_byte.clone(), b'X'),
                    ),
                    has_hex_digits_after(haystack, escape_pos.clone(), 1, haystack_len),
                ),
                Expr::or(
                    Expr::and(
                        byte_eq(escaped_byte.clone(), b'u'),
                        has_hex_digits_after(haystack, escape_pos.clone(), 4, haystack_len),
                    ),
                    Expr::and(
                        byte_eq(escaped_byte, b'U'),
                        has_hex_digits_after(haystack, escape_pos, 8, haystack_len),
                    ),
                ),
            ),
        ),
    )
}

pub(super) fn is_ident_start(value: Expr) -> Expr {
    Expr::or(is_alpha(value.clone()), byte_eq(value, b'_'))
}

pub(super) fn is_ident_continue(value: Expr) -> Expr {
    Expr::or(is_ident_start(value.clone()), is_digit(value))
}

pub(super) fn keyword_match(haystack: &str, base: Expr, word: &[u8]) -> Expr {
    let mut expr = Expr::eq(Expr::var("tok_len"), Expr::u32(word.len() as u32));
    for (offset, byte) in word.iter().enumerate() {
        expr = Expr::and(
            expr,
            Expr::eq(
                byte_load(haystack, Expr::add(base.clone(), Expr::u32(offset as u32))),
                ascii(*byte),
            ),
        );
    }
    expr
}

pub(super) fn classify_keyword(haystack: &str, base: Expr) -> Vec<Node> {
    const KEYWORDS: &[(&[u8], u32)] = &[
        (b"auto", TOK_AUTO),
        (b"break", TOK_BREAK),
        (b"case", TOK_CASE),
        (b"char", TOK_CHAR_KW),
        (b"const", TOK_CONST),
        (b"__const", TOK_CONST),
        (b"__const__", TOK_CONST),
        (b"continue", TOK_CONTINUE),
        (b"default", TOK_DEFAULT),
        (b"do", TOK_DO),
        (b"double", TOK_DOUBLE),
        (b"else", TOK_ELSE),
        (b"enum", TOK_ENUM),
        (b"extern", TOK_EXTERN),
        (b"float", TOK_FLOAT_KW),
        (b"for", TOK_FOR),
        (b"goto", TOK_GOTO),
        (b"if", TOK_IF),
        (b"inline", TOK_INLINE),
        (b"int", TOK_INT),
        (b"long", TOK_LONG),
        (b"register", TOK_REGISTER),
        (b"restrict", TOK_RESTRICT),
        (b"__restrict", TOK_RESTRICT),
        (b"__restrict__", TOK_RESTRICT),
        (b"return", TOK_RETURN),
        (b"short", TOK_SHORT),
        (b"signed", TOK_SIGNED),
        (b"__signed", TOK_SIGNED),
        (b"__signed__", TOK_SIGNED),
        (b"sizeof", TOK_SIZEOF),
        (b"static", TOK_STATIC),
        (b"struct", TOK_STRUCT),
        (b"switch", TOK_SWITCH),
        (b"typedef", TOK_TYPEDEF),
        (b"union", TOK_UNION),
        (b"unsigned", TOK_UNSIGNED),
        (b"void", TOK_VOID),
        (b"volatile", TOK_VOLATILE),
        (b"__volatile", TOK_VOLATILE),
        (b"while", TOK_WHILE),
        (b"_Alignas", TOK_ALIGNAS),
        (b"_Alignof", TOK_ALIGNOF),
        (b"_Atomic", TOK_ATOMIC),
        (b"_Bool", TOK_BOOL),
        (b"_Complex", TOK_COMPLEX),
        (b"_Generic", TOK_GENERIC),
        (b"_Imaginary", TOK_IMAGINARY),
        (b"_Noreturn", TOK_NORETURN),
        (b"_Static_assert", TOK_STATIC_ASSERT),
        (b"_Thread_local", TOK_THREAD_LOCAL),
        (b"__thread", TOK_THREAD_LOCAL),
        (b"asm", TOK_GNU_ASM),
        (b"__asm", TOK_GNU_ASM),
        (b"__asm__", TOK_GNU_ASM),
        (b"__attribute", TOK_GNU_ATTRIBUTE),
        (b"__attribute__", TOK_GNU_ATTRIBUTE),
        (b"typeof", TOK_GNU_TYPEOF),
        (b"__typeof", TOK_GNU_TYPEOF),
        (b"__typeof__", TOK_GNU_TYPEOF),
        (b"typeof_unqual", TOK_GNU_TYPEOF_UNQUAL),
        (b"__typeof_unqual", TOK_GNU_TYPEOF_UNQUAL),
        (b"__typeof_unqual__", TOK_GNU_TYPEOF_UNQUAL),
        (b"__extension__", TOK_GNU_EXTENSION),
        (b"__alignof", TOK_ALIGNOF),
        (b"__alignof__", TOK_ALIGNOF),
        (b"__inline", TOK_INLINE),
        (b"__inline__", TOK_INLINE),
        (b"__complex__", TOK_COMPLEX),
        (b"__real__", TOK_GNU_REAL),
        (b"__imag__", TOK_GNU_IMAG),
        (b"__volatile__", TOK_VOLATILE),
        (b"__builtin_constant_p", TOK_BUILTIN_CONSTANT_P),
        (b"__builtin_choose_expr", TOK_BUILTIN_CHOOSE_EXPR),
        (
            b"__builtin_types_compatible_p",
            TOK_BUILTIN_TYPES_COMPATIBLE_P,
        ),
        (b"__auto_type", TOK_GNU_AUTO_TYPE),
        (b"__int128", TOK_GNU_INT128),
        (b"__int128_t", TOK_GNU_INT128),
        (b"__uint128_t", TOK_GNU_INT128),
        (b"__builtin_va_list", TOK_GNU_BUILTIN_VA_LIST),
        (b"__seg_gs", TOK_GNU_ADDRESS_SPACE),
        (b"__seg_fs", TOK_GNU_ADDRESS_SPACE),
        (b"__label__", TOK_GNU_LABEL),
    ];
    KEYWORDS
        .iter()
        .map(|(word, token)| {
            Node::if_then(
                keyword_match(haystack, base.clone(), word),
                vec![Node::assign("tok_type", Expr::u32(*token))],
            )
        })
        .collect()
}

pub(super) fn set_token(condition: Expr, token: u32, len: Expr) -> Node {
    Node::if_then(
        Expr::and(Expr::eq(Expr::var("emit"), Expr::u32(0)), condition),
        vec![
            Node::assign("emit", Expr::u32(1)),
            Node::assign("tok_type", Expr::u32(token)),
            Node::assign("tok_len", len),
        ],
    )
}
