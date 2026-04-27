use crate::parsing::c::lex::tokens::*;
use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

fn byte_load(buffer: &str, index: Expr) -> Expr {
    Expr::bitand(Expr::load(buffer, index), Expr::u32(0xFF))
}

fn ascii(byte: u8) -> Expr {
    Expr::u32(u32::from(byte))
}

fn byte_eq(value: Expr, byte: u8) -> Expr {
    Expr::eq(value, ascii(byte))
}

fn byte_at_or_zero(haystack: &str, index: Expr, haystack_len: u32) -> Expr {
    Expr::select(
        Expr::lt(index.clone(), Expr::u32(haystack_len)),
        byte_load(haystack, index),
        Expr::u32(0),
    )
}

fn byte_between(value: Expr, low: u8, high: u8) -> Expr {
    Expr::and(
        Expr::ge(value.clone(), ascii(low)),
        Expr::le(value, ascii(high)),
    )
}

fn is_alpha(value: Expr) -> Expr {
    Expr::or(
        byte_between(value.clone(), b'a', b'z'),
        byte_between(value, b'A', b'Z'),
    )
}

fn is_digit(value: Expr) -> Expr {
    byte_between(value, b'0', b'9')
}

fn is_octal_digit(value: Expr) -> Expr {
    byte_between(value, b'0', b'7')
}

fn is_hex_digit(value: Expr) -> Expr {
    Expr::or(
        is_digit(value.clone()),
        Expr::or(
            byte_between(value.clone(), b'a', b'f'),
            byte_between(value, b'A', b'F'),
        ),
    )
}

fn has_hex_digits_after(haystack: &str, escape_pos: Expr, digits: u32, haystack_len: u32) -> Expr {
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

fn is_valid_escape_byte(
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

fn is_ident_start(value: Expr) -> Expr {
    Expr::or(is_alpha(value.clone()), byte_eq(value, b'_'))
}

fn is_ident_continue(value: Expr) -> Expr {
    Expr::or(is_ident_start(value.clone()), is_digit(value))
}

fn keyword_match(haystack: &str, base: Expr, word: &[u8]) -> Expr {
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

fn classify_keyword(haystack: &str, base: Expr) -> Vec<Node> {
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

fn set_token(condition: Expr, token: u32, len: Expr) -> Node {
    Node::if_then(
        Expr::and(Expr::eq(Expr::var("emit"), Expr::u32(0)), condition),
        vec![
            Node::assign("emit", Expr::u32(1)),
            Node::assign("tok_type", Expr::u32(token)),
            Node::assign("tok_len", len),
        ],
    )
}

/// C11 GPU lexer composition.
///
/// Emits a compact, source-ordered token stream from a GPU lane. The ordered
/// lane avoids nondeterministic atomics at the parser boundary; the lexer remains
/// a GPU stage and is structured so a prefix-compacted parallel scanner can
/// replace the entry loop without changing the token contract.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn c11_lexer(
    haystack: &str,
    out_tok_types: &str,
    out_tok_starts: &str,
    out_tok_lens: &str,
    out_counts: &str,
    haystack_len: u32,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };

    let next_byte = |offset: u32| {
        Expr::select(
            Expr::lt(
                Expr::add(Expr::var("pos"), Expr::u32(offset)),
                Expr::u32(haystack_len),
            ),
            byte_load(haystack, Expr::add(Expr::var("pos"), Expr::u32(offset))),
            Expr::u32(0),
        )
    };

    let mut classify_at_pos = vec![
        Node::let_bind("byte", byte_load(haystack, Expr::var("pos"))),
        Node::let_bind(
            "prev_byte",
            Expr::select(
                Expr::gt(Expr::var("pos"), Expr::u32(0)),
                byte_load(haystack, Expr::sub(Expr::var("pos"), Expr::u32(1))),
                Expr::u32(0),
            ),
        ),
        Node::let_bind("next_byte", next_byte(1)),
        Node::let_bind("next2_byte", next_byte(2)),
        Node::let_bind("emit", Expr::u32(0)),
        Node::let_bind("tok_type", Expr::u32(TOK_WHITESPACE)),
        Node::let_bind("tok_len", Expr::u32(1)),
    ];

    classify_at_pos.push(set_token(
        Expr::and(
            byte_eq(Expr::var("byte"), b'#'),
            Expr::eq(Expr::var("line_allows_directive"), Expr::u32(1)),
        ),
        TOK_PREPROC,
        Expr::u32(1),
    ));
    classify_at_pos.push(Node::if_then(
        Expr::eq(Expr::var("tok_type"), Expr::u32(TOK_PREPROC)),
        vec![
            Node::let_bind("preproc_done", Expr::u32(0)),
            Node::let_bind("preproc_spliced_cr", Expr::u32(0)),
            Node::loop_for(
                "scan_preproc",
                Expr::add(Expr::var("pos"), Expr::u32(1)),
                Expr::u32(haystack_len),
                vec![Node::if_then(
                    Expr::eq(Expr::var("preproc_done"), Expr::u32(0)),
                    vec![
                        Node::let_bind("scan_byte", byte_load(haystack, Expr::var("scan_preproc"))),
                        Node::let_bind(
                            "scan_prev",
                            Expr::select(
                                Expr::gt(Expr::var("scan_preproc"), Expr::var("pos")),
                                byte_load(
                                    haystack,
                                    Expr::sub(Expr::var("scan_preproc"), Expr::u32(1)),
                                ),
                                Expr::u32(0),
                            ),
                        ),
                        Node::if_then_else(
                            Expr::or(
                                byte_eq(Expr::var("scan_byte"), b'\n'),
                                byte_eq(Expr::var("scan_byte"), b'\r'),
                            ),
                            vec![Node::if_then_else(
                                Expr::or(
                                    byte_eq(Expr::var("scan_prev"), b'\\'),
                                    Expr::and(
                                        byte_eq(Expr::var("scan_byte"), b'\n'),
                                        Expr::eq(Expr::var("preproc_spliced_cr"), Expr::u32(1)),
                                    ),
                                ),
                                vec![
                                    Node::assign(
                                        "tok_len",
                                        Expr::add(Expr::var("tok_len"), Expr::u32(1)),
                                    ),
                                    Node::assign(
                                        "preproc_spliced_cr",
                                        Expr::select(
                                            byte_eq(Expr::var("scan_byte"), b'\r'),
                                            Expr::u32(1),
                                            Expr::u32(0),
                                        ),
                                    ),
                                ],
                                vec![Node::assign("preproc_done", Expr::u32(1))],
                            )],
                            vec![Node::assign(
                                "tok_len",
                                Expr::add(Expr::var("tok_len"), Expr::u32(1)),
                            )],
                        ),
                    ],
                )],
            ),
        ],
    ));

    classify_at_pos.push(set_token(
        Expr::and(
            byte_eq(Expr::var("byte"), b'/'),
            byte_eq(Expr::var("next_byte"), b'/'),
        ),
        TOK_COMMENT,
        Expr::u32(2),
    ));
    classify_at_pos.push(Node::if_then(
        Expr::eq(Expr::var("tok_type"), Expr::u32(TOK_COMMENT)),
        vec![
            Node::let_bind("comment_done", Expr::u32(0)),
            Node::loop_for(
                "scan_comment",
                Expr::add(Expr::var("pos"), Expr::u32(2)),
                Expr::u32(haystack_len),
                vec![Node::if_then(
                    Expr::eq(Expr::var("comment_done"), Expr::u32(0)),
                    vec![
                        Node::let_bind("scan_byte", byte_load(haystack, Expr::var("scan_comment"))),
                        Node::if_then_else(
                            byte_eq(Expr::var("scan_byte"), b'\n'),
                            vec![Node::assign("comment_done", Expr::u32(1))],
                            vec![Node::assign(
                                "tok_len",
                                Expr::add(Expr::var("tok_len"), Expr::u32(1)),
                            )],
                        ),
                    ],
                )],
            ),
        ],
    ));

    classify_at_pos.push(set_token(
        Expr::and(
            byte_eq(Expr::var("byte"), b'/'),
            byte_eq(Expr::var("next_byte"), b'*'),
        ),
        TOK_COMMENT,
        Expr::u32(2),
    ));
    classify_at_pos.push(Node::if_then(
        Expr::and(
            Expr::eq(Expr::var("tok_type"), Expr::u32(TOK_COMMENT)),
            byte_eq(Expr::var("next_byte"), b'*'),
        ),
        vec![
            Node::let_bind("block_done", Expr::u32(0)),
            Node::loop_for(
                "scan_block_comment",
                Expr::add(Expr::var("pos"), Expr::u32(2)),
                Expr::u32(haystack_len),
                vec![Node::if_then(
                    Expr::eq(Expr::var("block_done"), Expr::u32(0)),
                    vec![
                        Node::assign("tok_len", Expr::add(Expr::var("tok_len"), Expr::u32(1))),
                        Node::let_bind(
                            "scan_byte",
                            byte_load(haystack, Expr::var("scan_block_comment")),
                        ),
                        Node::let_bind(
                            "scan_next",
                            Expr::select(
                                Expr::lt(
                                    Expr::add(Expr::var("scan_block_comment"), Expr::u32(1)),
                                    Expr::u32(haystack_len),
                                ),
                                byte_load(
                                    haystack,
                                    Expr::add(Expr::var("scan_block_comment"), Expr::u32(1)),
                                ),
                                Expr::u32(0),
                            ),
                        ),
                        Node::if_then(
                            Expr::and(
                                byte_eq(Expr::var("scan_byte"), b'*'),
                                byte_eq(Expr::var("scan_next"), b'/'),
                            ),
                            vec![
                                Node::assign(
                                    "tok_len",
                                    Expr::add(Expr::var("tok_len"), Expr::u32(1)),
                                ),
                                Node::assign("block_done", Expr::u32(1)),
                            ],
                        ),
                    ],
                )],
            ),
            Node::if_then(
                Expr::eq(Expr::var("block_done"), Expr::u32(0)),
                vec![Node::assign(
                    "tok_type",
                    Expr::u32(TOK_ERR_UNTERMINATED_COMMENT),
                )],
            ),
        ],
    ));

    classify_at_pos.push(set_token(
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
    classify_at_pos.push(set_token(
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
            Node::let_bind("ident_done", Expr::u32(0)),
            Node::loop_for(
                "scan_ident",
                Expr::add(Expr::var("pos"), Expr::u32(1)),
                Expr::u32(haystack_len),
                vec![Node::if_then(
                    Expr::eq(Expr::var("ident_done"), Expr::u32(0)),
                    vec![
                        Node::let_bind("scan_byte", byte_load(haystack, Expr::var("scan_ident"))),
                        Node::if_then_else(
                            is_ident_continue(Expr::var("scan_byte")),
                            vec![Node::assign(
                                "tok_len",
                                Expr::add(Expr::var("tok_len"), Expr::u32(1)),
                            )],
                            vec![Node::assign("ident_done", Expr::u32(1))],
                        ),
                    ],
                )],
            ),
        ],
    ));
    classify_at_pos.extend(classify_keyword(haystack, Expr::var("pos")));

    classify_at_pos.push(set_token(
        Expr::and(
            is_digit(Expr::var("byte")),
            Expr::not(is_ident_continue(Expr::var("prev_byte"))),
        ),
        TOK_INTEGER,
        Expr::u32(1),
    ));
    classify_at_pos.push(set_token(
        Expr::and(
            byte_eq(Expr::var("byte"), b'.'),
            is_digit(Expr::var("next_byte")),
        ),
        TOK_FLOAT,
        Expr::u32(1),
    ));
    classify_at_pos.push(Node::if_then(
        Expr::or(
            Expr::eq(Expr::var("tok_type"), Expr::u32(TOK_INTEGER)),
            Expr::eq(Expr::var("tok_type"), Expr::u32(TOK_FLOAT)),
        ),
        vec![
            Node::let_bind("number_done", Expr::u32(0)),
            Node::let_bind(
                "number_is_float",
                Expr::select(
                    Expr::eq(Expr::var("tok_type"), Expr::u32(TOK_FLOAT)),
                    Expr::u32(1),
                    Expr::u32(0),
                ),
            ),
            Node::loop_for(
                "scan_number",
                Expr::add(Expr::var("pos"), Expr::u32(1)),
                Expr::u32(haystack_len),
                vec![Node::if_then(
                    Expr::eq(Expr::var("number_done"), Expr::u32(0)),
                    vec![
                        Node::let_bind("scan_byte", byte_load(haystack, Expr::var("scan_number"))),
                        Node::let_bind(
                            "scan_prev",
                            byte_load(haystack, Expr::sub(Expr::var("scan_number"), Expr::u32(1))),
                        ),
                        Node::let_bind(
                            "scan_next",
                            Expr::select(
                                Expr::lt(
                                    Expr::add(Expr::var("scan_number"), Expr::u32(1)),
                                    Expr::u32(haystack_len),
                                ),
                                byte_load(
                                    haystack,
                                    Expr::add(Expr::var("scan_number"), Expr::u32(1)),
                                ),
                                Expr::u32(0),
                            ),
                        ),
                        Node::let_bind(
                            "scan_can_start_exponent",
                            Expr::and(
                                Expr::or(
                                    byte_eq(Expr::var("scan_byte"), b'e'),
                                    Expr::or(
                                        byte_eq(Expr::var("scan_byte"), b'E'),
                                        Expr::or(
                                            byte_eq(Expr::var("scan_byte"), b'p'),
                                            byte_eq(Expr::var("scan_byte"), b'P'),
                                        ),
                                    ),
                                ),
                                Expr::or(
                                    is_digit(Expr::var("scan_next")),
                                    Expr::or(
                                        byte_eq(Expr::var("scan_next"), b'+'),
                                        byte_eq(Expr::var("scan_next"), b'-'),
                                    ),
                                ),
                            ),
                        ),
                        Node::let_bind(
                            "scan_is_exponent_sign",
                            Expr::and(
                                Expr::or(
                                    byte_eq(Expr::var("scan_byte"), b'+'),
                                    byte_eq(Expr::var("scan_byte"), b'-'),
                                ),
                                Expr::or(
                                    byte_eq(Expr::var("scan_prev"), b'e'),
                                    Expr::or(
                                        byte_eq(Expr::var("scan_prev"), b'E'),
                                        Expr::or(
                                            byte_eq(Expr::var("scan_prev"), b'p'),
                                            byte_eq(Expr::var("scan_prev"), b'P'),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                        Node::let_bind("scan_is_float_dot", byte_eq(Expr::var("scan_byte"), b'.')),
                        Node::let_bind(
                            "scan_is_number_tail",
                            Expr::or(
                                is_ident_continue(Expr::var("scan_byte")),
                                Expr::or(
                                    Expr::var("scan_is_float_dot"),
                                    Expr::var("scan_is_exponent_sign"),
                                ),
                            ),
                        ),
                        Node::if_then_else(
                            Expr::var("scan_is_number_tail"),
                            vec![
                                Node::assign(
                                    "tok_len",
                                    Expr::add(Expr::var("tok_len"), Expr::u32(1)),
                                ),
                                Node::if_then(
                                    Expr::or(
                                        Expr::var("scan_is_float_dot"),
                                        Expr::var("scan_can_start_exponent"),
                                    ),
                                    vec![Node::assign("number_is_float", Expr::u32(1))],
                                ),
                            ],
                            vec![Node::assign("number_done", Expr::u32(1))],
                        ),
                    ],
                )],
            ),
            Node::if_then(
                Expr::eq(Expr::var("number_is_float"), Expr::u32(1)),
                vec![Node::assign("tok_type", Expr::u32(TOK_FLOAT))],
            ),
        ],
    ));

    classify_at_pos.push(set_token(
        byte_eq(Expr::var("byte"), b'"'),
        TOK_STRING,
        Expr::u32(1),
    ));
    classify_at_pos.push(set_token(
        byte_eq(Expr::var("byte"), b'\''),
        TOK_CHAR,
        Expr::u32(1),
    ));
    classify_at_pos.push(Node::if_then(
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
                Expr::u32(haystack_len),
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

    for (token, first, second, third) in [
        (TOK_LSHIFT_EQ, b'<', b'<', b'='),
        (TOK_RSHIFT_EQ, b'>', b'>', b'='),
    ] {
        classify_at_pos.push(set_token(
            Expr::and(
                Expr::and(
                    byte_eq(Expr::var("byte"), first),
                    byte_eq(Expr::var("next_byte"), second),
                ),
                byte_eq(Expr::var("next2_byte"), third),
            ),
            token,
            Expr::u32(3),
        ));
    }

    for (token, first, second) in [
        (TOK_ARROW, b'-', b'>'),
        (TOK_INC, b'+', b'+'),
        (TOK_DEC, b'-', b'-'),
        (TOK_PLUS_EQ, b'+', b'='),
        (TOK_MINUS_EQ, b'-', b'='),
        (TOK_STAR_EQ, b'*', b'='),
        (TOK_SLASH_EQ, b'/', b'='),
        (TOK_PERCENT_EQ, b'%', b'='),
        (TOK_AMP_EQ, b'&', b'='),
        (TOK_PIPE_EQ, b'|', b'='),
        (TOK_CARET_EQ, b'^', b'='),
        (TOK_HASHHASH, b'#', b'#'),
        (TOK_EQ, b'=', b'='),
        (TOK_NE, b'!', b'='),
        (TOK_LE, b'<', b'='),
        (TOK_GE, b'>', b'='),
        (TOK_AND, b'&', b'&'),
        (TOK_OR, b'|', b'|'),
        (TOK_LSHIFT, b'<', b'<'),
        (TOK_RSHIFT, b'>', b'>'),
    ] {
        classify_at_pos.push(set_token(
            Expr::and(
                byte_eq(Expr::var("byte"), first),
                byte_eq(Expr::var("next_byte"), second),
            ),
            token,
            Expr::u32(2),
        ));
    }

    classify_at_pos.push(set_token(
        Expr::and(
            Expr::and(
                byte_eq(Expr::var("byte"), b'.'),
                byte_eq(Expr::var("next_byte"), b'.'),
            ),
            byte_eq(Expr::var("next2_byte"), b'.'),
        ),
        TOK_ELLIPSIS,
        Expr::u32(3),
    ));

    for (token, byte) in [
        (TOK_LPAREN, b'('),
        (TOK_RPAREN, b')'),
        (TOK_LBRACE, b'{'),
        (TOK_RBRACE, b'}'),
        (TOK_LBRACKET, b'['),
        (TOK_RBRACKET, b']'),
        (TOK_SEMICOLON, b';'),
        (TOK_COMMA, b','),
        (TOK_DOT, b'.'),
        (TOK_PLUS, b'+'),
        (TOK_MINUS, b'-'),
        (TOK_STAR, b'*'),
        (TOK_SLASH, b'/'),
        (TOK_PERCENT, b'%'),
        (TOK_AMP, b'&'),
        (TOK_PIPE, b'|'),
        (TOK_CARET, b'^'),
        (TOK_TILDE, b'~'),
        (TOK_BANG, b'!'),
        (TOK_ASSIGN, b'='),
        (TOK_LT, b'<'),
        (TOK_GT, b'>'),
        (TOK_QUESTION, b'?'),
        (TOK_COLON, b':'),
    ] {
        classify_at_pos.push(set_token(
            byte_eq(Expr::var("byte"), byte),
            token,
            Expr::u32(1),
        ));
    }
    classify_at_pos.push(set_token(
        byte_eq(Expr::var("byte"), b'#'),
        TOK_HASH,
        Expr::u32(1),
    ));
    classify_at_pos.extend(vec![
        Node::let_bind(
            "store_token",
            Expr::and(
                Expr::eq(Expr::var("emit"), Expr::u32(1)),
                Expr::and(
                    Expr::ne(Expr::var("tok_type"), Expr::u32(TOK_WHITESPACE)),
                    Expr::ne(Expr::var("tok_type"), Expr::u32(TOK_COMMENT)),
                ),
            ),
        ),
        Node::if_then(
            Expr::var("store_token"),
            vec![
                Node::store(out_tok_types, Expr::var("tok_idx"), Expr::var("tok_type")),
                Node::store(out_tok_starts, Expr::var("tok_idx"), Expr::var("pos")),
                Node::store(out_tok_lens, Expr::var("tok_idx"), Expr::var("tok_len")),
                Node::assign("tok_idx", Expr::add(Expr::var("tok_idx"), Expr::u32(1))),
            ],
        ),
        Node::let_bind(
            "tok_last_byte",
            byte_at_or_zero(
                haystack,
                Expr::add(
                    Expr::var("pos"),
                    Expr::sub(Expr::var("tok_len"), Expr::u32(1)),
                ),
                haystack_len,
            ),
        ),
        Node::if_then_else(
            Expr::eq(Expr::var("tok_type"), Expr::u32(TOK_PREPROC)),
            vec![Node::assign("line_allows_directive", Expr::u32(1))],
            vec![Node::if_then_else(
                Expr::or(
                    byte_eq(Expr::var("byte"), b'\n'),
                    Expr::or(
                        byte_eq(Expr::var("byte"), b'\r'),
                        Expr::or(
                            byte_eq(Expr::var("tok_last_byte"), b'\n'),
                            byte_eq(Expr::var("tok_last_byte"), b'\r'),
                        ),
                    ),
                ),
                vec![Node::assign("line_allows_directive", Expr::u32(1))],
                vec![Node::if_then(
                    Expr::not(Expr::and(
                        Expr::eq(Expr::var("line_allows_directive"), Expr::u32(1)),
                        Expr::or(
                            byte_eq(Expr::var("byte"), b' '),
                            byte_eq(Expr::var("byte"), b'\t'),
                        ),
                    )),
                    vec![Node::assign("line_allows_directive", Expr::u32(0))],
                )],
            )],
        ),
        Node::assign(
            "cursor",
            Expr::add(
                Expr::var("cursor"),
                Expr::select(
                    Expr::eq(Expr::var("emit"), Expr::u32(1)),
                    Expr::var("tok_len"),
                    Expr::u32(1),
                ),
            ),
        ),
    ]);

    Program::wrapped(
        vec![
            BufferDecl::storage(haystack, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(haystack_len),
            BufferDecl::storage(out_tok_types, 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(haystack_len),
            BufferDecl::storage(out_tok_starts, 2, BufferAccess::ReadWrite, DataType::U32)
                .with_count(haystack_len),
            BufferDecl::storage(out_tok_lens, 3, BufferAccess::ReadWrite, DataType::U32)
                .with_count(haystack_len),
            BufferDecl::storage(out_counts, 4, BufferAccess::ReadWrite, DataType::U32)
                .with_count(1),
        ],
        [256, 1, 1],
        {
            let entry_body = vec![Node::if_then(
                Expr::eq(t.clone(), Expr::u32(0)),
                vec![
                    Node::let_bind("cursor", Expr::u32(0)),
                    Node::let_bind("line_allows_directive", Expr::u32(1)),
                    Node::let_bind("tok_idx", Expr::u32(0)),
                    Node::loop_for(
                        "token_iter",
                        Expr::u32(0),
                        Expr::u32(haystack_len),
                        vec![Node::if_then(
                            Expr::lt(Expr::var("cursor"), Expr::u32(haystack_len)),
                            {
                                let mut body = vec![Node::let_bind("pos", Expr::var("cursor"))];
                                body.extend(classify_at_pos);
                                body
                            },
                        )],
                    ),
                    Node::store(out_counts, Expr::u32(0), Expr::var("tok_idx")),
                ],
            )];
            vec![wrap_anonymous("vyre-libs::parsing::c_lexer", entry_body)]
        },
    )
    .with_entry_op_id("vyre-libs::parsing::c_lexer")
    .with_non_composable_with_self(true)
}

/// Resolves C11 digraphs and line-splicing markers natively in the token stream.
/// Translates sequence pairs like `<` and `:` into `[` natively via parallel SIMT passes
/// without branching diverging divergence loops.
#[must_use]
pub fn c11_lex_digraphs(
    tok_types: &str,
    tok_starts: &str,
    tok_lens: &str,
    tok_count: u32,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };

    // Core transformation loop logic
    let transform_logic = vec![
        Node::let_bind("t1_type", Expr::load(tok_types, t.clone())),
        Node::let_bind("has_prev2", Expr::gt(t.clone(), Expr::u32(1))),
        Node::let_bind(
            "prev2_type",
            Expr::select(
                Expr::var("has_prev2"),
                Expr::load(tok_types, Expr::sub(t.clone(), Expr::u32(2))),
                Expr::u32(TOK_EOF),
            ),
        ),
        Node::let_bind(
            "prev1_type",
            Expr::select(
                Expr::gt(t.clone(), Expr::u32(0)),
                Expr::load(tok_types, Expr::sub(t.clone(), Expr::u32(1))),
                Expr::u32(TOK_EOF),
            ),
        ),
        // Boundary safety check for adjacent lookahead
        Node::if_then(
            Expr::lt(Expr::add(t.clone(), Expr::u32(1)), Expr::u32(tok_count)),
            vec![
                Node::let_bind(
                    "t2_type",
                    Expr::load(tok_types, Expr::add(t.clone(), Expr::u32(1))),
                ),
                Node::let_bind(
                    "t3_type",
                    Expr::select(
                        Expr::lt(Expr::add(t.clone(), Expr::u32(2)), Expr::u32(tok_count)),
                        Expr::load(tok_types, Expr::add(t.clone(), Expr::u32(2))),
                        Expr::u32(TOK_EOF),
                    ),
                ),
                Node::let_bind(
                    "t4_type",
                    Expr::select(
                        Expr::lt(Expr::add(t.clone(), Expr::u32(3)), Expr::u32(tok_count)),
                        Expr::load(tok_types, Expr::add(t.clone(), Expr::u32(3))),
                        Expr::u32(TOK_EOF),
                    ),
                ),
                Node::let_bind(
                    "is_percent_colon_percent_colon",
                    Expr::and(
                        Expr::and(
                            Expr::eq(Expr::var("t1_type"), Expr::u32(TOK_PERCENT)),
                            Expr::eq(Expr::var("t2_type"), Expr::u32(TOK_COLON)),
                        ),
                        Expr::and(
                            Expr::eq(Expr::var("t3_type"), Expr::u32(TOK_PERCENT)),
                            Expr::eq(Expr::var("t4_type"), Expr::u32(TOK_COLON)),
                        ),
                    ),
                ),
                Node::let_bind(
                    "inside_percent_colon_percent_colon_tail",
                    Expr::and(
                        Expr::var("has_prev2"),
                        Expr::and(
                            Expr::eq(Expr::var("prev2_type"), Expr::u32(TOK_PERCENT)),
                            Expr::eq(Expr::var("prev1_type"), Expr::u32(TOK_COLON)),
                        ),
                    ),
                ),
                Node::if_then(
                    Expr::var("is_percent_colon_percent_colon"),
                    vec![
                        Node::store(tok_types, t.clone(), Expr::u32(TOK_HASHHASH)),
                        Node::store(
                            tok_types,
                            Expr::add(t.clone(), Expr::u32(1)),
                            Expr::u32(TOK_COMMENT),
                        ),
                        Node::store(
                            tok_types,
                            Expr::add(t.clone(), Expr::u32(2)),
                            Expr::u32(TOK_COMMENT),
                        ),
                        Node::store(
                            tok_types,
                            Expr::add(t.clone(), Expr::u32(3)),
                            Expr::u32(TOK_COMMENT),
                        ),
                    ],
                ),
                // Match `<:` -> `[` (LBRACKET == 14)
                Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("t1_type"), Expr::u32(TOK_LT)),
                        Expr::eq(Expr::var("t2_type"), Expr::u32(TOK_COLON)),
                    ),
                    vec![
                        Node::store(tok_types, t.clone(), Expr::u32(TOK_LBRACKET)),
                        Node::store(
                            tok_types,
                            Expr::add(t.clone(), Expr::u32(1)),
                            Expr::u32(TOK_COMMENT),
                        ), // Erase the second component natively
                    ],
                ),
                // Match `:>` -> `]` (RBRACKET == 15)
                Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("t1_type"), Expr::u32(TOK_COLON)),
                        Expr::eq(Expr::var("t2_type"), Expr::u32(TOK_GT)),
                    ),
                    vec![
                        Node::store(tok_types, t.clone(), Expr::u32(TOK_RBRACKET)),
                        Node::store(
                            tok_types,
                            Expr::add(t.clone(), Expr::u32(1)),
                            Expr::u32(TOK_COMMENT),
                        ),
                    ],
                ),
                // Match `<%` -> `{` (LBRACE == 12)
                Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("t1_type"), Expr::u32(TOK_LT)),
                        Expr::eq(Expr::var("t2_type"), Expr::u32(TOK_PERCENT)),
                    ),
                    vec![
                        Node::store(tok_types, t.clone(), Expr::u32(TOK_LBRACE)),
                        Node::store(
                            tok_types,
                            Expr::add(t.clone(), Expr::u32(1)),
                            Expr::u32(TOK_COMMENT),
                        ),
                    ],
                ),
                // Match `%>` -> `}` (RBRACE == 13)
                Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("t1_type"), Expr::u32(TOK_PERCENT)),
                        Expr::eq(Expr::var("t2_type"), Expr::u32(TOK_GT)),
                    ),
                    vec![
                        Node::store(tok_types, t.clone(), Expr::u32(TOK_RBRACE)),
                        Node::store(
                            tok_types,
                            Expr::add(t.clone(), Expr::u32(1)),
                            Expr::u32(TOK_COMMENT),
                        ),
                    ],
                ),
                // Match `%:` -> `#` (HASH == 33)
                Node::if_then(
                    Expr::and(
                        Expr::and(
                            Expr::eq(Expr::var("t1_type"), Expr::u32(TOK_PERCENT)),
                            Expr::eq(Expr::var("t2_type"), Expr::u32(TOK_COLON)),
                        ),
                        Expr::and(
                            Expr::not(Expr::var("is_percent_colon_percent_colon")),
                            Expr::not(Expr::var("inside_percent_colon_percent_colon_tail")),
                        ),
                    ),
                    vec![
                        Node::store(tok_types, t.clone(), Expr::u32(TOK_HASH)),
                        Node::store(
                            tok_types,
                            Expr::add(t.clone(), Expr::u32(1)),
                            Expr::u32(TOK_COMMENT),
                        ),
                    ],
                ),
            ],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(tok_types, 0, BufferAccess::ReadWrite, DataType::U32)
                .with_count(tok_count),
            BufferDecl::storage(tok_starts, 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(tok_count),
            BufferDecl::storage(tok_lens, 2, BufferAccess::ReadWrite, DataType::U32)
                .with_count(tok_count),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(
            "vyre-libs::parsing::c11_lex_digraphs",
            vec![Node::if_then(
                Expr::lt(t.clone(), Expr::u32(tok_count)),
                transform_logic,
            )],
        )],
    )
    .with_entry_op_id("vyre-libs::parsing::c11_lex_digraphs")
    .with_non_composable_with_self(true)
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::parsing::c_lexer",
        build: || {
            c11_lexer("haystack", "out_tok_types", "out_tok_starts", "out_tok_lens", "out_counts", 4096)
        },
        // A single identifier spanning the whole haystack emits one compact token.
        test_inputs: Some(|| {
            vec![vec![
                vec![b'a'; 4_096 * 4],  // haystack as u32-backed byte cells
                vec![0u8; 4_096 * 4],
                vec![0u8; 4_096 * 4],
                vec![0u8; 4_096 * 4],
                vec![0u8; 4],
            ]]
        }),
        expected_output: Some(|| {
            let mut out_tok_types = vec![0u8; 4_096 * 4];
            out_tok_types[0..4].copy_from_slice(&TOK_IDENTIFIER.to_le_bytes());

            let mut out_tok_lens = vec![0u8; 4_096 * 4];
            out_tok_lens[0..4].copy_from_slice(&4_096u32.to_le_bytes());

            let mut out_counts = vec![0u8; 4];
            out_counts.copy_from_slice(&1u32.to_le_bytes());

            vec![vec![
                out_tok_types,
                vec![0u8; 4_096 * 4],
                out_tok_lens,
                out_counts,
            ]]
        }),
    }
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::parsing::c11_lex_digraphs",
        build: || {
            c11_lex_digraphs("tok_types", "tok_starts", "tok_lens", 4096)
        },
        // Zero-filled buffers: three u32 streams of 4096 slots each.
        // The digraph pass scans for adjacent `<:` / `:>` / `<%` / `%>`
        // / `%:` pairs; on a zero stream nothing rewrites, so the
        // output is bitwise equal to the input (stable fixed point).
        test_inputs: Some(|| vec![vec![
            vec![0u8; 4 * 4096],
            vec![0u8; 4 * 4096],
            vec![0u8; 4 * 4096],
        ]]),
        expected_output: Some(|| vec![vec![
            vec![0u8; 4 * 4096],
            vec![0u8; 4 * 4096],
            vec![0u8; 4 * 4096],
        ]]),
    }
}
