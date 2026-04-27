use crate::parsing::c::lex::tokens::*;
use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// C11 keyword table consumed by the GPU keyword promotion pass.
pub const C_KEYWORDS: &[(&str, u32)] = &[
    ("auto", TOK_AUTO),
    ("break", TOK_BREAK),
    ("case", TOK_CASE),
    ("char", TOK_CHAR_KW),
    ("const", TOK_CONST),
    ("__const", TOK_CONST),
    ("__const__", TOK_CONST),
    ("continue", TOK_CONTINUE),
    ("default", TOK_DEFAULT),
    ("do", TOK_DO),
    ("double", TOK_DOUBLE),
    ("else", TOK_ELSE),
    ("enum", TOK_ENUM),
    ("extern", TOK_EXTERN),
    ("float", TOK_FLOAT_KW),
    ("for", TOK_FOR),
    ("goto", TOK_GOTO),
    ("if", TOK_IF),
    ("inline", TOK_INLINE),
    ("int", TOK_INT),
    ("long", TOK_LONG),
    ("register", TOK_REGISTER),
    ("restrict", TOK_RESTRICT),
    ("__restrict", TOK_RESTRICT),
    ("__restrict__", TOK_RESTRICT),
    ("return", TOK_RETURN),
    ("short", TOK_SHORT),
    ("signed", TOK_SIGNED),
    ("__signed", TOK_SIGNED),
    ("__signed__", TOK_SIGNED),
    ("sizeof", TOK_SIZEOF),
    ("static", TOK_STATIC),
    ("struct", TOK_STRUCT),
    ("switch", TOK_SWITCH),
    ("typedef", TOK_TYPEDEF),
    ("union", TOK_UNION),
    ("unsigned", TOK_UNSIGNED),
    ("void", TOK_VOID),
    ("volatile", TOK_VOLATILE),
    ("__volatile", TOK_VOLATILE),
    ("while", TOK_WHILE),
    ("_Alignas", TOK_ALIGNAS),
    ("_Alignof", TOK_ALIGNOF),
    ("_Atomic", TOK_ATOMIC),
    ("_Bool", TOK_BOOL),
    ("_Complex", TOK_COMPLEX),
    ("_Generic", TOK_GENERIC),
    ("_Imaginary", TOK_IMAGINARY),
    ("_Noreturn", TOK_NORETURN),
    ("_Static_assert", TOK_STATIC_ASSERT),
    ("_Thread_local", TOK_THREAD_LOCAL),
    ("__thread", TOK_THREAD_LOCAL),
    ("asm", TOK_GNU_ASM),
    ("__asm", TOK_GNU_ASM),
    ("__asm__", TOK_GNU_ASM),
    ("__attribute", TOK_GNU_ATTRIBUTE),
    ("__attribute__", TOK_GNU_ATTRIBUTE),
    ("typeof", TOK_GNU_TYPEOF),
    ("__typeof", TOK_GNU_TYPEOF),
    ("__typeof__", TOK_GNU_TYPEOF),
    ("typeof_unqual", TOK_GNU_TYPEOF_UNQUAL),
    ("__typeof_unqual", TOK_GNU_TYPEOF_UNQUAL),
    ("__typeof_unqual__", TOK_GNU_TYPEOF_UNQUAL),
    ("__extension__", TOK_GNU_EXTENSION),
    ("__alignof", TOK_ALIGNOF),
    ("__alignof__", TOK_ALIGNOF),
    ("__inline", TOK_INLINE),
    ("__inline__", TOK_INLINE),
    ("__complex__", TOK_COMPLEX),
    ("__real__", TOK_GNU_REAL),
    ("__imag__", TOK_GNU_IMAG),
    ("__volatile__", TOK_VOLATILE),
    ("__builtin_constant_p", TOK_BUILTIN_CONSTANT_P),
    ("__builtin_choose_expr", TOK_BUILTIN_CHOOSE_EXPR),
    (
        "__builtin_types_compatible_p",
        TOK_BUILTIN_TYPES_COMPATIBLE_P,
    ),
    ("__auto_type", TOK_GNU_AUTO_TYPE),
    ("__int128", TOK_GNU_INT128),
    ("__int128_t", TOK_GNU_INT128),
    ("__uint128_t", TOK_GNU_INT128),
    ("__builtin_va_list", TOK_GNU_BUILTIN_VA_LIST),
    ("__seg_gs", TOK_GNU_ADDRESS_SPACE),
    ("__seg_fs", TOK_GNU_ADDRESS_SPACE),
    ("__label__", TOK_GNU_LABEL),
];

/// FNV-1a32 hash used by `c_keyword`.
#[must_use]
pub fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// Packed `[hash, token_id]` table for the GPU keyword pass.
#[must_use]
pub fn c_keyword_map_words() -> Vec<u32> {
    C_KEYWORDS
        .iter()
        .flat_map(|(keyword, token)| [fnv1a32(keyword.as_bytes()), *token])
        .collect()
}

/// CPU oracle for keyword promotion over extracted token streams.
#[must_use]
pub fn reference_c_keyword_types(
    tok_types: &[u32],
    tok_starts: &[u32],
    tok_lens: &[u32],
    haystack: &[u8],
) -> Vec<u32> {
    let mut out = tok_types.to_vec();
    for (idx, tok_type) in out.iter_mut().enumerate() {
        if *tok_type != TOK_IDENTIFIER {
            continue;
        }
        let start = tok_starts.get(idx).copied().unwrap_or_default() as usize;
        let len = tok_lens.get(idx).copied().unwrap_or_default() as usize;
        let Some(lexeme) = haystack.get(start..start.saturating_add(len)) else {
            continue;
        };
        if let Some((_, keyword_token)) = C_KEYWORDS
            .iter()
            .find(|(keyword, _)| keyword.as_bytes() == lexeme)
        {
            *tok_type = *keyword_token;
        }
    }
    out
}

/// GPU keyword reclassification pass
///
/// Runs sequentially or in parallel over the extracted token stream (`out_tokens`).
/// For every `TOK_IDENTIFIER` (type == 1), hashes its bytes via FNV-1a32 and checks
/// a keyword hash table. If a match is found, the token type is updated.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn c_keyword(
    tok_types: &str,
    tok_starts: &str,
    tok_lens: &str,
    counts: &str,
    haystack: &str,
    keyword_map: &str,
    max_tokens: u32,
    num_keywords: u32,
    haystack_len: u32,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let num_tokens = Expr::load(counts, Expr::u32(0));

    let loop_body = vec![
        Node::let_bind("tok_type", Expr::load(tok_types, t.clone())),
        Node::if_then(
            Expr::eq(Expr::var("tok_type"), Expr::u32(TOK_IDENTIFIER)),
            vec![
                Node::let_bind("start", Expr::load(tok_starts, t.clone())),
                Node::let_bind("len", Expr::load(tok_lens, t.clone())),
                // inline fnv1a32
                Node::let_bind("hash", Expr::u32(0x811c9dc5)),
                Node::loop_for(
                    "i",
                    Expr::u32(0),
                    Expr::var("len"),
                    vec![
                        Node::let_bind(
                            "byte",
                            Expr::load(haystack, Expr::add(Expr::var("start"), Expr::var("i"))),
                        ),
                        Node::assign("hash", Expr::bitxor(Expr::var("hash"), Expr::var("byte"))),
                        Node::assign("hash", Expr::mul(Expr::var("hash"), Expr::u32(0x01000193))),
                        // Node::assign("i", Expr::add(Expr::var("i"), Expr::u32(1))), // loop_for auto-increments
                    ],
                ),
                // keyword_map is [hash0, tok_id0, hash1, tok_id1, ...].
                // `done_kw` is the soft-break flag — once a keyword
                // match fires, subsequent iterations are no-ops.
                Node::let_bind("done_kw", Expr::u32(0)),
                Node::loop_for(
                    "k",
                    Expr::u32(0),
                    Expr::u32(num_keywords),
                    vec![Node::if_then(
                        Expr::eq(Expr::var("done_kw"), Expr::u32(0)),
                        vec![
                            Node::let_bind(
                                "kw_hash",
                                Expr::load(keyword_map, Expr::mul(Expr::var("k"), Expr::u32(2))),
                            ),
                            Node::if_then(
                                Expr::eq(Expr::var("kw_hash"), Expr::var("hash")),
                                vec![
                                    Node::store(
                                        tok_types,
                                        t.clone(),
                                        Expr::load(
                                            keyword_map,
                                            Expr::add(
                                                Expr::mul(Expr::var("k"), Expr::u32(2)),
                                                Expr::u32(1),
                                            ),
                                        ),
                                    ),
                                    Node::assign("done_kw", Expr::u32(1)),
                                ],
                            ),
                        ],
                    )],
                ),
            ],
        ),
    ];

    let body = vec![Node::if_then(Expr::lt(t.clone(), num_tokens), loop_body)];

    Program::wrapped(
        vec![
            BufferDecl::storage(tok_types, 0, BufferAccess::ReadWrite, DataType::U32)
                .with_count(max_tokens),
            BufferDecl::storage(tok_starts, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(max_tokens),
            BufferDecl::storage(tok_lens, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(max_tokens),
            BufferDecl::storage(counts, 3, BufferAccess::ReadOnly, DataType::U32).with_count(1),
            BufferDecl::storage(haystack, 4, BufferAccess::ReadOnly, DataType::U32)
                .with_count(haystack_len),
            BufferDecl::storage(keyword_map, 5, BufferAccess::ReadOnly, DataType::U32)
                .with_count(num_keywords.saturating_mul(2)),
        ],
        [256, 1, 1], // Launch configuration
        vec![wrap_anonymous("vyre-libs::parsing::c_keyword", body)],
    )
    .with_entry_op_id("vyre-libs::parsing::c_keyword")
    .with_non_composable_with_self(true)
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::parsing::c_keyword",
        build: || {
            c_keyword(
                "tok_types",
                "tok_starts",
                "tok_lens",
                "counts",
                "haystack",
                "keyword_map",
                1024,
                C_KEYWORDS.len() as u32,
                4096,
            )
        },
        // Zero-filled fixture: counts[0]=0 so the guard `t < num_tokens`
        // never fires, and no lane enters the keyword-lookup body. Every
        // output buffer remains at its input state. This pins the no-op
        // fast path byte-for-byte; non-empty token streams are exercised
        // by `build_c11_compiler_megakernel`.
        test_inputs: Some(|| vec![vec![
            vec![0u8; 1024 * 4],        // tok_types
            vec![0u8; 1024 * 4],        // tok_starts
            vec![0u8; 1024 * 4],        // tok_lens
            vec![0u8; 4],               // counts
            vec![0u8; 4_096 * 4],       // haystack
            vec![0u8; C_KEYWORDS.len() * 2 * 4], // keyword_map
        ]]),
        expected_output: Some(|| {
            // counts[0] = 0 → no lane enters the keyword loop, so
            // tok_types is unchanged (all zero). Only ReadWrite/output
            // buffers appear in the expected set; tok_types is the only
            // ReadWrite buffer declared.
            vec![vec![vec![0u8; 1024 * 4]]]
        }),
    }
}
