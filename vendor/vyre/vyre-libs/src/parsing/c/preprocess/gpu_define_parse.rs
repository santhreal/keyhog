//! GPU `#define` row parser.
//!
//! Per `TOK_PREPROC` token classified as `TOK_PP_DEFINE`, extract the
//! macro name byte span, optional arg-list byte span, and replacement
//! body byte span. Per-thread, no inter-token state.
//!
//! ## Output columns (one row per token)
//!
//! - `name_start`, `name_len`        — macro name byte span in `source`.
//! - `args_start`, `args_len`        — arg-list span (between the `(`
//!                                     immediately after the name and
//!                                     the matching `)`). `args_len = 0`
//!                                     for object-like macros.
//! - `body_start`, `body_len`        — replacement body span (with
//!                                     trailing horizontal whitespace
//!                                     trimmed).
//! - `is_function_like`              — `1` if there was a `(`
//!                                     immediately after the name, else 0.
//!
//! Non-DEFINE rows get all-zero output.
//!
//! ## Real-GPU lowering note
//!
//! Same conventions as the rest of the directive-classify family —
//! `source` is declared as packed U32 so reference-eval and naga-
//! emitted real GPU agree on word-indexed access; byte extraction is
//! inline. Fixed-width whitespace probes keep directive alignment cheap, while
//! macro names and function-like argument lists are scanned with per-row GPU
//! loops bounded by the directive token length. That keeps the compiled program
//! shape independent of translation-unit size without truncating long
//! clang-valid macro identifiers or parameter lists.

use crate::parsing::c::lex::tokens::TOK_PP_DEFINE;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-libs::parsing::c::preprocess::gpu_define_parse";

/// Canonical binding for the input per-token start-offset buffer.
pub const BINDING_TOK_STARTS: u32 = 0;
/// Canonical binding for the input per-token length buffer.
pub const BINDING_TOK_LENS: u32 = 1;
/// Canonical binding for the input directive-kinds buffer.
pub const BINDING_DIRECTIVE_KINDS: u32 = 2;
/// Canonical binding for the input source bytes (packed U32).
pub const BINDING_SOURCE: u32 = 3;
/// Canonical binding for the output `name_start` column.
pub const BINDING_NAME_START_OUT: u32 = 4;
/// Canonical binding for the output `name_len` column.
pub const BINDING_NAME_LEN_OUT: u32 = 5;
/// Canonical binding for the output `args_start` column.
pub const BINDING_ARGS_START_OUT: u32 = 6;
/// Canonical binding for the output `args_len` column.
pub const BINDING_ARGS_LEN_OUT: u32 = 7;
/// Canonical binding for the output `body_start` column.
pub const BINDING_BODY_START_OUT: u32 = 8;
/// Canonical binding for the output `body_len` column.
pub const BINDING_BODY_LEN_OUT: u32 = 9;
/// Canonical binding for the output `is_function_like` column.
pub const BINDING_IS_FUNCTION_LIKE_OUT: u32 = 10;

/// Maximum horizontal-WS run between elements (before `#`, between
/// `#` and the keyword, between the keyword and the name, between
/// `)` and the body). Practical real-world is 0–1; 4 is plenty.
const MAX_WS_PREFIX: u32 = 4;

/// Length of the `define` keyword (6 bytes), used to step past it.
const DEFINE_KW_LEN: u32 = 6;

/// Build the `#define` row parser `Program`.
///
/// `num_tokens` is kept ONLY to size the host-allocated output buffers
/// (the CUDA backend rejects readback when output buffers don't have a
/// static byte length). The kernel BODY itself uses `Expr::buf_len()` for
/// every per-thread bound — so the program AST is independent of the
/// host's input/source size and the dispatcher's pipeline cache hits
#[must_use]
pub fn gpu_define_parse(num_tokens: u32, source_len: u32) -> Program {
    let source_words = source_len.div_ceil(4).max(1);
    let t = Expr::var("t");

    let load_byte_u32 = |addr: Expr| -> Expr {
        let word_idx = Expr::div(addr.clone(), Expr::u32(4));
        let byte_in_word = Expr::rem(addr, Expr::u32(4));
        let word = Expr::cast(DataType::U32, Expr::load("source", word_idx));
        let shift = Expr::mul(byte_in_word, Expr::u32(8));
        Expr::bitand(Expr::shr(word, shift), Expr::u32(0xFF))
    };
    let safe_load = |addr: Expr| -> Expr {
        Expr::select(
            Expr::lt(
                addr.clone(),
                Expr::mul(Expr::buf_len("source"), Expr::u32(4)),
            ),
            load_byte_u32(addr),
            Expr::u32(0),
        )
    };
    let is_ws = |b: Expr| -> Expr {
        Expr::select(
            Expr::or(
                Expr::or(
                    Expr::eq(b.clone(), Expr::u32(b' ' as u32)),
                    Expr::eq(b.clone(), Expr::u32(b'\t' as u32)),
                ),
                Expr::or(
                    Expr::eq(b.clone(), Expr::u32(0x0B)),
                    Expr::eq(b, Expr::u32(0x0C)),
                ),
            ),
            Expr::u32(1),
            Expr::u32(0),
        )
    };
    // Trailing-WS check for body trimming includes \n / \r in addition
    // to horizontal WS.
    let is_trailing_ws = |b: Expr| -> Expr {
        Expr::select(
            Expr::or(
                Expr::or(
                    Expr::or(
                        Expr::eq(b.clone(), Expr::u32(b' ' as u32)),
                        Expr::eq(b.clone(), Expr::u32(b'\t' as u32)),
                    ),
                    Expr::or(
                        Expr::eq(b.clone(), Expr::u32(b'\n' as u32)),
                        Expr::eq(b.clone(), Expr::u32(b'\r' as u32)),
                    ),
                ),
                Expr::or(
                    Expr::eq(b.clone(), Expr::u32(0x0B)),
                    Expr::eq(b, Expr::u32(0x0C)),
                ),
            ),
            Expr::u32(1),
            Expr::u32(0),
        )
    };
    let is_continue = |b: Expr| -> Expr {
        let is_lower = Expr::and(
            Expr::ge(b.clone(), Expr::u32(b'a' as u32)),
            Expr::le(b.clone(), Expr::u32(b'z' as u32)),
        );
        let is_upper = Expr::and(
            Expr::ge(b.clone(), Expr::u32(b'A' as u32)),
            Expr::le(b.clone(), Expr::u32(b'Z' as u32)),
        );
        let is_digit = Expr::and(
            Expr::ge(b.clone(), Expr::u32(b'0' as u32)),
            Expr::le(b.clone(), Expr::u32(b'9' as u32)),
        );
        let is_under = Expr::eq(b, Expr::u32(b'_' as u32));
        Expr::select(
            Expr::or(Expr::or(is_lower, is_upper), Expr::or(is_digit, is_under)),
            Expr::u32(1),
            Expr::u32(0),
        )
    };
    let is_start = |b: Expr| -> Expr {
        let is_lower = Expr::and(
            Expr::ge(b.clone(), Expr::u32(b'a' as u32)),
            Expr::le(b.clone(), Expr::u32(b'z' as u32)),
        );
        let is_upper = Expr::and(
            Expr::ge(b.clone(), Expr::u32(b'A' as u32)),
            Expr::le(b.clone(), Expr::u32(b'Z' as u32)),
        );
        let is_under = Expr::eq(b, Expr::u32(b'_' as u32));
        Expr::select(
            Expr::or(Expr::or(is_lower, is_upper), is_under),
            Expr::u32(1),
            Expr::u32(0),
        )
    };

    // hash_off: scan for `#` within first MAX_WS_PREFIX+1 bytes.
    let hash_off_expr = {
        let mut acc = Expr::u32(0xFFFF_FFFF);
        for p in (0..=MAX_WS_PREFIX).rev() {
            let mut prefix_ws = Expr::u32(1);
            for q in 0..p {
                prefix_ws = Expr::bitand(prefix_ws, Expr::var(format!("hs_ws_{q}")));
            }
            let s_eq_hash = Expr::select(
                Expr::eq(Expr::var(format!("hs_{p}")), Expr::u32(b'#' as u32)),
                Expr::u32(1),
                Expr::u32(0),
            );
            let cond_u32 = Expr::bitand(s_eq_hash, prefix_ws);
            acc = Expr::select(Expr::eq(cond_u32, Expr::u32(1)), Expr::u32(p), acc);
        }
        acc
    };

    // Generic chained-Select for "first non-WS index in xs_0..xs_{N-1}",
    // returns N if every byte is WS (best-effort cap).
    let ws_skip_expr = |prefix: &str, n: u32| -> Expr {
        let mut acc = Expr::u32(n);
        for q in (0..n).rev() {
            let mut prefix_ws = Expr::u32(1);
            for r in 0..q {
                prefix_ws = Expr::bitand(prefix_ws, Expr::var(format!("{prefix}_ws_{r}")));
            }
            let xs_q_not_ws = Expr::select(
                Expr::eq(Expr::var(format!("{prefix}_ws_{q}")), Expr::u32(0)),
                Expr::u32(1),
                Expr::u32(0),
            );
            let cond_u32 = Expr::bitand(xs_q_not_ws, prefix_ws);
            acc = Expr::select(Expr::eq(cond_u32, Expr::u32(1)), Expr::u32(q), acc);
        }
        acc
    };

    let mut parse: Vec<Node> = Vec::new();
    parse.push(Node::let_bind(
        "tok_start",
        Expr::load("tok_starts", t.clone()),
    ));
    parse.push(Node::let_bind("tok_len", Expr::load("tok_lens", t.clone())));
    parse.push(Node::let_bind(
        "tok_end",
        Expr::add(Expr::var("tok_start"), Expr::var("tok_len")),
    ));

    // ---- Step 1: leading WS run + `#` ----
    for p in 0..=MAX_WS_PREFIX {
        parse.push(Node::let_bind(
            format!("hs_{p}"),
            safe_load(Expr::add(Expr::var("tok_start"), Expr::u32(p))),
        ));
    }
    for p in 0..=MAX_WS_PREFIX {
        parse.push(Node::let_bind(
            format!("hs_ws_{p}"),
            is_ws(Expr::var(format!("hs_{p}"))),
        ));
    }
    parse.push(Node::let_bind("hash_off", hash_off_expr));
    parse.push(Node::let_bind(
        "hash_idx",
        Expr::add(Expr::var("tok_start"), Expr::var("hash_off")),
    ));
    parse.push(Node::let_bind(
        "found_hash",
        Expr::select(
            Expr::lt(Expr::var("hash_off"), Expr::u32(MAX_WS_PREFIX + 1)),
            Expr::u32(1),
            Expr::u32(0),
        ),
    ));

    // ---- Step 2: WS between `#` and the `define` keyword ----
    for q in 0..MAX_WS_PREFIX {
        parse.push(Node::let_bind(
            format!("kp_{q}"),
            safe_load(Expr::add(Expr::var("hash_idx"), Expr::u32(q + 1))),
        ));
    }
    for q in 0..MAX_WS_PREFIX {
        parse.push(Node::let_bind(
            format!("kp_ws_{q}"),
            is_ws(Expr::var(format!("kp_{q}"))),
        ));
    }
    parse.push(Node::let_bind("kw_skip", ws_skip_expr("kp", MAX_WS_PREFIX)));
    parse.push(Node::let_bind(
        "kw_start",
        Expr::add(
            Expr::add(Expr::var("hash_idx"), Expr::u32(1)),
            Expr::var("kw_skip"),
        ),
    ));
    parse.push(Node::let_bind(
        "post_kw",
        Expr::add(Expr::var("kw_start"), Expr::u32(DEFINE_KW_LEN)),
    ));

    // ---- Step 3: WS between `define` and macro name ----
    for q in 0..MAX_WS_PREFIX {
        parse.push(Node::let_bind(
            format!("np_{q}"),
            safe_load(Expr::add(Expr::var("post_kw"), Expr::u32(q))),
        ));
    }
    for q in 0..MAX_WS_PREFIX {
        parse.push(Node::let_bind(
            format!("np_ws_{q}"),
            is_ws(Expr::var(format!("np_{q}"))),
        ));
    }
    parse.push(Node::let_bind(
        "name_skip",
        ws_skip_expr("np", MAX_WS_PREFIX),
    ));
    parse.push(Node::let_bind(
        "name_start_val",
        Expr::add(Expr::var("post_kw"), Expr::var("name_skip")),
    ));

    // ---- Step 4: scan name bytes to token end ----
    parse.push(Node::let_bind(
        "name_scan_limit",
        Expr::select(
            Expr::lt(Expr::var("name_start_val"), Expr::var("tok_end")),
            Expr::sub(Expr::var("tok_end"), Expr::var("name_start_val")),
            Expr::u32(0),
        ),
    ));
    parse.push(Node::let_bind("name_len_val", Expr::u32(0)));
    parse.push(Node::let_bind("name_done", Expr::u32(0)));
    parse.push(Node::loop_for(
        "name_i",
        Expr::u32(0),
        Expr::var("name_scan_limit"),
        vec![Node::if_then(
            Expr::eq(Expr::var("name_done"), Expr::u32(0)),
            vec![
                Node::let_bind(
                    "name_byte",
                    safe_load(Expr::add(Expr::var("name_start_val"), Expr::var("name_i"))),
                ),
                Node::let_bind(
                    "name_byte_ok",
                    Expr::select(
                        Expr::eq(Expr::var("name_i"), Expr::u32(0)),
                        is_start(Expr::var("name_byte")),
                        is_continue(Expr::var("name_byte")),
                    ),
                ),
                Node::if_then_else(
                    Expr::eq(Expr::var("name_byte_ok"), Expr::u32(1)),
                    vec![Node::assign(
                        "name_len_val",
                        Expr::add(Expr::var("name_i"), Expr::u32(1)),
                    )],
                    vec![Node::assign("name_done", Expr::u32(1))],
                ),
            ],
        )],
    ));

    // ---- Step 5: function-like check (next byte after name is `(`?) ----
    parse.push(Node::let_bind(
        "after_name_idx",
        Expr::add(Expr::var("name_start_val"), Expr::var("name_len_val")),
    ));
    parse.push(Node::let_bind(
        "after_name_byte",
        safe_load(Expr::var("after_name_idx")),
    ));
    parse.push(Node::let_bind(
        "is_func_val",
        Expr::select(
            Expr::eq(Expr::var("after_name_byte"), Expr::u32(b'(' as u32)),
            Expr::u32(1),
            Expr::u32(0),
        ),
    ));

    // ---- Step 6: scan args bytes for first `)` (function-like only) ----
    // args_start_val_raw = after_name_idx + 1 (past the `(`). For
    // object-like macros this position is meaningless; we mask the
    // output stores below behind `is_func_val == 1`.
    parse.push(Node::let_bind(
        "args_start_val_raw",
        Expr::add(Expr::var("after_name_idx"), Expr::u32(1)),
    ));
    parse.push(Node::let_bind(
        "args_scan_limit",
        Expr::select(
            Expr::lt(Expr::var("args_start_val_raw"), Expr::var("tok_end")),
            Expr::sub(Expr::var("tok_end"), Expr::var("args_start_val_raw")),
            Expr::u32(0),
        ),
    ));
    parse.push(Node::let_bind("args_len_val_raw", Expr::u32(0)));
    parse.push(Node::let_bind("args_done", Expr::u32(0)));
    parse.push(Node::loop_for(
        "args_i",
        Expr::u32(0),
        Expr::var("args_scan_limit"),
        vec![Node::if_then(
            Expr::and(
                Expr::eq(Expr::var("is_func_val"), Expr::u32(1)),
                Expr::eq(Expr::var("args_done"), Expr::u32(0)),
            ),
            vec![
                Node::let_bind(
                    "args_byte",
                    safe_load(Expr::add(
                        Expr::var("args_start_val_raw"),
                        Expr::var("args_i"),
                    )),
                ),
                Node::if_then(
                    Expr::eq(Expr::var("args_byte"), Expr::u32(b')' as u32)),
                    vec![
                        Node::assign("args_len_val_raw", Expr::var("args_i")),
                        Node::assign("args_done", Expr::u32(1)),
                    ],
                ),
            ],
        )],
    ));

    // ---- Step 7: body span ----
    // body_pre_start = position right after the closing `)` for
    // function-like macros; right after the name otherwise.
    parse.push(Node::let_bind(
        "body_pre_start",
        Expr::select(
            Expr::eq(Expr::var("is_func_val"), Expr::u32(1)),
            Expr::select(
                Expr::eq(Expr::var("args_done"), Expr::u32(1)),
                Expr::add(
                    Expr::add(
                        Expr::var("args_start_val_raw"),
                        Expr::var("args_len_val_raw"),
                    ),
                    Expr::u32(1),
                ),
                Expr::var("tok_end"),
            ),
            Expr::var("after_name_idx"),
        ),
    ));
    // Skip horizontal WS between `)` (or name) and the start of the body.
    for q in 0..MAX_WS_PREFIX {
        parse.push(Node::let_bind(
            format!("bp_{q}"),
            safe_load(Expr::add(Expr::var("body_pre_start"), Expr::u32(q))),
        ));
    }
    for q in 0..MAX_WS_PREFIX {
        parse.push(Node::let_bind(
            format!("bp_ws_{q}"),
            is_ws(Expr::var(format!("bp_{q}"))),
        ));
    }
    parse.push(Node::let_bind(
        "body_skip",
        ws_skip_expr("bp", MAX_WS_PREFIX),
    ));
    parse.push(Node::let_bind(
        "body_start_val",
        Expr::add(Expr::var("body_pre_start"), Expr::var("body_skip")),
    ));

    // ---- Step 8: trim trailing whitespace (incl. \n/\r) from the body ----
    // We probe the LAST MAX_WS_PREFIX bytes of the row and count a
    // trailing-WS run. The body length is `tok_end - body_start_val -
    // trailing_ws_count` clamped to >= 0.
    for q in 0..MAX_WS_PREFIX {
        // tb_q = byte at tok_end - 1 - q (last byte first when q=0).
        parse.push(Node::let_bind(
            format!("tb_{q}"),
            Expr::select(
                Expr::lt(
                    Expr::add(Expr::var("body_start_val"), Expr::u32(q + 1)),
                    Expr::add(Expr::var("tok_end"), Expr::u32(1)),
                ),
                safe_load(Expr::sub(Expr::var("tok_end"), Expr::u32(q + 1))),
                Expr::u32(0),
            ),
        ));
    }
    for q in 0..MAX_WS_PREFIX {
        parse.push(Node::let_bind(
            format!("tb_ws_{q}"),
            is_trailing_ws(Expr::var(format!("tb_{q}"))),
        ));
    }
    // trailing_ws_count = first q in [0, MAX_WS_PREFIX) where tb_ws_q
    // == 0 (the run of trailing WS bytes). Same chained-Select shape
    // as `ws_skip_expr` but reading the `tb_ws_*` bindings.
    let trailing_ws_expr = {
        let mut acc = Expr::u32(MAX_WS_PREFIX);
        for q in (0..MAX_WS_PREFIX).rev() {
            let mut prefix_ws = Expr::u32(1);
            for r in 0..q {
                prefix_ws = Expr::bitand(prefix_ws, Expr::var(format!("tb_ws_{r}")));
            }
            let tb_q_not_ws = Expr::select(
                Expr::eq(Expr::var(format!("tb_ws_{q}")), Expr::u32(0)),
                Expr::u32(1),
                Expr::u32(0),
            );
            let cond_u32 = Expr::bitand(tb_q_not_ws, prefix_ws);
            acc = Expr::select(Expr::eq(cond_u32, Expr::u32(1)), Expr::u32(q), acc);
        }
        acc
    };
    parse.push(Node::let_bind("trailing_ws_count", trailing_ws_expr));
    // body_len_val = max(0, (tok_end - trailing_ws_count) - body_start_val).
    parse.push(Node::let_bind(
        "body_end_trimmed",
        Expr::sub(Expr::var("tok_end"), Expr::var("trailing_ws_count")),
    ));
    parse.push(Node::let_bind(
        "body_len_val",
        Expr::select(
            Expr::lt(Expr::var("body_start_val"), Expr::var("body_end_trimmed")),
            Expr::sub(Expr::var("body_end_trimmed"), Expr::var("body_start_val")),
            Expr::u32(0),
        ),
    ));

    // ---- Step 9: commit ----
    // Stores fire only when found_hash == 1. The `is_func` masking
    // for args fields is handled by storing 0 unconditionally for
    // non-function-like rows.
    parse.push(Node::if_then(
        Expr::and(
            Expr::eq(Expr::var("found_hash"), Expr::u32(1)),
            Expr::gt(Expr::var("name_len_val"), Expr::u32(0)),
        ),
        vec![
            Node::store("name_start_out", t.clone(), Expr::var("name_start_val")),
            Node::store("name_len_out", t.clone(), Expr::var("name_len_val")),
            Node::store("body_start_out", t.clone(), Expr::var("body_start_val")),
            Node::store("body_len_out", t.clone(), Expr::var("body_len_val")),
            Node::store("is_function_like_out", t.clone(), Expr::var("is_func_val")),
            Node::if_then(
                Expr::and(
                    Expr::eq(Expr::var("is_func_val"), Expr::u32(1)),
                    Expr::eq(Expr::var("args_done"), Expr::u32(1)),
                ),
                vec![
                    Node::store("args_start_out", t.clone(), Expr::var("args_start_val_raw")),
                    Node::store("args_len_out", t.clone(), Expr::var("args_len_val_raw")),
                ],
            ),
        ],
    ));

    let body: Vec<Node> = vec![
        Node::let_bind("t", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(t.clone(), Expr::buf_len("tok_starts")),
            vec![
                Node::let_bind("kind", Expr::load("directive_kinds", t.clone())),
                // Pre-zero every output cell. Parse path conditionally
                // overwrites them when this is a parseable #define row.
                Node::store("name_start_out", t.clone(), Expr::u32(0)),
                Node::store("name_len_out", t.clone(), Expr::u32(0)),
                Node::store("args_start_out", t.clone(), Expr::u32(0)),
                Node::store("args_len_out", t.clone(), Expr::u32(0)),
                Node::store("body_start_out", t.clone(), Expr::u32(0)),
                Node::store("body_len_out", t.clone(), Expr::u32(0)),
                Node::store("is_function_like_out", t.clone(), Expr::u32(0)),
                Node::if_then(Expr::eq(Expr::var("kind"), Expr::u32(TOK_PP_DEFINE)), parse),
            ],
        ),
    ];

    let buffers = vec![
        BufferDecl::storage(
            "tok_starts",
            BINDING_TOK_STARTS,
            BufferAccess::ReadOnly,
            DataType::U32,
        )
        .with_count(num_tokens.max(1)),
        BufferDecl::storage(
            "tok_lens",
            BINDING_TOK_LENS,
            BufferAccess::ReadOnly,
            DataType::U32,
        )
        .with_count(num_tokens.max(1)),
        BufferDecl::storage(
            "directive_kinds",
            BINDING_DIRECTIVE_KINDS,
            BufferAccess::ReadOnly,
            DataType::U32,
        )
        .with_count(num_tokens.max(1)),
        BufferDecl::storage(
            "source",
            BINDING_SOURCE,
            BufferAccess::ReadOnly,
            DataType::U32,
        )
        .with_count(source_words),
        BufferDecl::storage(
            "name_start_out",
            BINDING_NAME_START_OUT,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(num_tokens.max(1)),
        BufferDecl::storage(
            "name_len_out",
            BINDING_NAME_LEN_OUT,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(num_tokens.max(1)),
        BufferDecl::storage(
            "args_start_out",
            BINDING_ARGS_START_OUT,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(num_tokens.max(1)),
        BufferDecl::storage(
            "args_len_out",
            BINDING_ARGS_LEN_OUT,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(num_tokens.max(1)),
        BufferDecl::storage(
            "body_start_out",
            BINDING_BODY_START_OUT,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(num_tokens.max(1)),
        BufferDecl::storage(
            "body_len_out",
            BINDING_BODY_LEN_OUT,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(num_tokens.max(1)),
        BufferDecl::storage(
            "is_function_like_out",
            BINDING_IS_FUNCTION_LIKE_OUT,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(num_tokens.max(1)),
    ];

    Program::wrapped(buffers, [256, 1, 1], body).with_entry_op_id(OP_ID)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_id_is_canonical_and_stable() {
        assert_eq!(OP_ID, "vyre-libs::parsing::c::preprocess::gpu_define_parse");
    }

    #[test]
    fn build_program_returns_well_formed_program() {
        let p = gpu_define_parse(8, 64);
        assert_eq!(p.buffers().len(), 11);
        assert_eq!(p.workgroup_size(), [256, 1, 1]);
    }
}
