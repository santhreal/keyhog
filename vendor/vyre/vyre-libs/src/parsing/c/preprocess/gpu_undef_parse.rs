//! GPU `#undef` row parser.
//!
//! Per `TOK_PREPROC` token classified as `TOK_PP_UNDEF`, extract the
//! macro-name byte span. Per-thread, fully parallel.
//!
//! ## Output columns (one row per token)
//!
//! - `name_start`, `name_len` — byte span of the macro name within
//!   `source`. Non-UNDEF rows get all-zero output. `name_len == 0`
//!   after this kernel means "not a parsed `#undef` row" — equivalent
//!   to the CPU `parse_undef_name` returning `None`/error.
//!
//! ## Wire layout
//!
//! Inputs:
//!   - `tok_starts` (U32), `tok_lens` (U32),
//!     `directive_kinds` (U32) — output of `gpu_directive_metadata`.
//!   - `source` (U32 packed bytes; see real-GPU note).
//!
//! Outputs (all U32, one element per token):
//!   - `name_start_out`, `name_len_out`.
//!
//! ## Real-GPU lowering note
//!
//! Same conventions as the rest of the directive-classify family:
//! `source` is declared as packed U32 so reference-eval and
//! naga-emitted real GPU agree on word-indexed access; the byte
//! extraction is in `load_byte_u32`. Macro-name extraction is bounded
//! by the directive row length, not by a compile-time identifier cap.

use crate::parsing::c::lex::tokens::TOK_PP_UNDEF;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-libs::parsing::c::preprocess::gpu_undef_parse_v2";

/// Canonical binding for the input per-token start-offset buffer.
pub const BINDING_TOK_STARTS: u32 = 0;
/// Canonical binding for the input per-token length buffer.
pub const BINDING_TOK_LENS: u32 = 1;
/// Canonical binding for the input directive-kinds buffer.
pub const BINDING_DIRECTIVE_KINDS: u32 = 2;
/// Canonical binding for the input source bytes (packed U32).
pub const BINDING_SOURCE: u32 = 3;
/// Canonical binding for the output `undef_name_start` column.
/// Renamed from `name_start_out` to avoid colliding with
/// `gpu_define_parse`'s own `name_start_out` when both kernels are
/// fused into a single dispatch (see gpu_extract_directive_payloads).
pub const BINDING_NAME_START_OUT: u32 = 4;
/// Canonical binding for the output `undef_name_len` column.
pub const BINDING_NAME_LEN_OUT: u32 = 5;

/// Maximum horizontal-WS run between elements the kernel tolerates
/// (between leading WS and `#`, between `#` and the keyword, between
/// the keyword and the macro name). Practical max is 1; cap at 4.
const MAX_WS_PREFIX: u32 = 4;

/// Length of `undef` keyword (5 bytes), used to step past it.
const UNDEF_KW_LEN: u32 = 5;

/// Build the `#undef` row parser `Program`.
///
/// Hybrid runtime/static-bound: kernel BODY uses `Expr::buf_len()` for
/// per-thread bounds, `num_tokens` is kept for output sizing, `source_len`
/// is unused.
#[must_use]
pub fn gpu_undef_parse(num_tokens: u32, source_len: u32) -> Program {
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

    // ws_skip: count consecutive WS in the next MAX_WS_PREFIX bytes.
    let ws_skip_expr = |prefix: &str| -> Expr {
        let mut acc = Expr::u32(MAX_WS_PREFIX);
        for q in (0..MAX_WS_PREFIX).rev() {
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

    // Read leading run + `#`.
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

    // Skip WS between `#` and `undef`.
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
    parse.push(Node::let_bind("kw_skip", ws_skip_expr("kp")));
    parse.push(Node::let_bind(
        "kw_start",
        Expr::add(
            Expr::add(Expr::var("hash_idx"), Expr::u32(1)),
            Expr::var("kw_skip"),
        ),
    ));
    parse.push(Node::let_bind(
        "post_kw",
        Expr::add(Expr::var("kw_start"), Expr::u32(UNDEF_KW_LEN)),
    ));

    // Skip WS between `undef` and the macro name.
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
    parse.push(Node::let_bind("name_skip", ws_skip_expr("np")));
    parse.push(Node::let_bind(
        "name_start_val",
        Expr::add(Expr::var("post_kw"), Expr::var("name_skip")),
    ));

    // Scan to the directive row end. This removes the old 64-byte
    // macro-name cap while preserving C identifier start/continue
    // semantics.
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
    parse.push(Node::let_bind(
        "valid_name",
        Expr::select(
            Expr::ne(Expr::var("name_len_val"), Expr::u32(0)),
            Expr::u32(1),
            Expr::u32(0),
        ),
    ));

    // Commit if found_hash AND valid_name.
    parse.push(Node::if_then(
        Expr::eq(
            Expr::bitand(Expr::var("found_hash"), Expr::var("valid_name")),
            Expr::u32(1),
        ),
        vec![
            Node::store(
                "undef_name_start_out",
                t.clone(),
                Expr::var("name_start_val"),
            ),
            Node::store("undef_name_len_out", t.clone(), Expr::var("name_len_val")),
        ],
    ));

    let body: Vec<Node> = vec![
        Node::let_bind("t", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(t.clone(), Expr::buf_len("tok_starts")),
            vec![
                Node::let_bind("kind", Expr::load("directive_kinds", t.clone())),
                Node::store("undef_name_start_out", t.clone(), Expr::u32(0)),
                Node::store("undef_name_len_out", t.clone(), Expr::u32(0)),
                Node::if_then(Expr::eq(Expr::var("kind"), Expr::u32(TOK_PP_UNDEF)), parse),
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
            "undef_name_start_out",
            BINDING_NAME_START_OUT,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(num_tokens.max(1)),
        BufferDecl::storage(
            "undef_name_len_out",
            BINDING_NAME_LEN_OUT,
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
        assert_eq!(
            OP_ID,
            "vyre-libs::parsing::c::preprocess::gpu_undef_parse_v2"
        );
    }

    #[test]
    fn build_program_returns_well_formed_program() {
        let p = gpu_undef_parse(8, 64);
        assert_eq!(p.buffers().len(), 6);
        assert_eq!(p.workgroup_size(), [256, 1, 1]);
    }
}
