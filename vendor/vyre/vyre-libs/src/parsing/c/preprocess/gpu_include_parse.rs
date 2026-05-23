//! GPU `#include` row parser.
//!
//! Phase 17b.7: per `TOK_PREPROC` token classified as
//! `TOK_PP_INCLUDE` or `TOK_PP_INCLUDE_NEXT`, extract the include
//! path's byte span and whether it was the `<…>` (system) form or
//! `"…"` (local) form. Per-thread, fully parallel.
//!
//! ## Output columns (one row per token)
//!
//! - `path_start`, `path_len`        — byte span between the
//!                                     delimiters (`<`/`>` or `"`/`"`).
//! - `is_system`                     — `1` for `<…>`, `0` for `"…"`.
//!
//! Non-INCLUDE rows get all-zero output. `path_len == 0` after this
//! kernel means "not a parsed `#include` row" — equivalent to the CPU
//! `parse_include_literal` returning `None`/error.
//!
//! ## Real-GPU lowering note
//!
//! Two real-GPU lowering pitfalls (both shared with
//! `gpu_directive_metadata`):
//!
//! 1. `DataType::U8` storage buffers are emitted by vyre-emit-naga as
//!    `array<u32>` (WGSL has no u8 storage). `Expr::load("source",
//!    addr)` therefore returns the u32 word at index `addr`, not the
//!    byte at byte-address `addr`. The kernel does the byte
//!    extraction inline so it produces the correct value on both
//!    backends.
//! 2. Whitespace skipping uses fixed-depth chained Selects because C
//!    directive separators are short in practice. Path extraction is
//!    bounded by the directive row length, so Linux-scale include paths
//!    are not truncated by a compile-time probe cap.
//!
//! ## Wire layout
//!
//! Inputs:
//!   - `tok_starts` (U32), `tok_lens` (U32),
//!     `directive_kinds` (U32) — output of 17a.
//!   - `source` (U8).
//!
//! Outputs (all U32, one element per token):
//!   - `path_start_out`, `path_len_out`, `is_system_out`.

use crate::parsing::c::lex::tokens::{TOK_PP_INCLUDE, TOK_PP_INCLUDE_NEXT};
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-libs::parsing::c::preprocess::gpu_include_parse_v2";

/// Canonical binding for the input per-token start-offset buffer.
pub const BINDING_TOK_STARTS: u32 = 0;
/// Canonical binding for the input per-token length buffer.
pub const BINDING_TOK_LENS: u32 = 1;
/// Canonical binding for the input directive-kinds buffer.
pub const BINDING_DIRECTIVE_KINDS: u32 = 2;
/// Canonical binding for the input source bytes.
pub const BINDING_SOURCE: u32 = 3;
/// Canonical binding for the output `path_start` column.
pub const BINDING_PATH_START_OUT: u32 = 4;
/// Canonical binding for the output `path_len` column.
pub const BINDING_PATH_LEN_OUT: u32 = 5;
/// Canonical binding for the output `is_system` column.
pub const BINDING_IS_SYSTEM_OUT: u32 = 6;

/// Maximum horizontal-WS run between path elements the kernel
/// tolerates. Practical real-world is 0–1; we cap at 4 each which
/// keeps the unrolled scans a fixed depth.
const MAX_WS_PREFIX: u32 = 4;

/// Build the 17b.7 `#include` row parser `Program`.
///
/// Hybrid runtime/static-bound: kernel BODY uses `Expr::buf_len()` for
/// every per-thread bound (so program AST is constant across files),
/// `num_tokens` is kept ONLY for output buffer sizing (CUDA backend
/// requires static byte length for readback), `source_len` is unused.
#[must_use]
pub fn gpu_include_parse(num_tokens: u32, source_len: u32) -> Program {
    let source_words = source_len.div_ceil(4).max(1);
    let t = Expr::var("t");
    let lane = Expr::var("lane");
    let block = Expr::var("block");

    // U8 byte extraction (see module note).
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

    // hash_off_expr: scan up to MAX_WS_PREFIX leading WS bytes for `#`.
    // bitand on u32 0/1 stays u32; reference-eval rejects mixed
    // u32/Bool in `Expr::and` chains, which is what naive `Expr::and`
    // chaining produces (first iter returns Bool, subsequent mix it
    // with u32 vars).
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

    // ---- step 1: hash_off / hash_idx ----
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

    // ---- step 2: skip WS between `#` and keyword. kw_start derived. ----
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

    // ---- step 3: skip past keyword. kw_len = 7 (`include`) or 12
    // (`include_next`). Decided by `kind`. ----
    parse.push(Node::let_bind(
        "kw_len_skip",
        Expr::select(
            Expr::eq(Expr::var("kind"), Expr::u32(TOK_PP_INCLUDE_NEXT)),
            Expr::u32(12),
            Expr::u32(7),
        ),
    ));
    parse.push(Node::let_bind(
        "post_kw",
        Expr::add(Expr::var("kw_start"), Expr::var("kw_len_skip")),
    ));

    // ---- step 4: skip WS between keyword and delimiter. ----
    for q in 0..MAX_WS_PREFIX {
        parse.push(Node::let_bind(
            format!("dp_{q}"),
            safe_load(Expr::add(Expr::var("post_kw"), Expr::u32(q))),
        ));
    }
    for q in 0..MAX_WS_PREFIX {
        parse.push(Node::let_bind(
            format!("dp_ws_{q}"),
            is_ws(Expr::var(format!("dp_{q}"))),
        ));
    }
    parse.push(Node::let_bind(
        "delim_skip",
        ws_skip_expr("dp", MAX_WS_PREFIX),
    ));
    parse.push(Node::let_bind(
        "delim_pos",
        Expr::add(Expr::var("post_kw"), Expr::var("delim_skip")),
    ));

    // ---- step 5: classify delimiter. ----
    parse.push(Node::let_bind(
        "delim_byte",
        safe_load(Expr::var("delim_pos")),
    ));
    parse.push(Node::let_bind(
        "is_angle",
        Expr::select(
            Expr::eq(Expr::var("delim_byte"), Expr::u32(b'<' as u32)),
            Expr::u32(1),
            Expr::u32(0),
        ),
    ));
    parse.push(Node::let_bind(
        "is_quote",
        Expr::select(
            Expr::eq(Expr::var("delim_byte"), Expr::u32(b'"' as u32)),
            Expr::u32(1),
            Expr::u32(0),
        ),
    ));
    parse.push(Node::let_bind(
        "valid_delim",
        Expr::select(
            Expr::or(
                Expr::eq(Expr::var("is_angle"), Expr::u32(1)),
                Expr::eq(Expr::var("is_quote"), Expr::u32(1)),
            ),
            Expr::u32(1),
            Expr::u32(0),
        ),
    ));
    parse.push(Node::let_bind(
        "close_byte",
        Expr::select(
            Expr::eq(Expr::var("is_angle"), Expr::u32(1)),
            Expr::u32(b'>' as u32),
            Expr::u32(b'"' as u32),
        ),
    ));
    parse.push(Node::let_bind(
        "path_start_val",
        Expr::add(Expr::var("delim_pos"), Expr::u32(1)),
    ));

    // ---- step 6: scan path bytes to the directive row end for the
    // closing delimiter. This used to be a fixed 48-byte unrolled
    // probe, which silently rejected long Linux/generated include
    // paths. The row-length loop keeps the program shape constant but
    // removes the semantic cap.
    parse.push(Node::let_bind(
        "path_scan_limit",
        Expr::select(
            Expr::lt(Expr::var("path_start_val"), Expr::var("tok_end")),
            Expr::sub(Expr::var("tok_end"), Expr::var("path_start_val")),
            Expr::u32(0),
        ),
    ));
    parse.push(Node::let_bind("path_len_val", Expr::u32(0)));
    parse.push(Node::let_bind("path_done", Expr::u32(0)));
    parse.push(Node::loop_for(
        "path_i",
        Expr::u32(0),
        Expr::var("path_scan_limit"),
        vec![Node::if_then(
            Expr::eq(Expr::var("path_done"), Expr::u32(0)),
            vec![
                Node::let_bind(
                    "path_byte",
                    safe_load(Expr::add(Expr::var("path_start_val"), Expr::var("path_i"))),
                ),
                Node::if_then(
                    Expr::eq(Expr::var("path_byte"), Expr::var("close_byte")),
                    vec![
                        Node::assign("path_len_val", Expr::var("path_i")),
                        Node::assign("path_done", Expr::u32(1)),
                    ],
                ),
            ],
        )],
    ));

    // ---- step 7: commit if found_hash AND valid_delim ----
    // Both are u32 0/1; bitand stays u32; convert to bool for if_then.
    parse.push(Node::if_then(
        Expr::eq(
            Expr::bitand(
                Expr::bitand(Expr::var("found_hash"), Expr::var("valid_delim")),
                Expr::var("path_done"),
            ),
            Expr::u32(1),
        ),
        vec![
            Node::store("path_start_out", t.clone(), Expr::var("path_start_val")),
            Node::store("path_len_out", t.clone(), Expr::var("path_len_val")),
            Node::store("is_system_out", t.clone(), Expr::var("is_angle")),
        ],
    ));

    // ---- per-thread top-level body ----
    let body: Vec<Node> = vec![
        Node::let_bind("lane", Expr::LocalId { axis: 0 }),
        Node::let_bind("block", Expr::WorkgroupId { axis: 0 }),
        Node::let_bind("t", Expr::add(Expr::mul(block, Expr::u32(256)), lane)),
        Node::if_then(
            Expr::lt(t.clone(), Expr::buf_len("tok_starts")),
            vec![
                Node::let_bind("kind", Expr::load("directive_kinds", t.clone())),
                // Pre-zero output cells. Parse path conditionally
                // overwrites them when the row is a parseable include.
                Node::store("path_start_out", t.clone(), Expr::u32(0)),
                Node::store("path_len_out", t.clone(), Expr::u32(0)),
                Node::store("is_system_out", t.clone(), Expr::u32(0)),
                Node::if_then(
                    Expr::or(
                        Expr::eq(Expr::var("kind"), Expr::u32(TOK_PP_INCLUDE)),
                        Expr::eq(Expr::var("kind"), Expr::u32(TOK_PP_INCLUDE_NEXT)),
                    ),
                    parse,
                ),
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
        // The source buffer is declared as packed `u32` words (see
        // module-level real-GPU note) so reference-eval and real GPU
        // agree on word-indexed access. The host pads input bytes to a
        // multiple of 4.
        BufferDecl::storage(
            "source",
            BINDING_SOURCE,
            BufferAccess::ReadOnly,
            DataType::U32,
        )
        .with_count(source_words),
        BufferDecl::storage(
            "path_start_out",
            BINDING_PATH_START_OUT,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(num_tokens.max(1)),
        BufferDecl::storage(
            "path_len_out",
            BINDING_PATH_LEN_OUT,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(num_tokens.max(1)),
        BufferDecl::storage(
            "is_system_out",
            BINDING_IS_SYSTEM_OUT,
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
            "vyre-libs::parsing::c::preprocess::gpu_include_parse_v2"
        );
    }

    #[test]
    fn build_program_returns_well_formed_program() {
        let p = gpu_include_parse(8, 64);
        assert_eq!(p.buffers().len(), 7);
        assert_eq!(p.workgroup_size(), [256, 1, 1]);
    }
}
