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
//! straight-line `let_bind` chains plus direct buffer stores, no
//! outer-scope mutables and no loops (the kernel parses up to a
//! fixed-depth name length using unrolled probes). `source` is
//! declared as packed U32 so reference-eval and naga-emitted real GPU
//! agree on word-indexed access; the byte extraction is in
//! `load_byte_u32`.

use crate::parsing::c::lex::tokens::TOK_PP_UNDEF;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-libs::parsing::c::preprocess::gpu_undef_parse";

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

/// Maximum macro-name length the kernel can extract. C identifiers in
/// the wild are well under this. Cap chosen so the unrolled probe
/// stays a manageable fixed depth.
const MAX_NAME_LEN: u32 = 64;

/// Length of `undef` keyword (5 bytes), used to step past it.
const UNDEF_KW_LEN: u32 = 5;

/// Build the `#undef` row parser `Program`.
#[must_use]
pub fn gpu_undef_parse(num_tokens: u32, source_len: u32) -> Program {
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
            Expr::lt(addr.clone(), Expr::u32(source_len)),
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
    parse.push(Node::let_bind("tok_start", Expr::load("tok_starts", t.clone())));

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

    // Probe up to MAX_NAME_LEN bytes; the name spans the longest
    // run of ident-continue bytes starting at `name_start_val`.
    for i in 0..MAX_NAME_LEN {
        parse.push(Node::let_bind(
            format!("nb_{i}"),
            safe_load(Expr::add(Expr::var("name_start_val"), Expr::u32(i))),
        ));
    }
    for i in 0..MAX_NAME_LEN {
        parse.push(Node::let_bind(
            format!("nb_cont_{i}"),
            is_continue(Expr::var(format!("nb_{i}"))),
        ));
    }
    // name_len_val: the smallest index `i` in [0, MAX_NAME_LEN) where
    // `nb_cont_i == 0`. Outer-first chained Select guarantees the
    // smallest matching index wins. If every byte is ident-continue,
    // returns MAX_NAME_LEN (best-effort cap; very large names are
    // truncated rather than misparsed).
    let name_len_expr = {
        let mut acc = Expr::u32(MAX_NAME_LEN);
        for i in (0..MAX_NAME_LEN).rev() {
            let nb_cont_i_zero = Expr::eq(Expr::var(format!("nb_cont_{i}")), Expr::u32(0));
            acc = Expr::select(nb_cont_i_zero, Expr::u32(i), acc);
        }
        acc
    };
    parse.push(Node::let_bind("name_len_val", name_len_expr));

    // First-byte sanity: a valid C identifier may not start with a
    // digit. If it does, treat the row as unparseable (name_len = 0).
    parse.push(Node::let_bind(
        "first_is_digit",
        Expr::select(
            Expr::and(
                Expr::ge(Expr::var("nb_0"), Expr::u32(b'0' as u32)),
                Expr::le(Expr::var("nb_0"), Expr::u32(b'9' as u32)),
            ),
            Expr::u32(1),
            Expr::u32(0),
        ),
    ));
    parse.push(Node::let_bind(
        "valid_name",
        Expr::select(
            Expr::and(
                Expr::ne(Expr::var("name_len_val"), Expr::u32(0)),
                Expr::eq(Expr::var("first_is_digit"), Expr::u32(0)),
            ),
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
            Node::store("undef_name_start_out", t.clone(), Expr::var("name_start_val")),
            Node::store("undef_name_len_out", t.clone(), Expr::var("name_len_val")),
        ],
    ));

    let body: Vec<Node> = vec![
        Node::let_bind("t", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(t.clone(), Expr::u32(num_tokens)),
            vec![
                Node::let_bind("kind", Expr::load("directive_kinds", t.clone())),
                Node::store("undef_name_start_out", t.clone(), Expr::u32(0)),
                Node::store("undef_name_len_out", t.clone(), Expr::u32(0)),
                Node::if_then(
                    Expr::eq(Expr::var("kind"), Expr::u32(TOK_PP_UNDEF)),
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
        BufferDecl::storage(
            "source",
            BINDING_SOURCE,
            BufferAccess::ReadOnly,
            DataType::U32,
        )
        .with_count(source_len.div_ceil(4).max(1)),
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
        assert_eq!(OP_ID, "vyre-libs::parsing::c::preprocess::gpu_undef_parse");
    }

    #[test]
    fn build_program_returns_well_formed_program() {
        let p = gpu_undef_parse(8, 64);
        assert_eq!(p.buffers().len(), 6);
        assert_eq!(p.workgroup_size(), [256, 1, 1]);
    }
}
