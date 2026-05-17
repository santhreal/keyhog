//! GPU `#ifdef` / `#ifndef` payload evaluator.
//!
//! Per-token, given the directive_kind already classified by
//! `gpu_directive_metadata`, parse the single identifier payload and
//! look it up in the host-supplied `defined_macros` table. For
//! `TOK_PP_IFDEF` emit `1` if defined else `0`. For `TOK_PP_IFNDEF`
//! emit the complement. For every other directive kind emit `0`.
//!
//! ## Wire layout
//!
//! Inputs:
//!   - `tok_starts` (U32) — per-token byte offset into `source`.
//!   - `tok_lens` (U32) — per-token byte length.
//!   - `directive_kinds` (U32) — output of `gpu_directive_metadata`.
//!   - `source` (U32 packed bytes; see real-GPU note).
//!   - `macro_names_packed` (U32 packed bytes) — concatenated
//!     defined-macro name bytes. Empty when no macros are defined.
//!   - `macro_offsets` (U32) — start offsets of each macro name.
//!     Length `num_macros + 1`; the final entry is the total
//!     `macro_names_packed` length so each name's length is
//!     `offsets[i+1] - offsets[i]`.
//!
//! Outputs:
//!   - `directive_values` (U32) — per-token value: `1` / `0` for
//!     ifdef / ifndef; `0` for every other directive kind.
//!
//! ## Real-GPU lowering note
//!
//! Same conventions as the rest of the directive-classify family —
//! `source` and `macro_names_packed` declared as packed U32 so
//! reference-eval and naga-emitted real GPU agree on word-indexed
//! access; byte extraction is inline. The kernel is **straight-line**
//! (no loops, no outer-scope mutables) to dodge the Q7 carrier-seed
//! family bug in vyre-lower's region-scope phi-merge.
//!
//! The macro-table lookup is the only piece that previously relied
//! on a serial loop with mutable state. It is now an unrolled
//! per-macro fan-in: for each `m in 0..num_macros` (constant at
//! Program-build time), the kernel emits a fixed-depth equality
//! check between the directive's identifier bytes and macro `m`'s
//! name bytes; the per-macro 0/1 results are OR-reduced into the
//! final value.

use crate::parsing::c::lex::tokens::{TOK_PP_IFDEF, TOK_PP_IFNDEF};
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-libs::parsing::c::preprocess::gpu_ifdef_value";

/// Canonical binding index for the input per-token byte-offset buffer.
pub const BINDING_TOK_STARTS: u32 = 0;
/// Canonical binding index for the input per-token byte-length buffer.
pub const BINDING_TOK_LENS: u32 = 1;
/// Canonical binding index for the input directive-kinds buffer.
pub const BINDING_DIRECTIVE_KINDS: u32 = 2;
/// Canonical binding index for the input source-bytes buffer.
pub const BINDING_SOURCE: u32 = 3;
/// Canonical binding index for the input packed macro-name bytes buffer.
pub const BINDING_MACRO_NAMES_PACKED: u32 = 4;
/// Canonical binding index for the input macro-offsets buffer.
pub const BINDING_MACRO_OFFSETS: u32 = 5;
/// Canonical binding index for the output `directive_values` buffer.
pub const BINDING_DIRECTIVE_VALUES: u32 = 6;

/// Maximum identifier length scanned for the `ifdef`/`ifndef`
/// payload AND the macro-name byte comparison. Identifiers longer
/// than this are treated as not-found (truncation-safe).
pub const MAX_IDENT_LEN: u32 = 64;

/// Maximum horizontal-WS run before `#`, between `#` and the
/// keyword, between the keyword and the identifier. Cap at 4 — real
/// rows have 0–1.
const MAX_WS_PREFIX: u32 = 4;

/// Build the ifdef/ifndef-evaluator `Program`.
#[must_use]
pub fn gpu_ifdef_value(
    num_tokens: u32,
    source_len: u32,
    macro_names_len: u32,
    num_macros: u32,
) -> Program {
    let t = Expr::var("t");

    let load_byte_u32 = |buf: &'static str, addr: Expr| -> Expr {
        let word_idx = Expr::div(addr.clone(), Expr::u32(4));
        let byte_in_word = Expr::rem(addr, Expr::u32(4));
        let word = Expr::cast(DataType::U32, Expr::load(buf, word_idx));
        let shift = Expr::mul(byte_in_word, Expr::u32(8));
        Expr::bitand(Expr::shr(word, shift), Expr::u32(0xFF))
    };
    let safe_load = |buf: &'static str, addr: Expr, bound: Expr| -> Expr {
        Expr::select(
            Expr::lt(addr.clone(), bound),
            load_byte_u32(buf, addr),
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

    let mut evaluate: Vec<Node> = Vec::new();
    evaluate.push(Node::let_bind("tok_start", Expr::load("tok_starts", t.clone())));

    // Step 1: leading WS + `#`.
    for p in 0..=MAX_WS_PREFIX {
        evaluate.push(Node::let_bind(
            format!("hs_{p}"),
            safe_load(
                "source",
                Expr::add(Expr::var("tok_start"), Expr::u32(p)),
                Expr::u32(source_len),
            ),
        ));
    }
    for p in 0..=MAX_WS_PREFIX {
        evaluate.push(Node::let_bind(
            format!("hs_ws_{p}"),
            is_ws(Expr::var(format!("hs_{p}"))),
        ));
    }
    evaluate.push(Node::let_bind("hash_off", hash_off_expr));
    evaluate.push(Node::let_bind(
        "hash_idx",
        Expr::add(Expr::var("tok_start"), Expr::var("hash_off")),
    ));
    evaluate.push(Node::let_bind(
        "found_hash",
        Expr::select(
            Expr::lt(Expr::var("hash_off"), Expr::u32(MAX_WS_PREFIX + 1)),
            Expr::u32(1),
            Expr::u32(0),
        ),
    ));

    // Step 2: WS between `#` and the keyword.
    for q in 0..MAX_WS_PREFIX {
        evaluate.push(Node::let_bind(
            format!("kp_{q}"),
            safe_load(
                "source",
                Expr::add(Expr::var("hash_idx"), Expr::u32(q + 1)),
                Expr::u32(source_len),
            ),
        ));
    }
    for q in 0..MAX_WS_PREFIX {
        evaluate.push(Node::let_bind(
            format!("kp_ws_{q}"),
            is_ws(Expr::var(format!("kp_{q}"))),
        ));
    }
    evaluate.push(Node::let_bind("kw_skip", ws_skip_expr("kp", MAX_WS_PREFIX)));
    evaluate.push(Node::let_bind(
        "kw_start",
        Expr::add(
            Expr::add(Expr::var("hash_idx"), Expr::u32(1)),
            Expr::var("kw_skip"),
        ),
    ));

    // Step 3: keyword length depends on kind (`ifdef`=5, `ifndef`=6).
    evaluate.push(Node::let_bind(
        "kw_len_skip",
        Expr::select(
            Expr::eq(Expr::var("kind"), Expr::u32(TOK_PP_IFNDEF)),
            Expr::u32(6),
            Expr::u32(5),
        ),
    ));
    evaluate.push(Node::let_bind(
        "post_kw",
        Expr::add(Expr::var("kw_start"), Expr::var("kw_len_skip")),
    ));

    // Step 4: WS between keyword and identifier.
    for q in 0..MAX_WS_PREFIX {
        evaluate.push(Node::let_bind(
            format!("ip_{q}"),
            safe_load(
                "source",
                Expr::add(Expr::var("post_kw"), Expr::u32(q)),
                Expr::u32(source_len),
            ),
        ));
    }
    for q in 0..MAX_WS_PREFIX {
        evaluate.push(Node::let_bind(
            format!("ip_ws_{q}"),
            is_ws(Expr::var(format!("ip_{q}"))),
        ));
    }
    evaluate.push(Node::let_bind("ident_skip", ws_skip_expr("ip", MAX_WS_PREFIX)));
    evaluate.push(Node::let_bind(
        "ident_start_val",
        Expr::add(Expr::var("post_kw"), Expr::var("ident_skip")),
    ));

    // Step 5: load identifier bytes (up to MAX_IDENT_LEN).
    for i in 0..MAX_IDENT_LEN {
        evaluate.push(Node::let_bind(
            format!("idb_{i}"),
            safe_load(
                "source",
                Expr::add(Expr::var("ident_start_val"), Expr::u32(i)),
                Expr::u32(source_len),
            ),
        ));
    }
    for i in 0..MAX_IDENT_LEN {
        evaluate.push(Node::let_bind(
            format!("idb_cont_{i}"),
            is_continue(Expr::var(format!("idb_{i}"))),
        ));
    }
    // ident_len_val: smallest i where idb_cont_i == 0 (run length of
    // ident-continue bytes from ident_start_val).
    let ident_len_expr = {
        let mut acc = Expr::u32(MAX_IDENT_LEN);
        for i in (0..MAX_IDENT_LEN).rev() {
            acc = Expr::select(
                Expr::eq(Expr::var(format!("idb_cont_{i}")), Expr::u32(0)),
                Expr::u32(i),
                acc,
            );
        }
        acc
    };
    evaluate.push(Node::let_bind("ident_len_val", ident_len_expr));

    // Step 6: per-macro byte equality. For each m in 0..num_macros,
    // load the m-th name's start/end via macro_offsets, length =
    // end - start. The macro matches iff length == ident_len_val AND
    // each byte matches. We unroll the byte comparison up to
    // MAX_IDENT_LEN: byte k matches when k >= macro_len OR
    // macro_name[m_start + k] == idb_k.
    let mut any_match: Expr = Expr::u32(0);
    for m in 0..num_macros {
        let m_start_var = format!("m_{m}_start");
        let m_end_var = format!("m_{m}_end");
        let m_len_var = format!("m_{m}_len");
        evaluate.push(Node::let_bind(
            m_start_var.clone(),
            Expr::cast(
                DataType::U32,
                Expr::load("macro_offsets", Expr::u32(m)),
            ),
        ));
        evaluate.push(Node::let_bind(
            m_end_var.clone(),
            Expr::cast(
                DataType::U32,
                Expr::load("macro_offsets", Expr::u32(m + 1)),
            ),
        ));
        evaluate.push(Node::let_bind(
            m_len_var.clone(),
            Expr::sub(Expr::var(m_end_var.clone()), Expr::var(m_start_var.clone())),
        ));

        // For each k in 0..MAX_IDENT_LEN: byte_match_k = (k >= macro_len)
        // OR (idb_k == macro_name[m_start + k]).
        let mut all_match: Expr = Expr::select(
            Expr::eq(Expr::var(m_len_var.clone()), Expr::var("ident_len_val")),
            Expr::u32(1),
            Expr::u32(0),
        );
        for k in 0..MAX_IDENT_LEN {
            let kth_var = format!("m_{m}_byte_{k}");
            evaluate.push(Node::let_bind(
                kth_var.clone(),
                safe_load(
                    "macro_names_packed",
                    Expr::add(Expr::var(m_start_var.clone()), Expr::u32(k)),
                    Expr::u32(macro_names_len),
                ),
            ));
            // byte_match_k as u32 0/1.
            let in_range = Expr::select(
                Expr::lt(Expr::u32(k), Expr::var(m_len_var.clone())),
                Expr::u32(1),
                Expr::u32(0),
            );
            // bytes_eq = (idb_k == m_byte_k) ? 1 : 0
            let bytes_eq = Expr::select(
                Expr::eq(Expr::var(format!("idb_{k}")), Expr::var(kth_var)),
                Expr::u32(1),
                Expr::u32(0),
            );
            // out-of-range bytes always "match" (don't constrain).
            // out_of_range_pass = (k >= macro_len) ? 1 : 0
            let out_of_range_pass = Expr::select(
                Expr::eq(in_range, Expr::u32(0)),
                Expr::u32(1),
                Expr::u32(0),
            );
            // byte_match_k = out_of_range_pass OR bytes_eq (u32).
            let byte_match_k = Expr::select(
                Expr::or(
                    Expr::eq(out_of_range_pass, Expr::u32(1)),
                    Expr::eq(bytes_eq, Expr::u32(1)),
                ),
                Expr::u32(1),
                Expr::u32(0),
            );
            all_match = Expr::bitand(all_match, byte_match_k);
        }
        // Bind so any_match's nested selects don't blow up the IR depth.
        let m_match_var = format!("m_{m}_match");
        evaluate.push(Node::let_bind(m_match_var.clone(), all_match));
        any_match = Expr::select(
            Expr::eq(Expr::var(m_match_var), Expr::u32(1)),
            Expr::u32(1),
            any_match,
        );
    }
    evaluate.push(Node::let_bind("def_found", any_match));

    // For #ifndef invert; for #ifdef as-is.
    evaluate.push(Node::let_bind(
        "value_out_val",
        Expr::select(
            Expr::eq(Expr::var("kind"), Expr::u32(TOK_PP_IFNDEF)),
            Expr::select(
                Expr::eq(Expr::var("def_found"), Expr::u32(1)),
                Expr::u32(0),
                Expr::u32(1),
            ),
            Expr::var("def_found"),
        ),
    ));

    // Commit only when we actually found `#` in the leading run.
    evaluate.push(Node::if_then(
        Expr::eq(Expr::var("found_hash"), Expr::u32(1)),
        vec![Node::store(
            "directive_values",
            t.clone(),
            Expr::var("value_out_val"),
        )],
    ));

    // Note: this kernel deliberately does NOT pre-zero
    // `directive_values` for non-ifdef/ifndef rows. The host
    // initializes the buffer to zero before dispatch, and the
    // sibling `gpu_if_expression` kernel only writes to if/elif
    // rows. With both kernels touching only their own kind's rows,
    // the two can be safely fused into a single dispatch (the fuser
    // inserts a barrier on the shared `directive_values` write
    // buffer, but pre-zero would clobber the other arm's writes).
    let body: Vec<Node> = vec![
        Node::let_bind("t", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(t.clone(), Expr::u32(num_tokens)),
            vec![
                Node::let_bind("kind", Expr::load("directive_kinds", t.clone())),
                Node::if_then(
                    Expr::or(
                        Expr::eq(Expr::var("kind"), Expr::u32(TOK_PP_IFDEF)),
                        Expr::eq(Expr::var("kind"), Expr::u32(TOK_PP_IFNDEF)),
                    ),
                    evaluate,
                ),
            ],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage("tok_starts", BINDING_TOK_STARTS, BufferAccess::ReadOnly, DataType::U32)
                .with_count(num_tokens.max(1)),
            BufferDecl::storage("tok_lens", BINDING_TOK_LENS, BufferAccess::ReadOnly, DataType::U32)
                .with_count(num_tokens.max(1)),
            BufferDecl::storage(
                "directive_kinds",
                BINDING_DIRECTIVE_KINDS,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(num_tokens.max(1)),
            BufferDecl::storage("source", BINDING_SOURCE, BufferAccess::ReadOnly, DataType::U32)
                .with_count(source_len.div_ceil(4).max(1)),
            BufferDecl::storage(
                "macro_names_packed",
                BINDING_MACRO_NAMES_PACKED,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(macro_names_len.div_ceil(4).max(1)),
            BufferDecl::storage(
                "macro_offsets",
                BINDING_MACRO_OFFSETS,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count((num_macros + 1).max(1)),
            BufferDecl::storage(
                "directive_values",
                BINDING_DIRECTIVE_VALUES,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(num_tokens.max(1)),
        ],
        [256, 1, 1],
        body,
    )
    .with_entry_op_id(OP_ID)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_id_is_canonical_and_stable() {
        assert_eq!(OP_ID, "vyre-libs::parsing::c::preprocess::gpu_ifdef_value");
    }

    #[test]
    fn binding_indices_are_canonical_and_stable() {
        assert_eq!(BINDING_TOK_STARTS, 0);
        assert_eq!(BINDING_TOK_LENS, 1);
        assert_eq!(BINDING_DIRECTIVE_KINDS, 2);
        assert_eq!(BINDING_SOURCE, 3);
        assert_eq!(BINDING_MACRO_NAMES_PACKED, 4);
        assert_eq!(BINDING_MACRO_OFFSETS, 5);
        assert_eq!(BINDING_DIRECTIVE_VALUES, 6);
    }

    #[test]
    fn build_program_returns_well_formed_program() {
        let p = gpu_ifdef_value(8, 64, 16, 2);
        assert_eq!(p.buffers().len(), 7);
        assert_eq!(p.workgroup_size(), [256, 1, 1]);
    }
}
