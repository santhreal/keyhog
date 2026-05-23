//! GPU `#if` / `#elif` expression evaluator.
//!
//! Phase 17b.4: per-thread iterative shunting-yard parser over the
//! payload bytes of one `#if`/`#elif` directive. Composes the literal
//! and char-constant scanners from 17b.2/17b.3 and the defined-name
//! lookup table from 17b.1.
//!
//! ## Stack design
//!
//! Per-thread fixed-depth stacks (depth 16): value stack and operator
//! stack. Both backed by 16 let_bind slots each — this keeps the IR
//! free of shared-memory dependencies and gives every thread an
//! independent scratch area. Real `#if` expressions in production C
//! corpora are usually 4-8 deep (paren nesting + ternary). 16 is a
//! comfortable cap; deeper expressions force the kernel into a `done`
//! state with the failsafe value of 0.
//!
//! ## Operator codes
//!
//! Stored on the op stack as small u32 opcodes so the apply step can
//! switch on them. Higher numeric value = higher precedence (loosely
//! ordered to match the C precedence ladder; the apply loop uses the
//! `precedence_of(op)` helper rather than the raw code so re-ordering
//! is safe).
//!
//! ## Operand inputs (binding layout)
//!
//! Inputs:
//!   - `tok_starts` (U32) — per-token byte offset.
//!   - `tok_lens` (U32) — per-token byte length.
//!   - `directive_kinds` (U32) — output of `gpu_directive_metadata`.
//!   - `source` (U32 packed bytes) — original source bytes.
//!   - `macro_names_packed` (U32 packed bytes), `macro_offsets` (U32),
//!     `macro_values` (U32) — GNU/Clang builtin perfect-hash table followed by
//!     the defined object-like macro integer values.
//!
//! Outputs:
//!   - `directive_values` (U32) — per-token value: `1`/`0` for
//!     `if`/`elif` rows; `0` for every other directive kind.
//!
//! ## Scope of this commit (17b.4 first cut)
//!
//! Operators supported:
//!   - Unary: `!`, `~`, `+`, `-`
//!   - Multiplicative: `*`, `/`, `%`
//!   - Additive: `+`, `-`
//!   - Shift: `<<`, `>>`
//!   - Relational: `<`, `<=`, `>`, `>=`
//!   - Equality: `==`, `!=`
//!   - Bitwise: `&`, `^`, `|`
//!   - Logical: `&&`, `||`
//!   - Ternary: `?:`
//!   - Parens: `(` `)`
//!   - `defined(X)` and `defined X`
//!   - Integer literals (via inlined logic from 17b.2)
//!   - Char constants (via inlined logic from 17b.3)
//!   - Identifier macro reference: bare ident → object-like integer macro value, or 0 if absent
//!
//! Tested under `tests/gpu_if_expression_roundtrip.rs` against the CPU
//! `reference_c_preprocessor_directive_metadata` for `if`/`elif` rows.

use crate::parsing::c::lex::tokens::{TOK_PP_ELIF, TOK_PP_IF};
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

mod abi;
mod apply;
mod byte_load;
mod opcodes;
mod stack;
#[cfg(test)]
mod tests;

pub use abi::{
    BINDING_DIRECTIVE_KINDS, BINDING_DIRECTIVE_VALUES, BINDING_MACRO_NAMES_PACKED,
    BINDING_MACRO_OFFSETS, BINDING_MACRO_VALUES, BINDING_SOURCE, BINDING_TOK_LENS,
    BINDING_TOK_STARTS, MAX_IDENT_LEN, MAX_PAYLOAD_BYTES, OP_ID, STACK_DEPTH,
};
use apply::apply_top_op;
use byte_load::{load_packed_byte_u32, safe_load_src_expr};
use opcodes::*;
use stack::{peek_stack, pop_stack, push_stack};

fn fnv1a32_bytes(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn ident_hash_equals(bytes: &'static [u8]) -> Expr {
    Expr::and(
        Expr::eq(Expr::var("ident_len"), Expr::u32(bytes.len() as u32)),
        Expr::eq(Expr::var("ident_hash"), Expr::u32(fnv1a32_bytes(bytes))),
    )
}

fn source_at_equals(start_var: &'static str, bytes: &'static [u8], source_byte_len: Expr) -> Expr {
    let mut expr = Expr::eq(Expr::u32(1), Expr::u32(1));
    for (idx, byte) in bytes.iter().copied().enumerate() {
        expr = Expr::and(
            expr,
            Expr::eq(
                safe_load_src_expr(
                    Expr::add(Expr::var(start_var), Expr::u32(idx as u32)),
                    source_byte_len.clone(),
                ),
                Expr::u32(u32::from(byte)),
            ),
        );
    }
    expr
}

fn push_gnu_builtin_hash_lookup(
    nodes: &mut Vec<Node>,
    prefix: &'static str,
    hash_var: &str,
    out_var: &str,
) {
    let slot_var = format!("{prefix}_lookup_slot");
    let value_var = format!("{prefix}_lookup_value");
    nodes.push(Node::let_bind(
        &slot_var,
        Expr::rem(
            Expr::mul(
                Expr::var(hash_var),
                Expr::u32(crate::parsing::c::parse::gnu_builtins::GPU_BUILTIN_HASH_TABLE_SEED),
            ),
            Expr::u32(crate::parsing::c::parse::gnu_builtins::GPU_BUILTIN_HASH_TABLE_SIZE as u32),
        ),
    ));
    nodes.push(Node::let_bind(
        &value_var,
        Expr::load("macro_values", Expr::var(&slot_var)),
    ));
    nodes.push(Node::let_bind(
        out_var,
        Expr::select(
            Expr::and(
                Expr::ne(Expr::var(&value_var), Expr::u32(0)),
                Expr::eq(Expr::var(&value_var), Expr::var(hash_var)),
            ),
            Expr::u32(1),
            Expr::u32(0),
        ),
    ));
}

fn push_has_builtin_call_parser(
    nodes: &mut Vec<Node>,
    prefix: &'static str,
    start_var: &'static str,
    tok_end_var: &'static str,
    tok_len_var: &'static str,
    source_byte_len: Expr,
    scan_out_var: &'static str,
    found_var: &'static str,
    value_var: &'static str,
) {
    let is_builtin = format!("{prefix}_is_builtin");
    let is_constexpr_builtin = format!("{prefix}_is_constexpr_builtin");
    let pos = format!("{prefix}_pos");
    let ws_done = format!("{prefix}_ws_done");
    let ws_loop = format!("{prefix}_ws");
    let ws_b = format!("{prefix}_ws_b");
    let ws_is_ws = format!("{prefix}_ws_is_ws");
    let had_paren = format!("{prefix}_had_paren");
    let ws2_done = format!("{prefix}_ws2_done");
    let ws2_loop = format!("{prefix}_ws2");
    let ws2_b = format!("{prefix}_ws2_b");
    let ws2_is_ws = format!("{prefix}_ws2_is_ws");
    let arg_base = format!("{prefix}_arg_base");
    let arg_len = format!("{prefix}_arg_len");
    let hash = format!("{prefix}_hash");
    let arg_loop = format!("{prefix}_arg_id");
    let arg_pos = format!("{prefix}_arg_pos");
    let arg_b = format!("{prefix}_arg_b");
    let arg_alpha = format!("{prefix}_arg_alpha");
    let arg_digit = format!("{prefix}_arg_digit");
    let arg_under = format!("{prefix}_arg_under");
    let arg_cont = format!("{prefix}_arg_cont");
    let known = format!("{prefix}_known");
    let ws3_done = format!("{prefix}_ws3_done");
    let ws3_loop = format!("{prefix}_ws3");
    let ws3_b = format!("{prefix}_ws3_b");
    let ws3_is_ws = format!("{prefix}_ws3_is_ws");
    let had_close = format!("{prefix}_had_close");

    nodes.push(Node::let_bind(
        &is_builtin,
        Expr::select(
            source_at_equals(start_var, b"__has_builtin", source_byte_len.clone()),
            Expr::u32(1),
            Expr::u32(0),
        ),
    ));
    nodes.push(Node::let_bind(
        &is_constexpr_builtin,
        Expr::select(
            source_at_equals(
                start_var,
                b"__has_constexpr_builtin",
                source_byte_len.clone(),
            ),
            Expr::u32(1),
            Expr::u32(0),
        ),
    ));
    nodes.push(Node::if_then(
        Expr::and(
            Expr::eq(Expr::var(found_var), Expr::u32(0)),
            Expr::or(
                Expr::eq(Expr::var(&is_builtin), Expr::u32(1)),
                Expr::eq(Expr::var(&is_constexpr_builtin), Expr::u32(1)),
            ),
        ),
        {
            let mut call_nodes: Vec<Node> = Vec::new();
            call_nodes.push(Node::let_bind(
                &pos,
                Expr::add(
                    Expr::var(start_var),
                    Expr::select(
                        Expr::eq(Expr::var(&is_builtin), Expr::u32(1)),
                        Expr::u32(13),
                        Expr::u32(23),
                    ),
                ),
            ));
            call_nodes.push(Node::let_bind(&ws_done, Expr::u32(0)));
            call_nodes.push(Node::loop_for(
                &ws_loop,
                Expr::u32(0),
                Expr::var(tok_len_var),
                vec![Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var(&ws_done), Expr::u32(0)),
                        Expr::lt(Expr::var(&pos), Expr::var(tok_end_var)),
                    ),
                    vec![
                        Node::let_bind(
                            &ws_b,
                            safe_load_src_expr(Expr::var(&pos), source_byte_len.clone()),
                        ),
                        Node::let_bind(
                            &ws_is_ws,
                            Expr::select(
                                Expr::or(
                                    Expr::or(
                                        Expr::eq(Expr::var(&ws_b), Expr::u32(b' ' as u32)),
                                        Expr::eq(Expr::var(&ws_b), Expr::u32(b'\t' as u32)),
                                    ),
                                    Expr::or(
                                        Expr::eq(Expr::var(&ws_b), Expr::u32(0x0B)),
                                        Expr::eq(Expr::var(&ws_b), Expr::u32(0x0C)),
                                    ),
                                ),
                                Expr::u32(1),
                                Expr::u32(0),
                            ),
                        ),
                        Node::if_then_else(
                            Expr::eq(Expr::var(&ws_is_ws), Expr::u32(1)),
                            vec![Node::assign(&pos, Expr::add(Expr::var(&pos), Expr::u32(1)))],
                            vec![Node::assign(&ws_done, Expr::u32(1))],
                        ),
                    ],
                )],
            ));
            call_nodes.push(Node::let_bind(
                &had_paren,
                Expr::select(
                    Expr::eq(
                        safe_load_src_expr(Expr::var(&pos), source_byte_len.clone()),
                        Expr::u32(b'(' as u32),
                    ),
                    Expr::u32(1),
                    Expr::u32(0),
                ),
            ));
            call_nodes.push(Node::if_then(
                Expr::eq(Expr::var(&had_paren), Expr::u32(1)),
                {
                    let mut paren_nodes: Vec<Node> = Vec::new();
                    paren_nodes.push(Node::assign(&pos, Expr::add(Expr::var(&pos), Expr::u32(1))));
                    paren_nodes.push(Node::let_bind(&ws2_done, Expr::u32(0)));
                    paren_nodes.push(Node::loop_for(
                        &ws2_loop,
                        Expr::u32(0),
                        Expr::var(tok_len_var),
                        vec![Node::if_then(
                            Expr::and(
                                Expr::eq(Expr::var(&ws2_done), Expr::u32(0)),
                                Expr::lt(Expr::var(&pos), Expr::var(tok_end_var)),
                            ),
                            vec![
                                Node::let_bind(
                                    &ws2_b,
                                    safe_load_src_expr(Expr::var(&pos), source_byte_len.clone()),
                                ),
                                Node::let_bind(
                                    &ws2_is_ws,
                                    Expr::select(
                                        Expr::or(
                                            Expr::or(
                                                Expr::eq(Expr::var(&ws2_b), Expr::u32(b' ' as u32)),
                                                Expr::eq(
                                                    Expr::var(&ws2_b),
                                                    Expr::u32(b'\t' as u32),
                                                ),
                                            ),
                                            Expr::or(
                                                Expr::eq(Expr::var(&ws2_b), Expr::u32(0x0B)),
                                                Expr::eq(Expr::var(&ws2_b), Expr::u32(0x0C)),
                                            ),
                                        ),
                                        Expr::u32(1),
                                        Expr::u32(0),
                                    ),
                                ),
                                Node::if_then_else(
                                    Expr::eq(Expr::var(&ws2_is_ws), Expr::u32(1)),
                                    vec![Node::assign(
                                        &pos,
                                        Expr::add(Expr::var(&pos), Expr::u32(1)),
                                    )],
                                    vec![Node::assign(&ws2_done, Expr::u32(1))],
                                ),
                            ],
                        )],
                    ));
                    paren_nodes.push(Node::let_bind(
                        &arg_base,
                        Expr::add(Expr::var(&pos), Expr::u32(0)),
                    ));
                    paren_nodes.push(Node::let_bind(&arg_len, Expr::u32(0)));
                    paren_nodes.push(Node::let_bind(&hash, Expr::u32(0x811c_9dc5)));
                    paren_nodes.push(Node::loop_for(
                        &arg_loop,
                        Expr::u32(0),
                        Expr::select(
                            Expr::lt(Expr::var(&arg_base), Expr::var(tok_end_var)),
                            Expr::sub(Expr::var(tok_end_var), Expr::var(&arg_base)),
                            Expr::u32(0),
                        ),
                        vec![Node::if_then(
                            Expr::eq(Expr::var(&arg_len), Expr::var(&arg_loop)),
                            vec![
                                Node::let_bind(
                                    &arg_pos,
                                    Expr::add(Expr::var(&arg_base), Expr::var(&arg_loop)),
                                ),
                                Node::if_then(
                                    Expr::lt(Expr::var(&arg_pos), Expr::var(tok_end_var)),
                                    vec![
                                        Node::let_bind(
                                            &arg_b,
                                            safe_load_src_expr(
                                                Expr::var(&arg_pos),
                                                source_byte_len.clone(),
                                            ),
                                        ),
                                        Node::let_bind(
                                            &arg_alpha,
                                            Expr::select(
                                                Expr::or(
                                                    Expr::and(
                                                        Expr::ge(
                                                            Expr::var(&arg_b),
                                                            Expr::u32(b'a' as u32),
                                                        ),
                                                        Expr::le(
                                                            Expr::var(&arg_b),
                                                            Expr::u32(b'z' as u32),
                                                        ),
                                                    ),
                                                    Expr::and(
                                                        Expr::ge(
                                                            Expr::var(&arg_b),
                                                            Expr::u32(b'A' as u32),
                                                        ),
                                                        Expr::le(
                                                            Expr::var(&arg_b),
                                                            Expr::u32(b'Z' as u32),
                                                        ),
                                                    ),
                                                ),
                                                Expr::u32(1),
                                                Expr::u32(0),
                                            ),
                                        ),
                                        Node::let_bind(
                                            &arg_digit,
                                            Expr::select(
                                                Expr::and(
                                                    Expr::ge(
                                                        Expr::var(&arg_b),
                                                        Expr::u32(b'0' as u32),
                                                    ),
                                                    Expr::le(
                                                        Expr::var(&arg_b),
                                                        Expr::u32(b'9' as u32),
                                                    ),
                                                ),
                                                Expr::u32(1),
                                                Expr::u32(0),
                                            ),
                                        ),
                                        Node::let_bind(
                                            &arg_under,
                                            Expr::select(
                                                Expr::eq(Expr::var(&arg_b), Expr::u32(b'_' as u32)),
                                                Expr::u32(1),
                                                Expr::u32(0),
                                            ),
                                        ),
                                        Node::let_bind(
                                            &arg_cont,
                                            Expr::select(
                                                Expr::or(
                                                    Expr::or(
                                                        Expr::eq(
                                                            Expr::var(&arg_alpha),
                                                            Expr::u32(1),
                                                        ),
                                                        Expr::eq(
                                                            Expr::var(&arg_digit),
                                                            Expr::u32(1),
                                                        ),
                                                    ),
                                                    Expr::eq(Expr::var(&arg_under), Expr::u32(1)),
                                                ),
                                                Expr::u32(1),
                                                Expr::u32(0),
                                            ),
                                        ),
                                        Node::if_then(
                                            Expr::eq(Expr::var(&arg_cont), Expr::u32(1)),
                                            vec![
                                                Node::assign(
                                                    &hash,
                                                    Expr::mul(
                                                        Expr::bitxor(
                                                            Expr::var(&hash),
                                                            Expr::var(&arg_b),
                                                        ),
                                                        Expr::u32(0x0100_0193),
                                                    ),
                                                ),
                                                Node::assign(
                                                    &arg_len,
                                                    Expr::add(Expr::var(&arg_len), Expr::u32(1)),
                                                ),
                                            ],
                                        ),
                                    ],
                                ),
                            ],
                        )],
                    ));
                    paren_nodes.push(Node::assign(
                        &pos,
                        Expr::add(Expr::var(&arg_base), Expr::var(&arg_len)),
                    ));
                    push_gnu_builtin_hash_lookup(&mut paren_nodes, prefix, &hash, &known);
                    paren_nodes.push(Node::let_bind(&ws3_done, Expr::u32(0)));
                    paren_nodes.push(Node::loop_for(
                        &ws3_loop,
                        Expr::u32(0),
                        Expr::var(tok_len_var),
                        vec![Node::if_then(
                            Expr::and(
                                Expr::eq(Expr::var(&ws3_done), Expr::u32(0)),
                                Expr::lt(Expr::var(&pos), Expr::var(tok_end_var)),
                            ),
                            vec![
                                Node::let_bind(
                                    &ws3_b,
                                    safe_load_src_expr(Expr::var(&pos), source_byte_len.clone()),
                                ),
                                Node::let_bind(
                                    &ws3_is_ws,
                                    Expr::select(
                                        Expr::or(
                                            Expr::or(
                                                Expr::eq(Expr::var(&ws3_b), Expr::u32(b' ' as u32)),
                                                Expr::eq(
                                                    Expr::var(&ws3_b),
                                                    Expr::u32(b'\t' as u32),
                                                ),
                                            ),
                                            Expr::or(
                                                Expr::eq(Expr::var(&ws3_b), Expr::u32(0x0B)),
                                                Expr::eq(Expr::var(&ws3_b), Expr::u32(0x0C)),
                                            ),
                                        ),
                                        Expr::u32(1),
                                        Expr::u32(0),
                                    ),
                                ),
                                Node::if_then_else(
                                    Expr::eq(Expr::var(&ws3_is_ws), Expr::u32(1)),
                                    vec![Node::assign(
                                        &pos,
                                        Expr::add(Expr::var(&pos), Expr::u32(1)),
                                    )],
                                    vec![Node::assign(&ws3_done, Expr::u32(1))],
                                ),
                            ],
                        )],
                    ));
                    paren_nodes.push(Node::let_bind(
                        &had_close,
                        Expr::select(
                            Expr::eq(
                                safe_load_src_expr(Expr::var(&pos), source_byte_len.clone()),
                                Expr::u32(b')' as u32),
                            ),
                            Expr::u32(1),
                            Expr::u32(0),
                        ),
                    ));
                    paren_nodes.push(Node::if_then(
                        Expr::eq(Expr::var(&had_close), Expr::u32(1)),
                        vec![
                            Node::assign(scan_out_var, Expr::add(Expr::var(&pos), Expr::u32(1))),
                            Node::assign(found_var, Expr::u32(1)),
                            Node::assign(value_var, Expr::var(&known)),
                        ],
                    ));
                    paren_nodes
                },
            ));
            call_nodes
        },
    ));
}

/// Build the 17b.4 `#if`/`#elif` evaluator `Program`.
///
/// `macro_names_len` and `num_macros` were previously construction-time
/// parameters baked into safe_load bounds and buffer counts. They are
/// no longer accepted: the kernel reads its macro count and packed-name
/// byte capacity at runtime via `Expr::buf_len("macro_offsets")` and
/// `Expr::buf_len("macro_names_packed")`. One program shape per process.
#[must_use]
pub fn gpu_if_expression(num_tokens: u32, source_len: u32) -> Program {
    let _ = source_len;
    let source_byte_len = Expr::mul(Expr::buf_len("source"), Expr::u32(4));
    let t = Expr::var("t");

    let safe_load_src = |addr: Expr| -> Expr { safe_load_src_expr(addr, source_byte_len.clone()) };

    let mut body: Vec<Node> = Vec::new();
    body.push(Node::let_bind("t", Expr::InvocationId { axis: 0 }));
    body.push(Node::if_then(
        Expr::lt(t.clone(), Expr::u32(num_tokens)),
        {
            let mut inner: Vec<Node> = Vec::new();
            inner.push(Node::let_bind("kind", Expr::load("directive_kinds", t.clone())));
            inner.push(Node::let_bind("expr_value_out", Expr::u32(0)));
            inner.push(Node::let_bind("expr_invalid", Expr::u32(0)));

            // Only if/elif tokens get evaluated by THIS kernel.
            let mut evaluate: Vec<Node> = Vec::new();
            evaluate.push(Node::let_bind("tok_start", Expr::load("tok_starts", t.clone())));
            evaluate.push(Node::let_bind("tok_len", Expr::load("tok_lens", t.clone())));
            evaluate.push(Node::let_bind(
                "tok_end",
                Expr::add(Expr::var("tok_start"), Expr::var("tok_len")),
            ));
            // Step past leading whitespace, `#`, optional whitespace,
            // and the keyword (`if` = 2, `elif` = 4). After this
            // `scan_pos` points at the first byte of the payload.
            evaluate.push(Node::let_bind(
                "keyword_len",
                Expr::select(
                    Expr::eq(Expr::var("kind"), Expr::u32(TOK_PP_IF)),
                    Expr::u32(2),
                    Expr::u32(4),
                ),
            ));
            evaluate.push(Node::let_bind("scan_pos", Expr::var("tok_start")));
            for step in &["pre_hash", "pre_kw", "pre_payload"] {
                let done = format!("ws_done_{step}");
                evaluate.push(Node::let_bind(&done, Expr::u32(0)));
                evaluate.push(Node::loop_for(
                    &format!("ws_{step}"),
                    Expr::u32(0),
                    Expr::var("tok_len"),
                    vec![Node::if_then(
                        Expr::eq(Expr::var(&done), Expr::u32(0)),
                        vec![
                            Node::let_bind("wb", safe_load_src(Expr::var("scan_pos"))),
                            Node::let_bind(
                                "wb_ws",
                                Expr::select(
                                    Expr::or(
                                        Expr::or(
                                            Expr::eq(Expr::var("wb"), Expr::u32(b' ' as u32)),
                                            Expr::eq(Expr::var("wb"), Expr::u32(b'\t' as u32)),
                                        ),
                                        Expr::or(
                                            Expr::eq(Expr::var("wb"), Expr::u32(0x0B)),
                                            Expr::eq(Expr::var("wb"), Expr::u32(0x0C)),
                                        ),
                                    ),
                                    Expr::u32(1),
                                    Expr::u32(0),
                                ),
                            ),
                            Node::if_then_else(
                                Expr::eq(Expr::var("wb_ws"), Expr::u32(1)),
                                vec![Node::assign(
                                    "scan_pos",
                                    Expr::add(Expr::var("scan_pos"), Expr::u32(1)),
                                )],
                                vec![Node::assign(&done, Expr::u32(1))],
                            ),
                        ],
                    )],
                ));
                if *step == "pre_hash" {
                    // Step past the `#`.
                    evaluate.push(Node::if_then(
                        Expr::eq(safe_load_src(Expr::var("scan_pos")), Expr::u32(b'#' as u32)),
                        vec![Node::assign(
                            "scan_pos",
                            Expr::add(Expr::var("scan_pos"), Expr::u32(1)),
                        )],
                    ));
                } else if *step == "pre_kw" {
                    // Step past keyword bytes.
                    evaluate.push(Node::assign(
                        "scan_pos",
                        Expr::add(Expr::var("scan_pos"), Expr::var("keyword_len")),
                    ));
                }
            }

            // ---------- Initialise stacks ----------
            evaluate.push(Node::let_bind("vsp", Expr::u32(0)));
            evaluate.push(Node::let_bind("osp", Expr::u32(0)));
            for slot in 0..STACK_DEPTH {
                evaluate.push(Node::let_bind(&format!("val_stack_{slot}"), Expr::u32(0)));
                evaluate.push(Node::let_bind(&format!("op_stack_{slot}"), Expr::u32(0)));
            }
            // Last-token-was-value flag — drives unary vs binary
            // disambiguation for `+` / `-`.
            evaluate.push(Node::let_bind("last_was_value", Expr::u32(0)));
            evaluate.push(Node::let_bind("scan_done", Expr::u32(0)));

            // ---------- Main scan loop ----------
            evaluate.push(Node::loop_for(
                "scan_iter",
                Expr::u32(0),
                Expr::var("tok_len"),
                vec![Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("scan_done"), Expr::u32(0)),
                        Expr::lt(Expr::var("scan_pos"), Expr::var("tok_end")),
                    ),
                    {
                        let mut iter_body: Vec<Node> = Vec::new();
                        // Skip horizontal whitespace. Production pipeline
                        // inputs have already passed phase-2 line splicing
                        // and phase-3 comment replacement, so this evaluator
                        // does not duplicate comment scanning in the hot loop.
                        iter_body.push(Node::let_bind("inner_ws_done", Expr::u32(0)));
                        iter_body.push(Node::loop_for(
                            "ws_skip",
                            Expr::u32(0),
                            Expr::var("tok_len"),
                            vec![Node::if_then(
                                Expr::and(
                                    Expr::eq(Expr::var("inner_ws_done"), Expr::u32(0)),
                                    Expr::lt(Expr::var("scan_pos"), Expr::var("tok_end")),
                                ),
                                vec![
                                    Node::let_bind("wb2", safe_load_src(Expr::var("scan_pos"))),
                                    Node::let_bind(
                                        "wb2_ws",
                                        Expr::select(
                                            Expr::or(
                                                Expr::or(
                                                    Expr::eq(Expr::var("wb2"), Expr::u32(b' ' as u32)),
                                                    Expr::eq(Expr::var("wb2"), Expr::u32(b'\t' as u32)),
                                                ),
                                                Expr::or(
                                                    Expr::eq(Expr::var("wb2"), Expr::u32(0x0B)),
                                                    Expr::eq(Expr::var("wb2"), Expr::u32(0x0C)),
                                                ),
                                            ),
                                            Expr::u32(1),
                                            Expr::u32(0),
                                        ),
                                    ),
                                    Node::if_then_else(
                                        Expr::eq(Expr::var("wb2_ws"), Expr::u32(1)),
                                        vec![Node::assign(
                                            "scan_pos",
                                            Expr::add(Expr::var("scan_pos"), Expr::u32(1)),
                                        )],
                                        vec![Node::assign("inner_ws_done", Expr::u32(1))],
                                    ),
                                ],
                            )],
                        ));
                        // End of payload?
                        iter_body.push(Node::if_then(
                            Expr::ge(Expr::var("scan_pos"), Expr::var("tok_end")),
                            vec![Node::assign("scan_done", Expr::u32(1))],
                        ));
                        // Read the next byte.
                        iter_body.push(Node::if_then(
                            Expr::eq(Expr::var("scan_done"), Expr::u32(0)),
                            {
                                let mut classify: Vec<Node> = Vec::new();
                                classify.push(Node::let_bind("c", safe_load_src(Expr::var("scan_pos"))));
                                classify.push(Node::let_bind("c1", safe_load_src(Expr::add(Expr::var("scan_pos"), Expr::u32(1)))));

                                // ---- Integer literal ----
                                classify.push(Node::let_bind(
                                    "is_dec_digit",
                                    Expr::select(
                                        Expr::and(
                                            Expr::ge(Expr::var("c"), Expr::u32(b'0' as u32)),
                                            Expr::le(Expr::var("c"), Expr::u32(b'9' as u32)),
                                        ),
                                        Expr::u32(1),
                                        Expr::u32(0),
                                    ),
                                ));
                                classify.push(Node::if_then(
                                    Expr::eq(Expr::var("is_dec_digit"), Expr::u32(1)),
                                    {
                                        let mut lit_nodes: Vec<Node> = Vec::new();
                                        // Inline integer-literal scan
                                        // (mirrors gpu_int_literal_scan
                                        // semantics; simplified to u32
                                        // wrapping). Detect radix.
                                        lit_nodes.push(Node::let_bind(
                                            "is_hex",
                                            Expr::select(
                                                Expr::and(
                                                    Expr::eq(Expr::var("c"), Expr::u32(b'0' as u32)),
                                                    Expr::or(
                                                        Expr::eq(Expr::var("c1"), Expr::u32(b'x' as u32)),
                                                        Expr::eq(Expr::var("c1"), Expr::u32(b'X' as u32)),
                                                    ),
                                                ),
                                                Expr::u32(1),
                                                Expr::u32(0),
                                            ),
                                        ));
                                        lit_nodes.push(Node::let_bind(
                                            "is_bin",
                                            Expr::select(
                                                Expr::and(
                                                    Expr::eq(Expr::var("c"), Expr::u32(b'0' as u32)),
                                                    Expr::or(
                                                        Expr::eq(Expr::var("c1"), Expr::u32(b'b' as u32)),
                                                        Expr::eq(Expr::var("c1"), Expr::u32(b'B' as u32)),
                                                    ),
                                                ),
                                                Expr::u32(1),
                                                Expr::u32(0),
                                            ),
                                        ));
                                        lit_nodes.push(Node::let_bind(
                                            "is_oct",
                                            Expr::select(
                                                Expr::and(
                                                    Expr::eq(Expr::var("c"), Expr::u32(b'0' as u32)),
                                                    Expr::and(
                                                        Expr::eq(Expr::var("is_hex"), Expr::u32(0)),
                                                        Expr::eq(Expr::var("is_bin"), Expr::u32(0)),
                                                    ),
                                                ),
                                                Expr::u32(1),
                                                Expr::u32(0),
                                            ),
                                        ));
                                        lit_nodes.push(Node::let_bind(
                                            "lit_radix",
                                            Expr::select(
                                                Expr::eq(Expr::var("is_hex"), Expr::u32(1)),
                                                Expr::u32(16),
                                                Expr::select(
                                                    Expr::eq(Expr::var("is_bin"), Expr::u32(1)),
                                                    Expr::u32(2),
                                                    Expr::select(
                                                        Expr::eq(Expr::var("is_oct"), Expr::u32(1)),
                                                        Expr::u32(8),
                                                        Expr::u32(10),
                                                    ),
                                                ),
                                            ),
                                        ));
                                        lit_nodes.push(Node::let_bind(
                                            "lit_skip",
                                            Expr::select(
                                                Expr::or(
                                                    Expr::eq(Expr::var("is_hex"), Expr::u32(1)),
                                                    Expr::eq(Expr::var("is_bin"), Expr::u32(1)),
                                                ),
                                                Expr::u32(2),
                                                Expr::u32(0),
                                            ),
                                        ));
                                        lit_nodes.push(Node::assign(
                                            "scan_pos",
                                            Expr::add(Expr::var("scan_pos"), Expr::var("lit_skip")),
                                        ));
                                        lit_nodes.push(Node::let_bind("lit_value", Expr::u32(0)));
                                        lit_nodes.push(Node::let_bind("lit_done", Expr::u32(0)));
                                        lit_nodes.push(Node::loop_for(
                                            "lit_d",
                                            Expr::u32(0),
                                            Expr::var("tok_len"),
                                            vec![Node::if_then(
                                                Expr::and(
                                                    Expr::eq(Expr::var("lit_done"), Expr::u32(0)),
                                                    Expr::lt(Expr::var("scan_pos"), Expr::var("tok_end")),
                                                ),
                                                vec![
                                                    Node::let_bind("ldb", safe_load_src(Expr::var("scan_pos"))),
                                                    Node::let_bind(
                                                        "ldb1",
                                                        safe_load_src(Expr::add(
                                                            Expr::var("scan_pos"),
                                                            Expr::u32(1),
                                                        )),
                                                    ),
                                                    Node::let_bind(
                                                        "ld_dec",
                                                        Expr::select(
                                                            Expr::and(
                                                                Expr::ge(Expr::var("ldb"), Expr::u32(b'0' as u32)),
                                                                Expr::le(Expr::var("ldb"), Expr::u32(b'9' as u32)),
                                                            ),
                                                            Expr::u32(1),
                                                            Expr::u32(0),
                                                        ),
                                                    ),
                                                    Node::let_bind(
                                                        "ld_lc",
                                                        Expr::select(
                                                            Expr::and(
                                                                Expr::ge(Expr::var("ldb"), Expr::u32(b'a' as u32)),
                                                                Expr::le(Expr::var("ldb"), Expr::u32(b'f' as u32)),
                                                            ),
                                                            Expr::u32(1),
                                                            Expr::u32(0),
                                                        ),
                                                    ),
                                                    Node::let_bind(
                                                        "ld_uc",
                                                        Expr::select(
                                                            Expr::and(
                                                                Expr::ge(Expr::var("ldb"), Expr::u32(b'A' as u32)),
                                                                Expr::le(Expr::var("ldb"), Expr::u32(b'F' as u32)),
                                                            ),
                                                            Expr::u32(1),
                                                            Expr::u32(0),
                                                        ),
                                                    ),
                                                    Node::let_bind(
                                                        "ld_v",
                                                        Expr::select(
                                                            Expr::eq(Expr::var("ld_dec"), Expr::u32(1)),
                                                            Expr::sub(Expr::var("ldb"), Expr::u32(b'0' as u32)),
                                                            Expr::select(
                                                                Expr::eq(Expr::var("ld_lc"), Expr::u32(1)),
                                                                Expr::add(
                                                                    Expr::sub(Expr::var("ldb"), Expr::u32(b'a' as u32)),
                                                                    Expr::u32(10),
                                                                ),
                                                                Expr::select(
                                                                    Expr::eq(Expr::var("ld_uc"), Expr::u32(1)),
                                                                    Expr::add(
                                                                        Expr::sub(Expr::var("ldb"), Expr::u32(b'A' as u32)),
                                                                        Expr::u32(10),
                                                                    ),
                                                                    Expr::u32(99),
                                                                ),
                                                            ),
                                                        ),
                                                    ),
                                                    Node::let_bind(
                                                        "ld1_dec",
                                                        Expr::select(
                                                            Expr::and(
                                                                Expr::ge(Expr::var("ldb1"), Expr::u32(b'0' as u32)),
                                                                Expr::le(Expr::var("ldb1"), Expr::u32(b'9' as u32)),
                                                            ),
                                                            Expr::u32(1),
                                                            Expr::u32(0),
                                                        ),
                                                    ),
                                                    Node::let_bind(
                                                        "ld1_lc",
                                                        Expr::select(
                                                            Expr::and(
                                                                Expr::ge(Expr::var("ldb1"), Expr::u32(b'a' as u32)),
                                                                Expr::le(Expr::var("ldb1"), Expr::u32(b'f' as u32)),
                                                            ),
                                                            Expr::u32(1),
                                                            Expr::u32(0),
                                                        ),
                                                    ),
                                                    Node::let_bind(
                                                        "ld1_uc",
                                                        Expr::select(
                                                            Expr::and(
                                                                Expr::ge(Expr::var("ldb1"), Expr::u32(b'A' as u32)),
                                                                Expr::le(Expr::var("ldb1"), Expr::u32(b'F' as u32)),
                                                            ),
                                                            Expr::u32(1),
                                                            Expr::u32(0),
                                                        ),
                                                    ),
                                                    Node::let_bind(
                                                        "ld1_v",
                                                        Expr::select(
                                                            Expr::eq(Expr::var("ld1_dec"), Expr::u32(1)),
                                                            Expr::sub(Expr::var("ldb1"), Expr::u32(b'0' as u32)),
                                                            Expr::select(
                                                                Expr::eq(Expr::var("ld1_lc"), Expr::u32(1)),
                                                                Expr::add(
                                                                    Expr::sub(Expr::var("ldb1"), Expr::u32(b'a' as u32)),
                                                                    Expr::u32(10),
                                                                ),
                                                                Expr::select(
                                                                    Expr::eq(Expr::var("ld1_uc"), Expr::u32(1)),
                                                                    Expr::add(
                                                                        Expr::sub(Expr::var("ldb1"), Expr::u32(b'A' as u32)),
                                                                        Expr::u32(10),
                                                                    ),
                                                                    Expr::u32(99),
                                                                ),
                                                            ),
                                                        ),
                                                    ),
                                                    Node::let_bind(
                                                        "lit_separator",
                                                        Expr::select(
                                                            Expr::and(
                                                                Expr::eq(Expr::var("ldb"), Expr::u32(b'\'' as u32)),
                                                                Expr::lt(Expr::var("ld1_v"), Expr::var("lit_radix")),
                                                            ),
                                                            Expr::u32(1),
                                                            Expr::u32(0),
                                                        ),
                                                    ),
                                                    Node::if_then_else(
                                                        Expr::or(
                                                            Expr::lt(Expr::var("ld_v"), Expr::var("lit_radix")),
                                                            Expr::eq(Expr::var("lit_separator"), Expr::u32(1)),
                                                        ),
                                                        vec![
                                                            Node::assign(
                                                                "lit_value",
                                                                Expr::select(
                                                                    Expr::eq(Expr::var("lit_separator"), Expr::u32(1)),
                                                                    Expr::var("lit_value"),
                                                                    Expr::add(
                                                                        Expr::mul(
                                                                            Expr::var("lit_value"),
                                                                            Expr::var("lit_radix"),
                                                                        ),
                                                                        Expr::var("ld_v"),
                                                                    ),
                                                                ),
                                                            ),
                                                            Node::assign(
                                                                "scan_pos",
                                                                Expr::add(Expr::var("scan_pos"), Expr::u32(1)),
                                                            ),
                                                        ],
                                                        vec![Node::assign("lit_done", Expr::u32(1))],
                                                    ),
                                                ],
                                            )],
                                        ));
                                        // Skip suffix u/U/l/L/z/Z/wb/WB (up to 4 loop iterations).
                                        lit_nodes.push(Node::let_bind("suf_done", Expr::u32(0)));
                                        lit_nodes.push(Node::loop_for(
                                            "lit_suf",
                                            Expr::u32(0),
                                            Expr::u32(4),
                                            vec![Node::if_then(
                                                Expr::and(
                                                    Expr::eq(Expr::var("suf_done"), Expr::u32(0)),
                                                    Expr::lt(Expr::var("scan_pos"), Expr::var("tok_end")),
                                                ),
                                                vec![
                                                    Node::let_bind("sfb", safe_load_src(Expr::var("scan_pos"))),
                                                    Node::let_bind(
                                                        "sfb1",
                                                        safe_load_src(Expr::add(
                                                            Expr::var("scan_pos"),
                                                            Expr::u32(1),
                                                        )),
                                                    ),
                                                    Node::let_bind(
                                                        "is_single_suf",
                                                        Expr::select(
                                                            Expr::or(
                                                                Expr::or(
                                                                    Expr::eq(Expr::var("sfb"), Expr::u32(b'u' as u32)),
                                                                    Expr::eq(Expr::var("sfb"), Expr::u32(b'U' as u32)),
                                                                ),
                                                                Expr::or(
                                                                    Expr::eq(Expr::var("sfb"), Expr::u32(b'l' as u32)),
                                                                    Expr::eq(Expr::var("sfb"), Expr::u32(b'L' as u32)),
                                                                ),
                                                            ),
                                                            Expr::u32(1),
                                                            Expr::u32(0),
                                                        ),
                                                    ),
                                                    Node::let_bind(
                                                        "is_z_suf",
                                                        Expr::select(
                                                            Expr::or(
                                                                Expr::eq(Expr::var("sfb"), Expr::u32(b'z' as u32)),
                                                                Expr::eq(Expr::var("sfb"), Expr::u32(b'Z' as u32)),
                                                            ),
                                                            Expr::u32(1),
                                                            Expr::u32(0),
                                                        ),
                                                    ),
                                                    Node::let_bind(
                                                        "is_wb_suf",
                                                        Expr::select(
                                                            Expr::and(
                                                                Expr::or(
                                                                    Expr::eq(Expr::var("sfb"), Expr::u32(b'w' as u32)),
                                                                    Expr::eq(Expr::var("sfb"), Expr::u32(b'W' as u32)),
                                                                ),
                                                                Expr::or(
                                                                    Expr::eq(Expr::var("sfb1"), Expr::u32(b'b' as u32)),
                                                                    Expr::eq(Expr::var("sfb1"), Expr::u32(b'B' as u32)),
                                                                ),
                                                            ),
                                                            Expr::u32(1),
                                                            Expr::u32(0),
                                                        ),
                                                    ),
                                                    Node::if_then_else(
                                                        Expr::or(
                                                            Expr::or(
                                                                Expr::eq(Expr::var("is_single_suf"), Expr::u32(1)),
                                                                Expr::eq(Expr::var("is_z_suf"), Expr::u32(1)),
                                                            ),
                                                            Expr::eq(Expr::var("is_wb_suf"), Expr::u32(1)),
                                                        ),
                                                        vec![Node::assign(
                                                            "scan_pos",
                                                            Expr::add(
                                                                Expr::var("scan_pos"),
                                                                Expr::select(
                                                                    Expr::eq(Expr::var("is_wb_suf"), Expr::u32(1)),
                                                                    Expr::u32(2),
                                                                    Expr::u32(1),
                                                                ),
                                                            ),
                                                        )],
                                                        vec![Node::assign("suf_done", Expr::u32(1))],
                                                    ),
                                                ],
                                            )],
                                        ));
                                        lit_nodes.extend(push_stack("val_stack", "vsp", Expr::var("lit_value")));
                                        lit_nodes.push(Node::assign("last_was_value", Expr::u32(1)));
                                        lit_nodes
                                    },
                                ));

                                // ---- Identifier (defined / bare macro) ----
                                classify.push(Node::let_bind(
                                    "is_alpha_start",
                                    Expr::select(
                                        Expr::or(
                                            Expr::or(
                                                Expr::and(
                                                    Expr::ge(Expr::var("c"), Expr::u32(b'a' as u32)),
                                                    Expr::le(Expr::var("c"), Expr::u32(b'z' as u32)),
                                                ),
                                                Expr::and(
                                                    Expr::ge(Expr::var("c"), Expr::u32(b'A' as u32)),
                                                    Expr::le(Expr::var("c"), Expr::u32(b'Z' as u32)),
                                                ),
                                            ),
                                            Expr::eq(Expr::var("c"), Expr::u32(b'_' as u32)),
                                        ),
                                        Expr::u32(1),
                                        Expr::u32(0),
                                    ),
                                ));
                                classify.push(Node::if_then(
                                    Expr::and(
                                        Expr::eq(Expr::var("is_alpha_start"), Expr::u32(1)),
                                        Expr::eq(Expr::var("is_dec_digit"), Expr::u32(0)),
                                    ),
                                    {
                                        let mut id_nodes: Vec<Node> = Vec::new();
                                        id_nodes.push(Node::let_bind("ident_start", Expr::add(Expr::var("scan_pos"), Expr::u32(0))));
                                        id_nodes.push(Node::let_bind("ident_len", Expr::u32(0)));
                                        id_nodes.push(Node::loop_for(
                                            "id_read",
                                            Expr::u32(0),
                                            Expr::select(
                                                Expr::lt(Expr::var("ident_start"), Expr::var("tok_end")),
                                                Expr::sub(Expr::var("tok_end"), Expr::var("ident_start")),
                                                Expr::u32(0),
                                            ),
                                            vec![Node::if_then(
                                                Expr::eq(Expr::var("ident_len"), Expr::var("id_read")),
                                                vec![
                                                    Node::let_bind(
                                                        "id_pos",
                                                        Expr::add(Expr::var("ident_start"), Expr::var("id_read")),
                                                    ),
                                                    Node::if_then(
                                                        Expr::lt(Expr::var("id_pos"), Expr::var("tok_end")),
                                                        vec![
                                                            Node::let_bind("idb", safe_load_src(Expr::var("id_pos"))),
                                                            Node::let_bind(
                                                                "id_alpha",
                                                                Expr::select(
                                                                    Expr::or(
                                                                        Expr::and(
                                                                            Expr::ge(Expr::var("idb"), Expr::u32(b'a' as u32)),
                                                                            Expr::le(Expr::var("idb"), Expr::u32(b'z' as u32)),
                                                                        ),
                                                                        Expr::and(
                                                                            Expr::ge(Expr::var("idb"), Expr::u32(b'A' as u32)),
                                                                            Expr::le(Expr::var("idb"), Expr::u32(b'Z' as u32)),
                                                                        ),
                                                                    ),
                                                                    Expr::u32(1),
                                                                    Expr::u32(0),
                                                                ),
                                                            ),
                                                            Node::let_bind(
                                                                "id_digit",
                                                                Expr::select(
                                                                    Expr::and(
                                                                        Expr::ge(Expr::var("idb"), Expr::u32(b'0' as u32)),
                                                                        Expr::le(Expr::var("idb"), Expr::u32(b'9' as u32)),
                                                                    ),
                                                                    Expr::u32(1),
                                                                    Expr::u32(0),
                                                                ),
                                                            ),
                                                            Node::let_bind(
                                                                "id_under",
                                                                Expr::select(
                                                                    Expr::eq(Expr::var("idb"), Expr::u32(b'_' as u32)),
                                                                    Expr::u32(1),
                                                                    Expr::u32(0),
                                                                ),
                                                            ),
                                                            Node::let_bind(
                                                                "id_cont",
                                                                Expr::select(
                                                                    Expr::or(
                                                                        Expr::or(
                                                                            Expr::eq(Expr::var("id_alpha"), Expr::u32(1)),
                                                                            Expr::eq(Expr::var("id_digit"), Expr::u32(1)),
                                                                        ),
                                                                        Expr::eq(Expr::var("id_under"), Expr::u32(1)),
                                                                    ),
                                                                    Expr::u32(1),
                                                                    Expr::u32(0),
                                                                ),
                                                            ),
                                                            Node::if_then(
                                                                Expr::eq(Expr::var("id_cont"), Expr::u32(1)),
                                                                vec![Node::assign(
                                                                    "ident_len",
                                                                    Expr::add(Expr::var("ident_len"), Expr::u32(1)),
                                                                )],
                                                            ),
                                                        ],
                                                    ),
                                                ],
                                            )],
                                        ));
                                        id_nodes.push(Node::assign(
                                            "scan_pos",
                                            Expr::add(Expr::var("ident_start"), Expr::var("ident_len")),
                                        ));
                                        id_nodes.push(Node::let_bind("ident_hash", Expr::u32(0x811c_9dc5)));
                                        id_nodes.push(Node::loop_for(
                                            "ident_hash_bytes",
                                            Expr::u32(0),
                                            Expr::var("ident_len"),
                                            vec![
                                                Node::let_bind(
                                                    "idhb",
                                                    safe_load_src(Expr::add(
                                                        Expr::var("ident_start"),
                                                        Expr::var("ident_hash_bytes"),
                                                    )),
                                                ),
                                                Node::assign(
                                                    "ident_hash",
                                                    Expr::mul(
                                                        Expr::bitxor(Expr::var("ident_hash"), Expr::var("idhb")),
                                                        Expr::u32(0x0100_0193),
                                                    ),
                                                ),
                                            ],
                                        ));
                                        // Preprocessor operators that look like identifiers.
                                        id_nodes.push(Node::let_bind(
                                            "is_defined_kw",
                                            Expr::select(
                                                ident_hash_equals(b"defined"),
                                                Expr::u32(1),
                                                Expr::u32(0),
                                            ),
                                        ));
                                        id_nodes.push(Node::let_bind(
                                            "is_has_builtin_kw",
                                            Expr::select(
                                                ident_hash_equals(b"__has_builtin"),
                                                Expr::u32(1),
                                                Expr::u32(0),
                                            ),
                                        ));
                                        id_nodes.push(Node::let_bind(
                                            "is_has_constexpr_builtin_kw",
                                            Expr::select(
                                                ident_hash_equals(b"__has_constexpr_builtin"),
                                                Expr::u32(1),
                                                Expr::u32(0),
                                            ),
                                        ));
                                        id_nodes.push(Node::let_bind(
                                            "is_has_x_kw",
                                            Expr::select(
                                                Expr::or(
                                                    Expr::or(
                                                        ident_hash_equals(b"__has_include"),
                                                        ident_hash_equals(b"__has_include_next"),
                                                    ),
                                                    Expr::or(
                                                        Expr::or(
                                                            ident_hash_equals(b"__has_embed"),
                                                            ident_hash_equals(b"__has_attribute"),
                                                        ),
                                                        Expr::or(
                                                            Expr::or(
                                                                ident_hash_equals(b"__has_c_attribute"),
                                                                ident_hash_equals(b"__has_cpp_attribute"),
                                                            ),
                                                            Expr::or(
                                                                Expr::or(
                                                                    ident_hash_equals(b"__has_declspec_attribute"),
                                                                    ident_hash_equals(b"__has_feature"),
                                                                ),
                                                                ident_hash_equals(b"__has_extension"),
                                                            ),
                                                        ),
                                                    ),
                                                ),
                                                Expr::u32(1),
                                                Expr::u32(0),
                                            ),
                                        ));
                                        // For both "defined X" and "defined(X)" we need to
                                        // capture the inner identifier and look it up.
                                        id_nodes.push(Node::if_then_else(
                                            Expr::eq(Expr::var("is_defined_kw"), Expr::u32(1)),
                                            {
                                                let mut def_nodes: Vec<Node> = Vec::new();
                                                // Skip whitespace.
                                                def_nodes.push(Node::let_bind("def_ws_done", Expr::u32(0)));
                                                def_nodes.push(Node::loop_for(
                                                    "def_ws",
                                                    Expr::u32(0),
                                                    Expr::var("tok_len"),
                                                    vec![Node::if_then(
                                                        Expr::and(
                                                            Expr::eq(Expr::var("def_ws_done"), Expr::u32(0)),
                                                            Expr::lt(Expr::var("scan_pos"), Expr::var("tok_end")),
                                                        ),
                                                        vec![
                                                            Node::let_bind("dwsb", safe_load_src(Expr::var("scan_pos"))),
                                                            Node::let_bind(
                                                                "dws_is_ws",
                                                                Expr::select(
                                                                    Expr::or(
                                                                        Expr::or(
                                                                            Expr::eq(Expr::var("dwsb"), Expr::u32(b' ' as u32)),
                                                                            Expr::eq(Expr::var("dwsb"), Expr::u32(b'\t' as u32)),
                                                                        ),
                                                                        Expr::or(
                                                                            Expr::eq(Expr::var("dwsb"), Expr::u32(0x0B)),
                                                                            Expr::eq(Expr::var("dwsb"), Expr::u32(0x0C)),
                                                                        ),
                                                                    ),
                                                                    Expr::u32(1),
                                                                    Expr::u32(0),
                                                                ),
                                                            ),
                                                            Node::if_then_else(
                                                                Expr::eq(Expr::var("dws_is_ws"), Expr::u32(1)),
                                                                vec![Node::assign(
                                                                    "scan_pos",
                                                                    Expr::add(Expr::var("scan_pos"), Expr::u32(1)),
                                                                )],
                                                                vec![Node::assign("def_ws_done", Expr::u32(1))],
                                                            ),
                                                        ],
                                                    )],
                                                ));
                                                // Optional `(`.
                                                def_nodes.push(Node::let_bind("def_open", safe_load_src(Expr::var("scan_pos"))));
                                                def_nodes.push(Node::let_bind(
                                                    "had_paren",
                                                    Expr::select(
                                                        Expr::eq(Expr::var("def_open"), Expr::u32(b'(' as u32)),
                                                        Expr::u32(1),
                                                        Expr::u32(0),
                                                    ),
                                                ));
                                                def_nodes.push(Node::if_then(
                                                    Expr::eq(Expr::var("had_paren"), Expr::u32(1)),
                                                    vec![Node::assign(
                                                        "scan_pos",
                                                        Expr::add(Expr::var("scan_pos"), Expr::u32(1)),
                                                    )],
                                                ));
                                                // Skip ws after `(`.
                                                def_nodes.push(Node::let_bind("def_ws2_done", Expr::u32(0)));
                                                def_nodes.push(Node::loop_for(
                                                    "def_ws2",
                                                    Expr::u32(0),
                                                    Expr::var("tok_len"),
                                                    vec![Node::if_then(
                                                        Expr::and(
                                                            Expr::eq(Expr::var("def_ws2_done"), Expr::u32(0)),
                                                            Expr::lt(Expr::var("scan_pos"), Expr::var("tok_end")),
                                                        ),
                                                        vec![
                                                            Node::let_bind("dws2b", safe_load_src(Expr::var("scan_pos"))),
                                                            Node::let_bind(
                                                                "dws2_is_ws",
                                                                Expr::select(
                                                                    Expr::or(
                                                                        Expr::or(
                                                                            Expr::eq(Expr::var("dws2b"), Expr::u32(b' ' as u32)),
                                                                            Expr::eq(Expr::var("dws2b"), Expr::u32(b'\t' as u32)),
                                                                        ),
                                                                        Expr::or(
                                                                            Expr::eq(Expr::var("dws2b"), Expr::u32(0x0B)),
                                                                            Expr::eq(Expr::var("dws2b"), Expr::u32(0x0C)),
                                                                        ),
                                                                    ),
                                                                    Expr::u32(1),
                                                                    Expr::u32(0),
                                                                ),
                                                            ),
                                                            Node::if_then_else(
                                                                Expr::eq(Expr::var("dws2_is_ws"), Expr::u32(1)),
                                                                vec![Node::assign(
                                                                    "scan_pos",
                                                                    Expr::add(Expr::var("scan_pos"), Expr::u32(1)),
                                                                )],
                                                                vec![Node::assign("def_ws2_done", Expr::u32(1))],
                                                            ),
                                                        ],
                                                    )],
                                                ));
                                                // Capture inner ident.
                                                def_nodes.push(Node::let_bind("inner_start", Expr::var("scan_pos")));
                                                def_nodes.push(Node::let_bind("inner_len", Expr::u32(0)));
                                                def_nodes.push(Node::loop_for(
                                                    "inner_id",
                                                    Expr::u32(0),
                                                    Expr::select(
                                                        Expr::lt(Expr::var("inner_start"), Expr::var("tok_end")),
                                                        Expr::sub(Expr::var("tok_end"), Expr::var("inner_start")),
                                                        Expr::u32(0),
                                                    ),
                                                    vec![Node::if_then(
                                                        Expr::eq(Expr::var("inner_len"), Expr::var("inner_id")),
                                                        vec![
                                                            Node::let_bind(
                                                                "ip",
                                                                Expr::add(Expr::var("inner_start"), Expr::var("inner_id")),
                                                            ),
                                                            Node::if_then(
                                                                Expr::lt(Expr::var("ip"), Expr::var("tok_end")),
                                                                vec![
                                                                    Node::let_bind("ib", safe_load_src(Expr::var("ip"))),
                                                                    Node::let_bind(
                                                                        "ib_alpha",
                                                                        Expr::select(
                                                                            Expr::or(
                                                                                Expr::and(
                                                                                    Expr::ge(Expr::var("ib"), Expr::u32(b'a' as u32)),
                                                                                    Expr::le(Expr::var("ib"), Expr::u32(b'z' as u32)),
                                                                                ),
                                                                                Expr::and(
                                                                                    Expr::ge(Expr::var("ib"), Expr::u32(b'A' as u32)),
                                                                                    Expr::le(Expr::var("ib"), Expr::u32(b'Z' as u32)),
                                                                                ),
                                                                            ),
                                                                            Expr::u32(1),
                                                                            Expr::u32(0),
                                                                        ),
                                                                    ),
                                                                    Node::let_bind(
                                                                        "ib_digit",
                                                                        Expr::select(
                                                                            Expr::and(
                                                                                Expr::ge(Expr::var("ib"), Expr::u32(b'0' as u32)),
                                                                                Expr::le(Expr::var("ib"), Expr::u32(b'9' as u32)),
                                                                            ),
                                                                            Expr::u32(1),
                                                                            Expr::u32(0),
                                                                        ),
                                                                    ),
                                                                    Node::let_bind(
                                                                        "ib_under",
                                                                        Expr::select(
                                                                            Expr::eq(Expr::var("ib"), Expr::u32(b'_' as u32)),
                                                                            Expr::u32(1),
                                                                            Expr::u32(0),
                                                                        ),
                                                                    ),
                                                                    Node::let_bind(
                                                                        "ib_cont",
                                                                        Expr::select(
                                                                            Expr::or(
                                                                                Expr::or(
                                                                                    Expr::eq(Expr::var("ib_alpha"), Expr::u32(1)),
                                                                                    Expr::eq(Expr::var("ib_digit"), Expr::u32(1)),
                                                                                ),
                                                                                Expr::eq(Expr::var("ib_under"), Expr::u32(1)),
                                                                            ),
                                                                            Expr::u32(1),
                                                                            Expr::u32(0),
                                                                        ),
                                                                    ),
                                                                    Node::if_then(
                                                                        Expr::eq(Expr::var("ib_cont"), Expr::u32(1)),
                                                                        vec![Node::assign(
                                                                            "inner_len",
                                                                            Expr::add(Expr::var("inner_len"), Expr::u32(1)),
                                                                        )],
                                                                    ),
                                                                ],
                                                            ),
                                                        ],
                                                    )],
                                                ));
                                                def_nodes.push(Node::assign(
                                                    "scan_pos",
                                                    Expr::add(Expr::var("inner_start"), Expr::var("inner_len")),
                                                ));
                                                // Lookup against macro table.
                                                def_nodes.push(Node::let_bind("def_found", Expr::u32(0)));
                                                def_nodes.push(Node::loop_for(
                                                    "dm",
                                                    Expr::u32(0),
                                                    Expr::select(
                                                        Expr::gt(Expr::buf_len("macro_offsets"), Expr::u32(0)),
                                                        Expr::sub(Expr::buf_len("macro_offsets"), Expr::u32(1)),
                                                        Expr::u32(0),
                                                    ),
                                                    vec![Node::if_then(
                                                        Expr::eq(Expr::var("def_found"), Expr::u32(0)),
                                                        vec![
                                                            Node::let_bind(
                                                                "dm_s",
                                                                Expr::load("macro_offsets", Expr::var("dm")),
                                                            ),
                                                            Node::let_bind(
                                                                "dm_e",
                                                                Expr::load("macro_offsets", Expr::add(Expr::var("dm"), Expr::u32(1))),
                                                            ),
                                                            Node::let_bind(
                                                                "dm_l",
                                                                Expr::sub(Expr::var("dm_e"), Expr::var("dm_s")),
                                                            ),
                                                            Node::if_then(
                                                                Expr::eq(Expr::var("dm_l"), Expr::var("inner_len")),
                                                                vec![
                                                                    Node::let_bind("dm_match", Expr::u32(1)),
                                                                    Node::loop_for(
                                                                        "dmk",
                                                                        Expr::u32(0),
                                                                        Expr::var("inner_len"),
                                                                        vec![
                                                                            Node::let_bind(
                                                                                "dms_b",
                                                                                safe_load_src(Expr::add(Expr::var("inner_start"), Expr::var("dmk"))),
                                                                            ),
                                                                            Node::let_bind(
                                                                                "dmm_b",
                                                                                Expr::select(
                                                                                    Expr::lt(
                                                                                        Expr::add(Expr::var("dm_s"), Expr::var("dmk")),
                                                                                        Expr::mul(Expr::buf_len("macro_names_packed"), Expr::u32(4)),
                                                                                    ),
                                                                                    load_packed_byte_u32("macro_names_packed", Expr::add(Expr::var("dm_s"), Expr::var("dmk"))),
                                                                                    Expr::u32(0),
                                                                                ),
                                                                            ),
                                                                            Node::if_then(
                                                                                Expr::ne(Expr::var("dms_b"), Expr::var("dmm_b")),
                                                                                vec![Node::assign("dm_match", Expr::u32(0))],
                                                                            ),
                                                                        ],
                                                                    ),
                                                                    Node::if_then(
                                                                        Expr::eq(Expr::var("dm_match"), Expr::u32(1)),
                                                                        vec![Node::assign("def_found", Expr::u32(1))],
                                                                    ),
                                                                ],
                                                            ),
                                                        ],
                                                    )],
                                                ));
                                                // Skip closing `)` if there was an opener.
                                                def_nodes.push(Node::if_then(
                                                    Expr::eq(Expr::var("had_paren"), Expr::u32(1)),
                                                    vec![
                                                        // Skip ws.
                                                        Node::let_bind("def_ws3_done", Expr::u32(0)),
                                                        Node::loop_for(
                                                            "def_ws3",
                                                            Expr::u32(0),
                                                            Expr::var("tok_len"),
                                                            vec![Node::if_then(
                                                                Expr::and(
                                                                    Expr::eq(Expr::var("def_ws3_done"), Expr::u32(0)),
                                                                    Expr::lt(Expr::var("scan_pos"), Expr::var("tok_end")),
                                                                ),
                                                                vec![
                                                                    Node::let_bind("dws3b", safe_load_src(Expr::var("scan_pos"))),
                                                                    Node::let_bind(
                                                                        "dws3_is_ws",
                                                                        Expr::select(
                                                                            Expr::or(
                                                                                Expr::or(
                                                                                    Expr::eq(Expr::var("dws3b"), Expr::u32(b' ' as u32)),
                                                                                    Expr::eq(Expr::var("dws3b"), Expr::u32(b'\t' as u32)),
                                                                                ),
                                                                                Expr::or(
                                                                                    Expr::eq(Expr::var("dws3b"), Expr::u32(0x0B)),
                                                                                    Expr::eq(Expr::var("dws3b"), Expr::u32(0x0C)),
                                                                                ),
                                                                            ),
                                                                            Expr::u32(1),
                                                                            Expr::u32(0),
                                                                        ),
                                                                    ),
                                                                    Node::if_then_else(
                                                                        Expr::eq(Expr::var("dws3_is_ws"), Expr::u32(1)),
                                                                        vec![Node::assign(
                                                                            "scan_pos",
                                                                            Expr::add(Expr::var("scan_pos"), Expr::u32(1)),
                                                                        )],
                                                                        vec![Node::assign("def_ws3_done", Expr::u32(1))],
                                                                    ),
                                                                ],
                                                            )],
                                                        ),
                                                        // Consume `)` if present.
                                                        Node::if_then(
                                                            Expr::eq(safe_load_src(Expr::var("scan_pos")), Expr::u32(b')' as u32)),
                                                            vec![Node::assign(
                                                                "scan_pos",
                                                                Expr::add(Expr::var("scan_pos"), Expr::u32(1)),
                                                            )],
                                                        ),
                                                    ],
                                                ));
                                                def_nodes.extend(push_stack("val_stack", "vsp", Expr::var("def_found")));
                                                def_nodes.push(Node::assign("last_was_value", Expr::u32(1)));
                                                def_nodes
                                            },
                                            {
                                                // Bare ident: treat as an object-like integer macro reference.
                                                // Push the packed macro value when defined, otherwise 0.
                                                let mut bare_nodes: Vec<Node> = Vec::new();
                                                bare_nodes.push(Node::let_bind("bare_found", Expr::u32(0)));
                                                bare_nodes.push(Node::let_bind("bare_value", Expr::u32(0)));
                                                bare_nodes.push(Node::let_bind(
                                                    "bare_ident_base",
                                                    Expr::sub(Expr::var("scan_pos"), Expr::var("ident_len")),
                                                ));
                                                push_has_builtin_call_parser(
                                                    &mut bare_nodes,
                                                    "ehb",
                                                    "bare_ident_base",
                                                    "tok_end",
                                                    "tok_len",
                                                    source_byte_len.clone(),
                                                    "scan_pos",
                                                    "bare_found",
                                                    "bare_value",
                                                );
                                                bare_nodes.push(Node::if_then(
                                                    Expr::and(
                                                        Expr::eq(Expr::var("bare_found"), Expr::u32(0)),
                                                        Expr::eq(Expr::var("is_has_x_kw"), Expr::u32(1)),
                                                    ),
                                                    {
                                                        let mut hx_nodes: Vec<Node> = Vec::new();
                                                        hx_nodes.push(Node::let_bind("hx_ws_done", Expr::u32(0)));
                                                        hx_nodes.push(Node::loop_for(
                                                            "hx_ws",
                                                            Expr::u32(0),
                                                            Expr::var("tok_len"),
                                                            vec![Node::if_then(
                                                                Expr::and(
                                                                    Expr::eq(Expr::var("hx_ws_done"), Expr::u32(0)),
                                                                    Expr::lt(Expr::var("scan_pos"), Expr::var("tok_end")),
                                                                ),
                                                                vec![
                                                                    Node::let_bind("hxwsb", safe_load_src(Expr::var("scan_pos"))),
                                                                    Node::let_bind(
                                                                        "hxws_is_ws",
                                                                        Expr::select(
                                                                            Expr::or(
                                                                                Expr::or(
                                                                                    Expr::eq(Expr::var("hxwsb"), Expr::u32(b' ' as u32)),
                                                                                    Expr::eq(Expr::var("hxwsb"), Expr::u32(b'\t' as u32)),
                                                                                ),
                                                                                Expr::or(
                                                                                    Expr::eq(Expr::var("hxwsb"), Expr::u32(0x0B)),
                                                                                    Expr::eq(Expr::var("hxwsb"), Expr::u32(0x0C)),
                                                                                ),
                                                                            ),
                                                                            Expr::u32(1),
                                                                            Expr::u32(0),
                                                                        ),
                                                                    ),
                                                                    Node::if_then_else(
                                                                        Expr::eq(Expr::var("hxws_is_ws"), Expr::u32(1)),
                                                                        vec![Node::assign(
                                                                            "scan_pos",
                                                                            Expr::add(Expr::var("scan_pos"), Expr::u32(1)),
                                                                        )],
                                                                        vec![Node::assign("hx_ws_done", Expr::u32(1))],
                                                                    ),
                                                                ],
                                                            )],
                                                        ));
                                                        hx_nodes.push(Node::let_bind("hx_open", safe_load_src(Expr::var("scan_pos"))));
                                                        hx_nodes.push(Node::if_then(
                                                            Expr::eq(Expr::var("hx_open"), Expr::u32(b'(' as u32)),
                                                            {
                                                                let mut paren_nodes: Vec<Node> = Vec::new();
                                                                paren_nodes.push(Node::assign(
                                                                    "scan_pos",
                                                                    Expr::add(Expr::var("scan_pos"), Expr::u32(1)),
                                                                ));
                                                                paren_nodes.push(Node::let_bind("hx_depth", Expr::u32(1)));
                                                                paren_nodes.push(Node::loop_for(
                                                                    "hx_arg_scan",
                                                                    Expr::u32(0),
                                                                    Expr::var("tok_len"),
                                                                    vec![Node::if_then(
                                                                        Expr::and(
                                                                            Expr::gt(Expr::var("hx_depth"), Expr::u32(0)),
                                                                            Expr::lt(Expr::var("scan_pos"), Expr::var("tok_end")),
                                                                        ),
                                                                        vec![
                                                                            Node::let_bind("hxab", safe_load_src(Expr::var("scan_pos"))),
                                                                            Node::if_then(
                                                                                Expr::eq(Expr::var("hxab"), Expr::u32(b'(' as u32)),
                                                                                vec![Node::assign(
                                                                                    "hx_depth",
                                                                                    Expr::add(Expr::var("hx_depth"), Expr::u32(1)),
                                                                                )],
                                                                            ),
                                                                            Node::if_then(
                                                                                Expr::eq(Expr::var("hxab"), Expr::u32(b')' as u32)),
                                                                                vec![Node::assign(
                                                                                    "hx_depth",
                                                                                    Expr::sub(Expr::var("hx_depth"), Expr::u32(1)),
                                                                                )],
                                                                            ),
                                                                            Node::assign(
                                                                                "scan_pos",
                                                                                Expr::add(Expr::var("scan_pos"), Expr::u32(1)),
                                                                            ),
                                                                        ],
                                                                    )],
                                                                ));
                                                                paren_nodes
                                                            },
                                                        ));
                                                        hx_nodes.push(Node::assign("bare_found", Expr::u32(1)));
                                                        hx_nodes.push(Node::assign("bare_value", Expr::u32(0)));
                                                        hx_nodes
                                                    },
                                                ));
                                                bare_nodes.push(Node::loop_for(
                                                    "bm",
                                                    Expr::u32(0),
                                                    Expr::select(
                                                        Expr::gt(Expr::buf_len("macro_offsets"), Expr::u32(0)),
                                                        Expr::sub(Expr::buf_len("macro_offsets"), Expr::u32(1)),
                                                        Expr::u32(0),
                                                    ),
                                                    vec![Node::if_then(
                                                        Expr::eq(Expr::var("bare_found"), Expr::u32(0)),
                                                        vec![
                                                            Node::let_bind(
                                                                "bm_s",
                                                                Expr::load("macro_offsets", Expr::var("bm")),
                                                            ),
                                                            Node::let_bind(
                                                                "bm_e",
                                                                Expr::load("macro_offsets", Expr::add(Expr::var("bm"), Expr::u32(1))),
                                                            ),
                                                            Node::let_bind(
                                                                "bm_l",
                                                                Expr::sub(Expr::var("bm_e"), Expr::var("bm_s")),
                                                            ),
                                                            Node::let_bind("bm_match", Expr::u32(0)),
                                                            Node::if_then(
                                                                Expr::eq(Expr::var("bm_l"), Expr::var("ident_len")),
                                                                vec![
                                                                    Node::assign("bm_match", Expr::u32(1)),
                                                                    Node::loop_for(
                                                                        "bmk",
                                                                        Expr::u32(0),
                                                                        Expr::var("ident_len"),
                                                                        vec![
                                                                            Node::let_bind(
                                                                                "bms_b",
                                                                                safe_load_src(Expr::add(Expr::var("bare_ident_base"), Expr::var("bmk"))),
                                                                            ),
                                                                            Node::let_bind(
                                                                                "bmm_b",
                                                                                Expr::select(
                                                                                    Expr::lt(
                                                                                        Expr::add(Expr::var("bm_s"), Expr::var("bmk")),
                                                                                        Expr::mul(Expr::buf_len("macro_names_packed"), Expr::u32(4)),
                                                                                    ),
                                                                                    load_packed_byte_u32("macro_names_packed", Expr::add(Expr::var("bm_s"), Expr::var("bmk"))),
                                                                                    Expr::u32(0),
                                                                                ),
                                                                            ),
                                                                            Node::if_then(
                                                                                Expr::ne(Expr::var("bms_b"), Expr::var("bmm_b")),
                                                                                vec![Node::assign("bm_match", Expr::u32(0))],
                                                                            ),
                                                                        ],
                                                                    ),
                                                                    Node::if_then(
                                                                        Expr::eq(Expr::var("bm_match"), Expr::u32(1)),
                                                                        vec![
                                                                            Node::assign("bare_found", Expr::u32(1)),
                                                                            Node::assign(
                                                                                "bare_value",
                                                                                Expr::load(
                                                                                    "macro_values",
                                                                                    Expr::add(
                                                                                        Expr::u32(
                                                                                            crate::parsing::c::parse::gnu_builtins::GPU_BUILTIN_HASH_TABLE_SIZE as u32,
                                                                                        ),
                                                                                        Expr::var("bm"),
                                                                                    ),
                                                                                ),
                                                                            ),
                                                                        ],
                                                                    ),
                                                                ],
                                                            ),
                                                        ],
                                                    )],
                                                ));
                                                bare_nodes.extend(push_stack("val_stack", "vsp", Expr::var("bare_value")));
                                                bare_nodes.push(Node::assign("last_was_value", Expr::u32(1)));
                                                bare_nodes
                                            },
                                        ));
                                        id_nodes
                                    },
                                ));

                                // ---- Operators / parens ----
                                classify.push(Node::if_then(
                                    Expr::and(
                                        Expr::eq(Expr::var("is_dec_digit"), Expr::u32(0)),
                                        Expr::eq(Expr::var("is_alpha_start"), Expr::u32(0)),
                                    ),
                                    {
                                        let mut op_nodes: Vec<Node> = Vec::new();
                                        // Detect each operator. We always
                                        // start by classifying as one of:
                                        // (, ), 2-char op, 1-char op, or
                                        // unknown (terminate).
                                        op_nodes.push(Node::let_bind("op_picked", Expr::u32(0)));
                                        op_nodes.push(Node::let_bind("op_skip", Expr::u32(1)));
                                        // Open paren.
                                        op_nodes.push(Node::if_then(
                                            Expr::eq(Expr::var("c"), Expr::u32(b'(' as u32)),
                                            vec![
                                                Node::assign("op_picked", Expr::u32(OP_LPAREN)),
                                            ],
                                        ));
                                        // Close paren — pop until LPAREN.
                                        op_nodes.push(Node::if_then(
                                            Expr::eq(Expr::var("c"), Expr::u32(b')' as u32)),
                                            {
                                                let mut close: Vec<Node> = Vec::new();
                                                close.push(Node::let_bind("close_done", Expr::u32(0)));
                                                close.push(Node::loop_for(
                                                    "close_pop",
                                                    Expr::u32(0),
                                                    Expr::u32(STACK_DEPTH),
                                                    vec![Node::if_then(
                                                        Expr::and(
                                                            Expr::eq(Expr::var("close_done"), Expr::u32(0)),
                                                            Expr::gt(Expr::var("osp"), Expr::u32(0)),
                                                        ),
                                                        {
                                                            let mut iter: Vec<Node> = Vec::new();
                                                            iter.push(Node::let_bind("top_op_close", Expr::u32(0)));
                                                            iter.extend(peek_stack("op_stack", "osp", "top_op_close"));
                                                            iter.push(Node::if_then_else(
                                                                Expr::eq(Expr::var("top_op_close"), Expr::u32(OP_LPAREN)),
                                                                vec![
                                                                    Node::assign("osp", Expr::sub(Expr::var("osp"), Expr::u32(1))),
                                                                    Node::assign("close_done", Expr::u32(1)),
                                                                ],
                                                                apply_top_op(),
                                                            ));
                                                            iter
                                                        },
                                                    )],
                                                ));
                                                close.push(Node::assign("op_picked", Expr::u32(OP_LPAREN))); // marker so we don't re-push
                                                close.push(Node::assign("op_skip", Expr::u32(1)));
                                                close.push(Node::assign("last_was_value", Expr::u32(1)));
                                                close
                                            },
                                        ));
                                        // Unary !/~/+/- (when last token wasn't a value).
                                        // Push as deferred opcode onto op_stack so it
                                        // applies AFTER its operand has been pushed.
                                        op_nodes.push(Node::if_then(
                                            Expr::and(
                                                Expr::eq(Expr::var("last_was_value"), Expr::u32(0)),
                                                Expr::or(
                                                    Expr::eq(Expr::var("c"), Expr::u32(b'+' as u32)),
                                                    Expr::or(
                                                        Expr::eq(Expr::var("c"), Expr::u32(b'-' as u32)),
                                                        Expr::or(
                                                            Expr::eq(Expr::var("c"), Expr::u32(b'!' as u32)),
                                                            Expr::eq(Expr::var("c"), Expr::u32(b'~' as u32)),
                                                        ),
                                                    ),
                                                ),
                                            ),
                                            {
                                                let mut un: Vec<Node> = Vec::new();
                                                un.push(Node::let_bind(
                                                    "un_op",
                                                    Expr::select(
                                                        Expr::eq(Expr::var("c"), Expr::u32(b'!' as u32)),
                                                        Expr::u32(OP_UN_NOT),
                                                        Expr::select(
                                                            Expr::eq(Expr::var("c"), Expr::u32(b'~' as u32)),
                                                            Expr::u32(OP_UN_BNOT),
                                                            Expr::select(
                                                                Expr::eq(Expr::var("c"), Expr::u32(b'-' as u32)),
                                                                Expr::u32(OP_UN_NEG),
                                                                Expr::u32(OP_UN_PLUS),
                                                            ),
                                                        ),
                                                    ),
                                                ));
                                                un.extend(push_stack("op_stack", "osp", Expr::var("un_op")));
                                                // Mark as handled so the binary classifier
                                                // doesn't try to interpret the same byte.
                                                un.push(Node::assign("op_picked", Expr::u32(OP_LPAREN)));
                                                // last_was_value stays 0 so the operand
                                                // following the unary still parses as a
                                                // value (not as an unconditional binary).
                                                un
                                            },
                                        ));
                                        // Two-char binary ops. Map ('=', '=') etc.
                                        let pairs: &[(u8, u8, u32)] = &[
                                            (b'|', b'|', OP_LOR),
                                            (b'&', b'&', OP_LAND),
                                            (b'=', b'=', OP_EQ),
                                            (b'!', b'=', OP_NE),
                                            (b'<', b'=', OP_LE),
                                            (b'>', b'=', OP_GE),
                                            (b'<', b'<', OP_SHL),
                                            (b'>', b'>', OP_SHR),
                                        ];
                                        for &(a, b, op) in pairs {
                                            op_nodes.push(Node::if_then(
                                                Expr::and(
                                                    Expr::eq(Expr::var("op_picked"), Expr::u32(0)),
                                                    Expr::and(
                                                        Expr::eq(Expr::var("c"), Expr::u32(a as u32)),
                                                        Expr::eq(Expr::var("c1"), Expr::u32(b as u32)),
                                                    ),
                                                ),
                                                vec![
                                                    Node::assign("op_picked", Expr::u32(op)),
                                                    Node::assign("op_skip", Expr::u32(2)),
                                                ],
                                            ));
                                        }
                                        // One-char binary ops (skip if op_picked already set above).
                                        let singles: &[(u8, u32)] = &[
                                            (b'|', OP_BOR),
                                            (b'&', OP_BAND),
                                            (b'^', OP_BXOR),
                                            (b'<', OP_LT),
                                            (b'>', OP_GT),
                                            (b'+', OP_ADD),
                                            (b'-', OP_SUB),
                                            (b'*', OP_MUL),
                                            (b'/', OP_DIV),
                                            (b'%', OP_MOD),
                                        ];
                                        for &(b, op) in singles {
                                            op_nodes.push(Node::if_then(
                                                Expr::and(
                                                    Expr::eq(Expr::var("op_picked"), Expr::u32(0)),
                                                    Expr::eq(Expr::var("c"), Expr::u32(b as u32)),
                                                ),
                                                vec![Node::assign("op_picked", Expr::u32(op))],
                                            ));
                                        }
                                        // Push binary op (everything except LPAREN and the close-paren marker).
                                        op_nodes.push(Node::if_then(
                                            Expr::and(
                                                Expr::ne(Expr::var("op_picked"), Expr::u32(0)),
                                                Expr::ne(Expr::var("op_picked"), Expr::u32(OP_LPAREN)),
                                            ),
                                            {
                                                let mut push_bin: Vec<Node> = Vec::new();
                                                // Pop while stack top has >= precedence.
                                                push_bin.push(Node::let_bind("pop_done", Expr::u32(0)));
                                                push_bin.push(Node::let_bind("new_prec", precedence_of(Expr::var("op_picked"))));
                                                push_bin.push(Node::loop_for(
                                                    "pop_while",
                                                    Expr::u32(0),
                                                    Expr::u32(STACK_DEPTH),
                                                    vec![Node::if_then(
                                                        Expr::and(
                                                            Expr::eq(Expr::var("pop_done"), Expr::u32(0)),
                                                            Expr::gt(Expr::var("osp"), Expr::u32(0)),
                                                        ),
                                                        {
                                                            let mut iter: Vec<Node> = Vec::new();
                                                            iter.push(Node::let_bind("top_op_apply", Expr::u32(0)));
                                                            iter.extend(peek_stack("op_stack", "osp", "top_op_apply"));
                                                            iter.push(Node::let_bind("top_prec", precedence_of(Expr::var("top_op_apply"))));
                                                            iter.push(Node::if_then_else(
                                                                Expr::ge(Expr::var("top_prec"), Expr::var("new_prec")),
                                                                apply_top_op(),
                                                                vec![Node::assign("pop_done", Expr::u32(1))],
                                                            ));
                                                            iter
                                                        },
                                                    )],
                                                ));
                                                push_bin.extend(push_stack("op_stack", "osp", Expr::var("op_picked")));
                                                push_bin.push(Node::assign("last_was_value", Expr::u32(0)));
                                                push_bin
                                            },
                                        ));
                                        // Pure LPAREN push.
                                        op_nodes.push(Node::if_then(
                                            Expr::eq(Expr::var("c"), Expr::u32(b'(' as u32)),
                                            {
                                                let mut nodes: Vec<Node> = Vec::new();
                                                nodes.extend(push_stack("op_stack", "osp", Expr::u32(OP_LPAREN)));
                                                nodes.push(Node::assign("last_was_value", Expr::u32(0)));
                                                nodes
                                            },
                                        ));
                                        // Unknown character: terminate scan to avoid infinite loop.
                                        op_nodes.push(Node::if_then(
                                            Expr::eq(Expr::var("op_picked"), Expr::u32(0)),
                                            vec![Node::assign("scan_done", Expr::u32(1))],
                                        ));
                                        op_nodes.push(Node::assign(
                                            "scan_pos",
                                            Expr::add(Expr::var("scan_pos"), Expr::var("op_skip")),
                                        ));
                                        op_nodes
                                    },
                                ));
                                classify
                            },
                        ));
                        iter_body
                    },
                )],
            ));

            // ---------- Drain remaining operators ----------
            evaluate.push(Node::let_bind("drain_done", Expr::u32(0)));
            evaluate.push(Node::loop_for(
                "drain",
                Expr::u32(0),
                Expr::u32(STACK_DEPTH),
                vec![Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("drain_done"), Expr::u32(0)),
                        Expr::gt(Expr::var("osp"), Expr::u32(0)),
                    ),
                    {
                        let mut iter: Vec<Node> = Vec::new();
                        iter.push(Node::let_bind("top_op_drain", Expr::u32(0)));
                        iter.extend(peek_stack("op_stack", "osp", "top_op_drain"));
                        iter.push(Node::if_then_else(
                            Expr::or(
                                Expr::eq(Expr::var("top_op_drain"), Expr::u32(OP_LPAREN)),
                                Expr::eq(Expr::var("top_op_drain"), Expr::u32(OP_TERNARY_Q)),
                            ),
                            vec![
                                Node::assign("osp", Expr::sub(Expr::var("osp"), Expr::u32(1))),
                            ],
                            apply_top_op(),
                        ));
                        iter
                    },
                )],
            ));

            // ---------- Final value: top of val_stack, mapped to bool ----------
            evaluate.push(Node::let_bind("final_val", Expr::u32(0)));
            evaluate.extend(peek_stack("val_stack", "vsp", "final_val"));
            evaluate.push(Node::assign(
                "expr_value_out",
                Expr::select(
                    Expr::ne(Expr::var("expr_invalid"), Expr::u32(0)),
                    Expr::u32(INVALID_EXPR_VALUE),
                    Expr::select(
                        Expr::ne(Expr::var("final_val"), Expr::u32(0)),
                        Expr::u32(1),
                        Expr::u32(0),
                    ),
                ),
            ));

            // Gate the directive_values store on directive_kind so
            // this kernel only writes to if/elif rows. This makes
            // it safe to fuse with `gpu_ifdef_value` (which writes
            // ifdef/ifndef rows) — disjoint cells, no clobbering
            // even with a barrier between fused arms.
            inner.push(Node::if_then(
                Expr::or(
                    Expr::eq(Expr::var("kind"), Expr::u32(TOK_PP_IF)),
                    Expr::eq(Expr::var("kind"), Expr::u32(TOK_PP_ELIF)),
                ),
                {
                    let mut gated = evaluate;
                    gated.push(Node::store(
                        "directive_values",
                        t.clone(),
                        Expr::var("expr_value_out"),
                    ));
                    gated
                },
            ));
            inner
        },
    ));

    Program::wrapped(
        vec![
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
            .with_count(0),
            // Runtime-sized: count=0 marks the buffer as runtime-bound,
            // so the program structure stays independent of the host's
            // macro-table size.
            BufferDecl::storage(
                "macro_names_packed",
                BINDING_MACRO_NAMES_PACKED,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(0),
            BufferDecl::storage(
                "macro_offsets",
                BINDING_MACRO_OFFSETS,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(0),
            BufferDecl::storage(
                "macro_values",
                BINDING_MACRO_VALUES,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(0),
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
