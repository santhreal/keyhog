//! GPU comment-strip mask for C source.
//!
//! Phase 17b.5: per-byte mask `1 = inside comment, 0 = code`. Composes
//! with `gpu_line_splice_classify` (multiply masks element-wise) and
//! `stream_compact` to produce a comment-and-splice-free byte stream
//! before lexing.
//!
//! ## GPU formulation
//!
//! Comment state is sequential by nature: a `/*` opens until the next
//! `*/`; a `//` opens until the next `\n`. Pure parallel formulations
//! exist (segmented scans, balanced-paren style) but each adds enough
//! complexity that v0.4 ships a single-thread state-machine running on
//! GPU. One thread per dispatch, byte-at-a-time. This is "on GPU"
//! (satisfies the rule that production code must not run on CPU) but
//! intentionally trades parallelism for clarity. A future rewrite can
//! parallelize via `multi_block_prefix_scan` with a custom monoid.
//!
//! ## Wire layout
//!
//! Inputs:
//!   - `bytes_in` (U8) — raw source bytes.
//!
//! Outputs:
//!   - `comment_mask_out` (U32) — one entry per byte. `1` if the byte
//!     is part of a comment (including the `/`, `*`, etc. that bound
//!     the comment); `0` otherwise.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-libs::parsing::c::preprocess::gpu_comment_strip_mask";

/// Canonical binding for the input source bytes.
pub const BINDING_BYTES_IN: u32 = 0;
/// Canonical binding for the output comment mask.
pub const BINDING_COMMENT_MASK_OUT: u32 = 1;

/// Build the 17b.5 comment-strip-mask `Program`.
#[must_use]
pub fn gpu_comment_strip_mask(byte_count: u32) -> Program {
    // Real-GPU note: U8 storage buffers emit as `array<u32>`; load
    // returns the u32 word at index `addr`. Reference-eval is byte-
    // addressed. Declaring `bytes_in` as packed U32 below makes both
    // backends agree; this helper extracts the byte explicitly.
    let load_byte_u32 = |addr: Expr| -> Expr {
        let word_idx = Expr::div(addr.clone(), Expr::u32(4));
        let byte_in_word = Expr::rem(addr, Expr::u32(4));
        let word = Expr::cast(DataType::U32, Expr::load("bytes_in", word_idx));
        let shift = Expr::mul(byte_in_word, Expr::u32(8));
        Expr::bitand(Expr::shr(word, shift), Expr::u32(0xFF))
    };
    let safe_load = |addr: Expr| -> Expr {
        Expr::select(
            Expr::lt(addr.clone(), Expr::u32(byte_count)),
            load_byte_u32(addr),
            Expr::u32(0),
        )
    };

    // Single thread (lane 0 of workgroup 0) walks the byte stream
    // sequentially, maintaining (in_line, in_block) state. Every byte
    // either gets `0` (code) or `1` (comment) written to
    // `comment_mask_out`.
    let body: Vec<Node> = vec![Node::if_then(
        Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
        vec![
            Node::let_bind("in_line", Expr::u32(0)),
            Node::let_bind("in_block", Expr::u32(0)),
            Node::let_bind("i", Expr::u32(0)),
            Node::loop_for(
                "step",
                Expr::u32(0),
                Expr::u32(byte_count),
                vec![
                    Node::let_bind("b", safe_load(Expr::var("i"))),
                    Node::let_bind("b1", safe_load(Expr::add(Expr::var("i"), Expr::u32(1)))),

                    // Default mask value for this byte = currently in
                    // any comment.
                    Node::let_bind(
                        "mask",
                        Expr::select(
                            Expr::or(
                                Expr::eq(Expr::var("in_line"), Expr::u32(1)),
                                Expr::eq(Expr::var("in_block"), Expr::u32(1)),
                            ),
                            Expr::u32(1),
                            Expr::u32(0),
                        ),
                    ),

                    // Detect comment open when not inside any.
                    Node::if_then(
                        Expr::and(
                            Expr::eq(Expr::var("in_line"), Expr::u32(0)),
                            Expr::eq(Expr::var("in_block"), Expr::u32(0)),
                        ),
                        vec![
                            // `//` opens a line comment.
                            Node::if_then(
                                Expr::and(
                                    Expr::eq(Expr::var("b"), Expr::u32(b'/' as u32)),
                                    Expr::eq(Expr::var("b1"), Expr::u32(b'/' as u32)),
                                ),
                                vec![
                                    Node::assign("in_line", Expr::u32(1)),
                                    // The current `/` byte is part of the comment.
                                    Node::assign("mask", Expr::u32(1)),
                                ],
                            ),
                            // `/*` opens a block comment.
                            Node::if_then(
                                Expr::and(
                                    Expr::eq(Expr::var("b"), Expr::u32(b'/' as u32)),
                                    Expr::eq(Expr::var("b1"), Expr::u32(b'*' as u32)),
                                ),
                                vec![
                                    Node::assign("in_block", Expr::u32(1)),
                                    Node::assign("mask", Expr::u32(1)),
                                ],
                            ),
                        ],
                    ),

                    // Write the mask before processing closes — this
                    // ensures the closing `*/` bytes are themselves
                    // marked as comment.
                    Node::store("comment_mask_out", Expr::var("i"), Expr::var("mask")),

                    // Detect comment closes AFTER writing the mask.
                    // - Line comment closes at `\n` (the newline itself
                    //   is OUTSIDE the comment per typical C semantics;
                    //   tools that mask comments usually keep newlines
                    //   so line counts stay correct, but we already
                    //   wrote 1 before checking — fix that next).
                    Node::if_then(
                        Expr::and(
                            Expr::eq(Expr::var("in_line"), Expr::u32(1)),
                            Expr::eq(Expr::var("b"), Expr::u32(b'\n' as u32)),
                        ),
                        vec![
                            // Newline is NOT part of the comment — overwrite.
                            Node::store("comment_mask_out", Expr::var("i"), Expr::u32(0)),
                            Node::assign("in_line", Expr::u32(0)),
                        ],
                    ),
                    // Block comment closes when current byte is `*`
                    // and next byte is `/`. The closing `/` (i+1) is
                    // also part of the comment, so we set in_block=0
                    // only after the `/` byte itself is processed.
                    // We do this by detecting (b == '*' && b1 == '/')
                    // and writing the mask for byte i+1 in the next
                    // iteration normally; here we just transition out
                    // AFTER advancing past the `/`. Simplest: set
                    // in_block=0 next iteration when (prev was `*` and
                    // current is `/`). Track via `prev_star` flag.
                    // Implemented below via two-step trailing close.
                    Node::if_then(
                        Expr::and(
                            Expr::eq(Expr::var("in_block"), Expr::u32(1)),
                            Expr::and(
                                Expr::eq(Expr::var("b"), Expr::u32(b'*' as u32)),
                                Expr::eq(Expr::var("b1"), Expr::u32(b'/' as u32)),
                            ),
                        ),
                        vec![
                            // Mark the trailing '/' (i+1) as comment now,
                            // and exit the block AFTER it. We do this by
                            // pre-storing into i+1 here, then on the next
                            // iteration the loop body will run with
                            // in_block=0 but the mask we already stored
                            // wins because we won't re-store unless we
                            // write the same slot.
                            Node::if_then(
                                Expr::lt(
                                    Expr::add(Expr::var("i"), Expr::u32(1)),
                                    Expr::u32(byte_count),
                                ),
                                vec![Node::store(
                                    "comment_mask_out",
                                    Expr::add(Expr::var("i"), Expr::u32(1)),
                                    Expr::u32(1),
                                )],
                            ),
                            // Skip the next byte by bumping i, then
                            // exit the comment.
                            Node::assign("i", Expr::add(Expr::var("i"), Expr::u32(1))),
                            Node::assign("in_block", Expr::u32(0)),
                        ],
                    ),
                    Node::assign("i", Expr::add(Expr::var("i"), Expr::u32(1))),
                ],
            ),
        ],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(
                "bytes_in",
                BINDING_BYTES_IN,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(byte_count.div_ceil(4).max(1)),
            BufferDecl::storage(
                "comment_mask_out",
                BINDING_COMMENT_MASK_OUT,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(byte_count.max(1)),
        ],
        [256, 1, 1],
        body,
    )
    .with_entry_op_id(OP_ID)
}

// ---- CPU reference contract ----

/// CPU reference: returns the same per-byte mask the GPU kernel emits.
#[must_use]
pub fn gpu_comment_strip_mask_cpu(source: &[u8]) -> Vec<u32> {
    let mut out = vec![0u32; source.len()];
    let mut in_line = false;
    let mut in_block = false;
    let mut i = 0usize;
    while i < source.len() {
        let b = source[i];
        let b1 = source.get(i + 1).copied().unwrap_or(0);
        if !in_line && !in_block {
            if b == b'/' && b1 == b'/' {
                in_line = true;
                out[i] = 1;
                i += 1;
                continue;
            }
            if b == b'/' && b1 == b'*' {
                in_block = true;
                out[i] = 1;
                i += 1;
                continue;
            }
            out[i] = 0;
            i += 1;
            continue;
        }
        if in_line {
            if b == b'\n' {
                out[i] = 0;
                in_line = false;
            } else {
                out[i] = 1;
            }
            i += 1;
            continue;
        }
        // in_block
        if b == b'*' && b1 == b'/' {
            out[i] = 1;
            if i + 1 < source.len() {
                out[i + 1] = 1;
            }
            i += 2;
            in_block = false;
            continue;
        }
        out[i] = 1;
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_id_is_canonical_and_stable() {
        assert_eq!(
            OP_ID,
            "vyre-libs::parsing::c::preprocess::gpu_comment_strip_mask"
        );
    }

    #[test]
    fn binding_indices_are_canonical_and_stable() {
        assert_eq!(BINDING_BYTES_IN, 0);
        assert_eq!(BINDING_COMMENT_MASK_OUT, 1);
    }

    #[test]
    fn build_program_returns_well_formed_program() {
        let p = gpu_comment_strip_mask(64);
        assert_eq!(p.buffers().len(), 2);
        assert_eq!(p.workgroup_size(), [256, 1, 1]);
    }

    #[test]
    fn cpu_no_comment_returns_all_zero() {
        assert_eq!(gpu_comment_strip_mask_cpu(b"int x = 1;"), vec![0; 10]);
    }

    #[test]
    fn cpu_line_comment_to_eol() {
        // "//foo\nx" → bytes 0..5 are comment (//foo), 5 is newline (0), 6 is 'x' (0).
        assert_eq!(
            gpu_comment_strip_mask_cpu(b"//foo\nx"),
            vec![1, 1, 1, 1, 1, 0, 0]
        );
    }

    #[test]
    fn cpu_block_comment_inline() {
        // "/*x*/" → all 5 bytes are comment.
        assert_eq!(gpu_comment_strip_mask_cpu(b"/*x*/"), vec![1, 1, 1, 1, 1]);
    }

    #[test]
    fn cpu_block_comment_with_code_around() {
        let src = b"a/*c*/b";
        // a=code, /*c*/=comment, b=code.
        assert_eq!(
            gpu_comment_strip_mask_cpu(src),
            vec![0, 1, 1, 1, 1, 1, 0]
        );
    }

    #[test]
    fn cpu_unterminated_block_comment_runs_to_eof() {
        let src = b"a/*xyz";
        // a=code, /*xyz=all comment.
        assert_eq!(gpu_comment_strip_mask_cpu(src), vec![0, 1, 1, 1, 1, 1]);
    }

    #[test]
    fn cpu_lone_slash_is_code() {
        let src = b"a/b";
        assert_eq!(gpu_comment_strip_mask_cpu(src), vec![0, 0, 0]);
    }

    #[test]
    fn cpu_block_inside_string_we_currently_count_as_comment() {
        // We don't track string state — `"/* */"` would mistakenly mark
        // the inner block as a comment. This test pins the current
        // behaviour. A future commit can add string-state tracking.
        let src = b"\"/* */\"";
        let m = gpu_comment_strip_mask_cpu(src);
        assert_eq!(m[1], 1, "currently treats /*…*/ inside string as comment");
    }
}
