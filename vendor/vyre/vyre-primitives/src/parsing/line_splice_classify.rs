//! `line_splice_classify`  -  per-byte "is-kept" mask for C translation
//! phase 2 (`\<newline>` deletion).
//!
//! Op id: `vyre-primitives::parsing::line_splice_classify`. Soundness:
//! `Exact` against the C11 phase-2 spec (and the existing Reference oracle
//! `c_translation_phase_line_splice` in higher-level preprocessing
//! compositions). The Reference oracle at the bottom of this file is the
//! contract; the GPU `Program` matches it byte-for-byte.
//!
//! ## Why it matters
//!
//! Phase 2 of C11 translation deletes every `\<LF>`, `\<CR>`, and
//! `\<CR><LF>` triple. Every C tokenization path must see the same
//! phase-2 byte stream; a reference one-shot is the only obstacle to a fully
//! GPU-resident preprocessor pipeline. This primitive is the parallel
//! kernel that replaces the byte-at-a-time reference loop.
//!
//! ## Wire layout
//!
//! Inputs:
//!   - `bytes_in`  -  `DataType::Bytes` buffer holding one input byte per
//!     element. Out-of-range loads (past `byte_count`) are guarded by an
//!     `if_then` and never speculate.
//!
//! Outputs:
//!   - `kept_mask_out`  -  `DataType::U32`, one entry per input byte. `1`
//!     if the byte survives phase-2 splice deletion; `0` if it is part of
//!     a `\<newline>` sequence and must be dropped. Composes with
//!     `vyre-primitives::math::stream_compact` to produce the post-phase-2
//!     byte stream and the original-offset map in two further dispatches.
//!
//! ## Why per-byte and not word-at-a-time
//!
//! The deletion patterns straddle word boundaries (`\` in word k, `\n` in
//! word k+1). Word-at-a-time classification would need a 2-word sliding
//! window with explicit cross-lane shuffles. Per-byte threads with
//! ±2-byte neighbor reads keep the kernel readable and let the bounds-
//! check clamp in the PTX backend handle the buffer edge for free.

use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::parsing::line_splice_classify";

/// Canonical binding index for the input byte stream.
pub const BINDING_BYTES_IN: u32 = 0;
/// Canonical binding index for the output kept-mask.
pub const BINDING_KEPT_MASK_OUT: u32 = 1;

const BACKSLASH: u32 = 0x5C; // '\\'
const LF: u32 = 0x0A; // '\n'
const CR: u32 = 0x0D; // '\r'

/// Build the IR `Program` that emits a per-byte kept-mask for phase-2
/// line splicing.
///
/// One thread per input byte. Each thread loads a 5-byte sliding window
/// `[i-2, i-1, i, i+1, i+2]` (0 outside the buffer) and emits `0` to
/// `kept_mask_out[i]` if `byte_in[i]` is part of any deletable sequence.
///
/// The five deletion cases  -  corresponding 1:1 to the Reference oracle
/// `c_translation_phase_line_splice`:
/// 1. `byte[i] == '\\' && byte[i+1] == '\n'`  -  `\` of `\<LF>`.
/// 2. `byte[i] == '\\' && byte[i+1] == '\r'`  -  `\` of `\<CR>` /
///    `\<CR><LF>`.
/// 3. `byte[i-1] == '\\' && byte[i] == '\n'`  -  `<LF>` after `\`.
/// 4. `byte[i-1] == '\\' && byte[i] == '\r'`  -  `<CR>` after `\`.
/// 5. `byte[i-2] == '\\' && byte[i-1] == '\r' && byte[i] == '\n'`  -
///    `<LF>` of `\<CR><LF>`.
///
/// `byte_count` is the number of input bytes. Workgroup size is 256.
#[must_use]
pub fn line_splice_classify(byte_count: u32) -> Program {
    let i = Expr::var("i");

    // ±2-byte neighbor reads. The ±N forms guard `i ± N` against
    // underflow / overflow at the buffer edge; outside the window each
    // byte is treated as 0, which never matches BACKSLASH/LF/CR. The
    // u8 load is widened to u32 so the Select arms have matching types
    // (V029) and so equality compares against the u32 BACKSLASH/LF/CR
    // constants type-cleanly.
    // Real-GPU note: U8 storage buffers emit as `array<u32>`; load
    // returns the u32 word at index `addr`. Reference-eval is byte-
    // addressed. Declaring `bytes_in` as packed U32 below makes both
    // backends agree; this helper extracts the byte explicitly.
    let load_u32 = |addr: Expr| -> Expr {
        let word_idx = Expr::div(addr.clone(), Expr::u32(4));
        let byte_in_word = Expr::rem(addr, Expr::u32(4));
        let word = Expr::cast(DataType::U32, Expr::load("bytes_in", word_idx));
        let shift = Expr::mul(byte_in_word, Expr::u32(8));
        Expr::bitand(Expr::shr(word, shift), Expr::u32(0xFF))
    };
    let load = |off: i32| -> Expr {
        match off {
            0 => load_u32(i.clone()),
            1 => Expr::select(
                Expr::lt(Expr::add(i.clone(), Expr::u32(1)), Expr::u32(byte_count)),
                load_u32(Expr::add(i.clone(), Expr::u32(1))),
                Expr::u32(0),
            ),
            2 => Expr::select(
                Expr::lt(Expr::add(i.clone(), Expr::u32(2)), Expr::u32(byte_count)),
                load_u32(Expr::add(i.clone(), Expr::u32(2))),
                Expr::u32(0),
            ),
            -1 => Expr::select(
                Expr::ge(i.clone(), Expr::u32(1)),
                load_u32(Expr::sub(i.clone(), Expr::u32(1))),
                Expr::u32(0),
            ),
            -2 => Expr::select(
                Expr::ge(i.clone(), Expr::u32(2)),
                load_u32(Expr::sub(i.clone(), Expr::u32(2))),
                Expr::u32(0),
            ),
            _ => unreachable!("line_splice_classify only uses offsets in [-2, 2]"),
        }
    };

    let body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::u32(byte_count)),
            vec![
                Node::let_bind("b_m2", load(-2)),
                Node::let_bind("b_m1", load(-1)),
                Node::let_bind("b_0", load(0)),
                Node::let_bind("b_p1", load(1)),
                // Case 1: byte[i] == '\\' && byte[i+1] == '\n'.
                Node::let_bind(
                    "case1",
                    Expr::and(
                        Expr::eq(Expr::var("b_0"), Expr::u32(BACKSLASH)),
                        Expr::eq(Expr::var("b_p1"), Expr::u32(LF)),
                    ),
                ),
                // Case 2: byte[i] == '\\' && byte[i+1] == '\r'.
                Node::let_bind(
                    "case2",
                    Expr::and(
                        Expr::eq(Expr::var("b_0"), Expr::u32(BACKSLASH)),
                        Expr::eq(Expr::var("b_p1"), Expr::u32(CR)),
                    ),
                ),
                // Case 3: byte[i-1] == '\\' && byte[i] == '\n'.
                Node::let_bind(
                    "case3",
                    Expr::and(
                        Expr::eq(Expr::var("b_m1"), Expr::u32(BACKSLASH)),
                        Expr::eq(Expr::var("b_0"), Expr::u32(LF)),
                    ),
                ),
                // Case 4: byte[i-1] == '\\' && byte[i] == '\r'.
                Node::let_bind(
                    "case4",
                    Expr::and(
                        Expr::eq(Expr::var("b_m1"), Expr::u32(BACKSLASH)),
                        Expr::eq(Expr::var("b_0"), Expr::u32(CR)),
                    ),
                ),
                // Case 5: byte[i-2] == '\\' && byte[i-1] == '\r' && byte[i] == '\n'.
                Node::let_bind(
                    "case5",
                    Expr::and(
                        Expr::eq(Expr::var("b_m2"), Expr::u32(BACKSLASH)),
                        Expr::and(
                            Expr::eq(Expr::var("b_m1"), Expr::u32(CR)),
                            Expr::eq(Expr::var("b_0"), Expr::u32(LF)),
                        ),
                    ),
                ),
                // OR all five cases. If any fires the byte is dropped.
                Node::let_bind(
                    "any_drop",
                    Expr::or(
                        Expr::or(
                            Expr::or(Expr::var("case1"), Expr::var("case2")),
                            Expr::or(Expr::var("case3"), Expr::var("case4")),
                        ),
                        Expr::var("case5"),
                    ),
                ),
                Node::let_bind(
                    "kept",
                    Expr::select(Expr::var("any_drop"), Expr::u32(0), Expr::u32(1)),
                ),
                Node::store("kept_mask_out", i.clone(), Expr::var("kept")),
            ],
        ),
    ];

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
                "kept_mask_out",
                BINDING_KEPT_MASK_OUT,
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

// ---------- reference oracle contract ----------

/// Reference oracle for `line_splice_classify`. Returns one `u32 ∈ {0, 1}`
/// per input byte. The GPU `Program` MUST emit the same vector.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn reference_line_splice_classify(source: &[u8]) -> Vec<u32> {
    let mut out = Vec::new();
    try_reference_line_splice_classify_into(source, &mut out)
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - line-splice classifier reference allocation failed");
    out
}

/// Capacity-reusing variant of `reference_line_splice_classify`.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn reference_line_splice_classify_into(source: &[u8], out: &mut Vec<u32>) {
    try_reference_line_splice_classify_into(source, out)
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - line-splice classifier reference allocation failed");
}

/// Fallible capacity-reusing variant of `reference_line_splice_classify`.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn try_reference_line_splice_classify_into(
    source: &[u8],
    out: &mut Vec<u32>,
) -> Result<(), String> {
    if source.len() > out.capacity() {
        out.try_reserve_exact(source.len() - out.capacity())
            .map_err(|err| {
                format!(
                    "line-splice classifier reference could not reserve {} output words: {err}",
                    source.len()
                )
            })?;
    }
    out.clear();
    for i in 0..source.len() {
        let b_m2 = i.checked_sub(2).map(|j| source[j]).unwrap_or(0);
        let b_m1 = i.checked_sub(1).map(|j| source[j]).unwrap_or(0);
        let b_0 = source[i];
        let b_p1 = source.get(i + 1).copied().unwrap_or(0);
        let case1 = b_0 == b'\\' && b_p1 == b'\n';
        let case2 = b_0 == b'\\' && b_p1 == b'\r';
        let case3 = b_m1 == b'\\' && b_0 == b'\n';
        let case4 = b_m1 == b'\\' && b_0 == b'\r';
        let case5 = b_m2 == b'\\' && b_m1 == b'\r' && b_0 == b'\n';
        let dropped = case1 || case2 || case3 || case4 || case5;
        out.push(u32::from(!dropped));
    }
    Ok(())
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || line_splice_classify(256),
        Some(|| {
            let to_bytes = |w: &[u32]| crate::wire::pack_u32_slice(w);
            let mut bytes = vec![120 | (120 << 8) | (120 << 16) | (120 << 24); 64];
            bytes[0] = 97 | (92 << 8) | (10 << 16) | (98 << 24);
            vec![vec![
                to_bytes(&bytes),                // bytes_in
                to_bytes(&[0; 256]),             // kept_mask_out
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| crate::wire::pack_u32_slice(w);
            let mut expected = vec![1; 256];
            expected[1] = 0;
            expected[2] = 0;
            vec![vec![to_bytes(&expected)]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_emits_empty_output() {
        assert!(reference_line_splice_classify(b"").is_empty());
    }

    #[test]
    fn classify_into_reuses_output_and_clears_stale_tail() {
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(&[u32::MAX; 16]);
        let ptr = out.as_ptr();

        try_reference_line_splice_classify_into(b"a\\\nB", &mut out).unwrap();

        assert_eq!(out, vec![1, 0, 0, 1]);
        assert_eq!(out.as_ptr(), ptr);
    }

    #[test]
    fn no_backslashes_keeps_every_byte() {
        let src = b"int main(void) { return 0; }";
        let mask = reference_line_splice_classify(src);
        assert_eq!(mask, vec![1; src.len()]);
    }

    #[test]
    fn lone_backslash_with_no_newline_is_kept() {
        // Backslash followed by space is not a splice  -  both bytes survive.
        let src = b"a\\ b";
        let mask = reference_line_splice_classify(src);
        assert_eq!(mask, vec![1, 1, 1, 1]);
    }

    #[test]
    fn backslash_lf_pair_drops_both_bytes() {
        let src = b"a\\\nb";
        let mask = reference_line_splice_classify(src);
        // 'a' kept, '\\' dropped, '\n' dropped, 'b' kept.
        assert_eq!(mask, vec![1, 0, 0, 1]);
    }

    #[test]
    fn backslash_cr_lf_triple_drops_all_three() {
        let src = b"a\\\r\nb";
        let mask = reference_line_splice_classify(src);
        // 'a' kept, '\\' dropped, '\r' dropped, '\n' dropped, 'b' kept.
        assert_eq!(mask, vec![1, 0, 0, 0, 1]);
    }

    #[test]
    fn backslash_cr_alone_drops_both_bytes() {
        // \<CR> with no following LF  -  still a splice on classic
        // Mac-style line endings.
        let src = b"a\\\rb";
        let mask = reference_line_splice_classify(src);
        assert_eq!(mask, vec![1, 0, 0, 1]);
    }

    #[test]
    fn back_to_back_splices_each_drop_their_pair() {
        // a\\\nb\\\nc  -  two splices.
        let src = b"a\\\nb\\\nc";
        let mask = reference_line_splice_classify(src);
        assert_eq!(mask, vec![1, 0, 0, 1, 0, 0, 1]);
    }

    #[test]
    fn splice_at_start_of_buffer_is_handled() {
        // Buffer starts with \\\n  -  both dropped.
        let src = b"\\\nx";
        let mask = reference_line_splice_classify(src);
        assert_eq!(mask, vec![0, 0, 1]);
    }

    #[test]
    fn splice_at_end_of_buffer_is_handled() {
        // Buffer ends with \\\n  -  both dropped.
        let src = b"x\\\n";
        let mask = reference_line_splice_classify(src);
        assert_eq!(mask, vec![1, 0, 0]);
    }

    #[test]
    fn lone_backslash_at_eof_is_kept() {
        // Backslash at end of buffer with nothing following  -  keeps it
        // (there's no newline to splice with).
        let src = b"x\\";
        let mask = reference_line_splice_classify(src);
        assert_eq!(mask, vec![1, 1]);
    }

    #[test]
    fn double_backslash_before_newline_only_drops_the_pair() {
        // a\\\\\nb  -  `\\\\` is two backslashes; only the second `\\` and
        // the `\n` form a splice.
        let src = b"a\\\\\nb";
        let mask = reference_line_splice_classify(src);
        assert_eq!(mask, vec![1, 1, 0, 0, 1]);
    }

    #[test]
    fn cr_alone_without_backslash_is_kept() {
        let src = b"a\rb";
        let mask = reference_line_splice_classify(src);
        assert_eq!(mask, vec![1, 1, 1]);
    }

    #[test]
    fn lf_alone_without_backslash_is_kept() {
        let src = b"a\nb";
        let mask = reference_line_splice_classify(src);
        assert_eq!(mask, vec![1, 1, 1]);
    }

    #[test]
    fn op_id_is_canonical_and_stable() {
        assert_eq!(OP_ID, "vyre-primitives::parsing::line_splice_classify");
    }

    #[test]
    fn binding_indices_are_canonical_and_stable() {
        assert_eq!(BINDING_BYTES_IN, 0);
        assert_eq!(BINDING_KEPT_MASK_OUT, 1);
    }

    #[test]
    fn build_program_returns_well_formed_program() {
        let p = line_splice_classify(64);
        assert_eq!(p.buffers().len(), 2, "bytes_in + kept_mask_out");
        assert_eq!(p.workgroup_size(), [256, 1, 1]);
    }

    #[test]
    fn build_program_is_deterministic_across_calls() {
        let p1 = line_splice_classify(128);
        let p2 = line_splice_classify(128);
        assert_eq!(p1.buffers().len(), p2.buffers().len());
        assert_eq!(p1.workgroup_size(), p2.workgroup_size());
    }

    #[test]
    fn cpu_reference_is_deterministic() {
        let src = b"a\\\nb\\\r\nc\\\rd";
        let m1 = reference_line_splice_classify(src);
        let m2 = reference_line_splice_classify(src);
        assert_eq!(m1, m2);
    }

    #[test]
    fn classify_into_reuses_output_capacity() {
        let src = b"a\\\nb";
        let mut out = Vec::with_capacity(64);
        let cap = out.capacity();
        reference_line_splice_classify_into(src, &mut out);
        assert_eq!(out, vec![1, 0, 0, 1]);
        assert_eq!(out.capacity(), cap);
    }
}
