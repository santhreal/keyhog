//! GPU LZ4 literal-extraction composition.
//!
//! # GPU-port design
//!
//! LZ4 blocks are a tightly packed sequence of (token, literals, match) tuples.
//! The format has a serial dependency: you cannot know where sequence N starts
//! without parsing sequences 0..N-1.  This makes a naive one-thread-per-byte
//! kernel impossible.
//!
//! ## Two-stage pipeline
//!
//! 1. **Index build** (CPU fallback today, GPU prefix-sum in future).
//!    Walk the token stream and emit a table where row `i` holds:
//!    - `seq_literal_start[i]` — byte offset of the first literal byte
//!    - `seq_literal_len[i]`  — number of literal bytes
//!    - `seq_literal_offset[i]` — prefix-sum output position
//!
//! 2. **Parallel copy** (`ziftsieve_gpu`).
//!    One invocation per sequence.  Each lane reads its row from the index
//!    buffers and copies `literal_len` bytes from `input` to `output` at
//!    `literal_offset`.  This stage is fully parallel, divergence is bounded
//!    by the natural distribution of literal lengths, and the output stays
//!    in GPU memory for a fused scan kernel.
//!
//! ## Future work
//!
//! - Move the index build to GPU using a Blelloch prefix-sum over a
//!   token-length pass (needs `BufferAccess::Workgroup` + barrier lowering).
//! - Fuse `ziftsieve_gpu` with `aho_corasick` so literals never touch host
//!   memory (decode→scan chain).
//!
//! See `NOTE_ZIFTSIEVE_GPU_DESIGN` for the canonical pointer.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::buffer_names::scoped_generic_name;
use crate::region::wrap_anonymous;

const OP_ID: &str = "vyre-libs::decode::ziftsieve";
const FAMILY_PREFIX: &str = "decode_ziftsieve";

/// Canonical pointer to the GPU-port design documentation.
///
/// The full design lives in the module-level doc comment of this file.
pub const NOTE_ZIFTSIEVE_GPU_DESIGN: &str =
    "docs: GPU-port design is in the module-level doc comment of \
     libs/performance/matching/vyre/vyre-libs/src/decode/ziftsieve.rs";

fn scoped_input_buffer(name: &str) -> String {
    scoped_generic_name(FAMILY_PREFIX, "input", name, &["input"])
}

fn scoped_output_buffer(name: &str) -> String {
    scoped_generic_name(FAMILY_PREFIX, "output", name, &["output", "decoded"])
}

fn pack_words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

// ---------------------------------------------------------------------------
// CPU fallback
// ---------------------------------------------------------------------------

const MAX_BLOCK_SIZE: usize = 4 * 1024 * 1024;
const MAX_SEQUENCES_PER_BLOCK: usize = 100_000;

/// CPU fallback: sequential LZ4 literal extraction.
///
/// Re-implements the hot loop from `ziftsieve::lz4::extract_literals` so
/// `vyre-libs` does not need to depend on the `ziftsieve` crate.
///
/// # Errors
///
/// Returns an actionable error string on malformed input.  Every error
/// message includes a `Fix:` tag.
pub fn ziftsieve_cpu_extract_literals(
    compressed: &[u8],
    max_output: usize,
) -> Result<Vec<u8>, String> {
    let initial_cap = compressed
        .len()
        .saturating_mul(2)
        .min(max_output)
        .min(MAX_BLOCK_SIZE);
    let mut literals = Vec::with_capacity(initial_cap);
    let mut pos = 0usize;
    let mut sequence_count = 0usize;

    while pos < compressed.len() {
        sequence_count += 1;
        if sequence_count >= MAX_SEQUENCES_PER_BLOCK {
            return Err(format!(
                "too many LZ4 sequences (max {MAX_SEQUENCES_PER_BLOCK}). \
                 Fix: use a smaller LZ4 block or increase MAX_SEQUENCES_PER_BLOCK"
            ));
        }

        if pos >= compressed.len() {
            break;
        }

        let token = compressed[pos];
        pos += 1;

        let literal_len = (token >> 4) as usize;
        let match_len = (token & 0x0F) as usize;

        let literal_len = if literal_len == 15 {
            decode_length(compressed, &mut pos, literal_len)?
        } else {
            literal_len
        };

        if literal_len > MAX_BLOCK_SIZE {
            return Err(format!(
                "literal length {literal_len} exceeds MAX_BLOCK_SIZE {MAX_BLOCK_SIZE}. \
                 Fix: use a valid LZ4 stream"
            ));
        }

        if pos + literal_len > compressed.len() {
            return Err(format!(
                "literal exceeds block bounds at offset {pos}. \
                 Fix: use a valid LZ4 stream"
            ));
        }

        let remaining_output = max_output.saturating_sub(literals.len());
        let to_copy = literal_len.min(remaining_output);

        if to_copy > 0 {
            literals.extend_from_slice(&compressed[pos..pos + to_copy]);
        }

        pos += literal_len;

        if pos < compressed.len() {
            if pos + 2 > compressed.len() {
                return Err(format!(
                    "truncated match offset at offset {pos}. \
                     Fix: use a complete LZ4 stream"
                ));
            }
            pos += 2; // skip match offset

            if match_len == 15 {
                let _ = decode_length(compressed, &mut pos, match_len)?;
            }
        }
    }

    Ok(literals)
}

fn decode_length(data: &[u8], pos: &mut usize, initial: usize) -> Result<usize, String> {
    let mut len = initial;
    loop {
        if *pos >= data.len() {
            return Err(format!(
                "truncated length encoding at offset {pos}. \
                 Fix: use a complete LZ4 stream"
            ));
        }
        let byte = data[*pos];
        *pos += 1;
        len = len.checked_add(byte as usize).ok_or_else(|| {
            "length overflow in variable-length encoding. Fix: use a valid LZ4 stream".to_string()
        })?;
        if byte < 255 {
            break;
        }
        if len > MAX_BLOCK_SIZE {
            return Err(format!(
                "length {len} exceeds MAX_BLOCK_SIZE {MAX_BLOCK_SIZE}. \
                 Fix: use a valid LZ4 stream"
            ));
        }
    }
    Ok(len)
}

// ---------------------------------------------------------------------------
// GPU builder
// ---------------------------------------------------------------------------

fn ziftsieve_gpu_body(
    input: &str,
    output: &str,
    seq_literal_start: &str,
    seq_literal_len: &str,
    seq_literal_offset: &str,
    seq_count: u32,
) -> Vec<Node> {
    vec![
        Node::let_bind("seq_idx", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(Expr::var("seq_idx"), Expr::u32(seq_count)),
            vec![
                Node::let_bind(
                    "literal_start",
                    Expr::load(seq_literal_start, Expr::var("seq_idx")),
                ),
                Node::let_bind(
                    "literal_len",
                    Expr::load(seq_literal_len, Expr::var("seq_idx")),
                ),
                Node::let_bind(
                    "literal_offset",
                    Expr::load(seq_literal_offset, Expr::var("seq_idx")),
                ),
                Node::loop_for(
                    "i",
                    Expr::u32(0),
                    Expr::var("literal_len"),
                    vec![
                        Node::let_bind(
                            "src",
                            Expr::load(
                                input,
                                Expr::add(Expr::var("literal_start"), Expr::var("i")),
                            ),
                        ),
                        Node::store(
                            output,
                            Expr::add(Expr::var("literal_offset"), Expr::var("i")),
                            Expr::var("src"),
                        ),
                    ],
                ),
            ],
        ),
    ]
}

/// Build a Program that copies LZ4 literals in parallel given a pre-built
/// sequence index.
///
/// # Buffers
///
/// - `input` (binding 0): ReadOnly `u32` — raw LZ4 block bytes, one `u32` per byte.
/// - `seq_literal_start` (binding 1): ReadOnly `u32` — for each sequence, byte
///   offset of the first literal byte.
/// - `seq_literal_len` (binding 2): ReadOnly `u32` — for each sequence, number
///   of literal bytes.
/// - `seq_literal_offset` (binding 3): ReadOnly `u32` — for each sequence,
///   output position (prefix sum of literal lengths).
/// - `output` (binding 4): output `u32` — concatenated literal bytes, one `u32`
///   per byte.
///
/// One invocation processes one sequence.  Sequences with zero literals are
/// no-ops.  The caller must size `output` to the sum of all `literal_len`.
///
/// # Parameters
///
/// - `input` — name of the input buffer.
/// - `output` — name of the output buffer.
/// - `seq_literal_start` — name of the sequence-start buffer.
/// - `seq_literal_len` — name of the sequence-length buffer.
/// - `seq_literal_offset` — name of the sequence-offset buffer.
/// - `input_len` — length of the input buffer in elements.
/// - `seq_count` — number of sequences.
/// - `max_output` — maximum output buffer size in elements.
#[must_use]
pub fn ziftsieve_gpu(
    input: &str,
    output: &str,
    seq_literal_start: &str,
    seq_literal_len: &str,
    seq_literal_offset: &str,
    input_len: u32,
    seq_count: u32,
    max_output: u32,
) -> Program {
    let input = scoped_input_buffer(input);
    let output = scoped_output_buffer(output);
    let body = ziftsieve_gpu_body(
        &input,
        &output,
        seq_literal_start,
        seq_literal_len,
        seq_literal_offset,
        seq_count,
    );

    let input_decl = BufferDecl::storage(&input, 0, BufferAccess::ReadOnly, DataType::U32);
    let input_decl = if input_len == 0 {
        input_decl
    } else {
        input_decl.with_count(input_len)
    };

    Program::wrapped(
        vec![
            input_decl,
            BufferDecl::storage(seq_literal_start, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(seq_count.max(1)),
            BufferDecl::storage(seq_literal_len, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(seq_count.max(1)),
            BufferDecl::storage(seq_literal_offset, 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(seq_count.max(1)),
            BufferDecl::output(&output, 4, DataType::U32).with_count(max_output.max(1)),
        ],
        [64, 1, 1],
        vec![wrap_anonymous(OP_ID, body)],
    )
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn fixture_inputs() -> Vec<Vec<Vec<u8>>> {
    // Two sequences: "A" then "BC"
    let input = pack_words(&[0x10, b'A' as u32, 0x20, b'B' as u32, b'C' as u32]);
    let seq_literal_start = pack_words(&[1, 3]);
    let seq_literal_len = pack_words(&[1, 2]);
    let seq_literal_offset = pack_words(&[0, 1]);
    let output = vec![0u8; 3 * 4];
    vec![vec![
        input,
        seq_literal_start,
        seq_literal_len,
        seq_literal_offset,
        output,
    ]]
}

fn fixture_outputs() -> Vec<Vec<Vec<u8>>> {
    vec![vec![pack_words(&[b'A' as u32, b'B' as u32, b'C' as u32])]]
}

inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || ziftsieve_gpu("input", "output", "seq_start", "seq_len", "seq_off", 5, 2, 3),
        Some(fixture_inputs),
        Some(fixture_outputs),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use vyre_reference::value::Value;

    fn run(input: &[u8], seq_starts: &[u32], seq_lens: &[u32], seq_offsets: &[u32]) -> Vec<u32> {
        let seq_count = seq_starts.len() as u32;
        let max_output = seq_lens.iter().copied().sum::<u32>();
        let program = ziftsieve_gpu(
            "input",
            "output",
            "seq_start",
            "seq_len",
            "seq_off",
            input.len() as u32,
            seq_count,
            max_output,
        );
        let inputs = vec![
            Value::from(pack_words(
                &input.iter().map(|&b| u32::from(b)).collect::<Vec<_>>(),
            )),
            Value::from(pack_words(seq_starts)),
            Value::from(pack_words(seq_lens)),
            Value::from(pack_words(seq_offsets)),
            Value::from(vec![0u8; (max_output.max(1) as usize) * 4]),
        ];
        let outputs =
            vyre_reference::reference_eval(&program, &inputs).expect("ziftsieve_gpu must run");
        let words: Vec<u32> = outputs[0]
            .to_bytes()
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect();
        words.into_iter().take(max_output as usize).collect()
    }

    #[test]
    fn single_literal() {
        // Token: 0x10 = literal_len=1, match_len=0, literal='A'
        assert_eq!(run(&[0x10, b'A'], &[1], &[1], &[0]), vec![b'A' as u32]);
    }

    #[test]
    fn two_sequences() {
        // Seq1: 0x10, 'A'  (1 literal)
        // Seq2: 0x20, 'B', 'C'  (2 literals)
        assert_eq!(
            run(&[0x10, b'A', 0x20, b'B', b'C'], &[1, 3], &[1, 2], &[0, 1]),
            vec![b'A' as u32, b'B' as u32, b'C' as u32]
        );
    }

    #[test]
    fn zero_literal_sequence_is_nop() {
        // One sequence with 0 literals.
        assert_eq!(
            run(&[0x00, 0x10, b'A'], &[0], &[0], &[0]),
            Vec::<u32>::new()
        );
    }

    #[test]
    fn cpu_fallback_extracts_simple_literal() {
        let data = [0x10, b'A'];
        let result = ziftsieve_cpu_extract_literals(&data, 1024).unwrap();
        assert_eq!(result, b"A");
    }

    #[test]
    fn cpu_fallback_extracts_with_match_skip() {
        // Token: 0x11 = literal_len=1, match_len=1
        // Literal: 'A'
        // Match offset: 0x0001
        let data = [0x11, b'A', 0x01, 0x00];
        let result = ziftsieve_cpu_extract_literals(&data, 1024).unwrap();
        assert_eq!(result, b"A");
    }

    #[test]
    fn cpu_fallback_rejects_truncated_literal() {
        let data = [0x20, b'A']; // Claims 2 literals, only 1 present
        assert!(ziftsieve_cpu_extract_literals(&data, 1024).is_err());
    }

    #[test]
    fn cpu_fallback_rejects_too_many_sequences() {
        let mut data = Vec::new();
        // Pack MAX_SEQUENCES_PER_BLOCK + 1 single-byte-literal sequences.
        for _ in 0..=MAX_SEQUENCES_PER_BLOCK {
            data.push(0x10); // literal_len=1, match_len=0
            data.push(b'X');
            data.extend_from_slice(&[0x00, 0x00]); // match offset
        }
        assert!(ziftsieve_cpu_extract_literals(&data, 1024).is_err());
    }
}
