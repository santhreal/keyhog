//! GPU-accelerated byte histogram + encoding classification.
//!
//! Replaces the CPU-only sliding-window stats used by Mozilla-style
//! universalchardet with a single-dispatch GPU histogram kernel. Each
//! work-item owns one byte value (0..255) and counts occurrences across
//! the entire input. Thread 0 then reads the 256-bin histogram and
//! applies a compact heuristic classifier.
//!
//! # Design notes
//!
//! - Single workgroup [256,1,1] keeps the classification exact (no
//!   cross-workgroup reduction needed). The histogram is the bottleneck
//!   for multi-MB scans; a single SM can saturate most of device memory
//!   bandwidth with perfectly coalesced strided loads.
//! - N-gram frequencies are **not** computed on-GPU yet; the task
//!   explicitly permits leaving the small-N classifier on CPU and
//!   focusing on the byte-histogram pass (PHASE2_DECODE MEDIUM).
//! - The CPU fallback `encodex_cpu` mirrors the GPU heuristics so
//!   callers can choose the path that fits their pipeline.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Program};
use vyre_primitives::text::byte_histogram::byte_histogram_256_child;
pub use vyre_primitives::text::encoding_classify::{
    classify_from_histogram, encoding_classify_child, ENC_ASCII, ENC_BINARY, ENC_ISO8859_1,
    ENC_UTF16BE, ENC_UTF16LE, ENC_UTF8,
};

#[cfg(test)]
use crate::buffer_names::fixed_name;
use crate::buffer_names::scoped_generic_name;
use crate::region::wrap_anonymous;

const OP_ID: &str = "vyre-libs::decode::encodex";
const FAMILY_PREFIX: &str = "decode_encodex";
const HISTOGRAM_BUFFER: &str = "__vyre_decode_encodex_histogram";

fn scoped_input_buffer(name: &str) -> String {
    scoped_generic_name(FAMILY_PREFIX, "input", name, &["input"])
}

fn scoped_output_buffer(name: &str) -> String {
    scoped_generic_name(
        FAMILY_PREFIX,
        "encoding_id",
        name,
        &["encoding_id", "output"],
    )
}

fn pack_words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

/// Build a Program that computes a 256-bin byte histogram over `input`
/// and writes the detected encoding-id to `output`.
///
/// The input buffer carries one byte per `u32` element (same convention
/// used by `vyre-libs::decode::base64` and `hex`).  The histogram is
/// exposed as a `read_write` buffer so callers can read it back for
/// their own CPU-side refinement if desired.
///
/// ```ignore
/// use vyre_libs::decode::encodex_gpu;
///
/// let program = encodex_gpu("bytes", "encoding", 1024);
/// assert_eq!(program.buffers().len(), 3);
/// ```
#[must_use]
pub fn encodex_gpu(input: &str, output: &str, count: u32) -> Program {
    let input = scoped_input_buffer(input);
    let output = scoped_output_buffer(output);
    let histogram = HISTOGRAM_BUFFER.to_string();
    let body = vec![
        byte_histogram_256_child(OP_ID, &input, &histogram, count),
        encoding_classify_child(OP_ID, &histogram, &output, count),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage(&input, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(count.max(1)),
            BufferDecl::read_write(&histogram, 1, DataType::U32).with_count(256),
            BufferDecl::output(&output, 2, DataType::U32).with_count(1),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(OP_ID, body)],
    )
}

/// CPU fallback that mirrors the GPU heuristics.
///
/// Computes the same 256-bin histogram and applies the identical
/// classification rules so `encodex_cpu` and `encodex_gpu` agree on
/// every input.
pub fn encodex_cpu(input: &[u8]) -> u32 {
    let mut histogram = [0u32; 256];
    for &byte in input {
        histogram[usize::from(byte)] += 1;
    }
    classify_from_histogram(&histogram, input.len() as u32)
}

// ---------------------------------------------------------------------------
// Fixtures & harness
// ---------------------------------------------------------------------------

fn fixture_cases() -> Vec<Vec<u8>> {
    vec![
        b"Hello".to_vec(),
        vec![0xC3, 0xA9, 0xC3, 0xA9, b'!'],
        vec![0x00, 0x00, 0x00, 0x41, 0x42],
        vec![0xE9, 0xE8, 0xEA, 0xEB, 0xEC],
    ]
}

fn fixture_inputs() -> Vec<Vec<Vec<u8>>> {
    fixture_cases()
        .into_iter()
        .map(|input| {
            vec![
                pack_words(&input.iter().map(|&b| u32::from(b)).collect::<Vec<_>>()),
                vec![0u8; 256 * 4],
                vec![0u8; 4],
            ]
        })
        .collect()
}

fn fixture_outputs() -> Vec<Vec<Vec<u8>>> {
    fixture_cases()
        .into_iter()
        .map(|input| {
            let mut histogram = [0u32; 256];
            for &b in &input {
                histogram[usize::from(b)] += 1;
            }
            let enc_id = classify_from_histogram(&histogram, input.len() as u32);
            vec![
                histogram.iter().flat_map(|v| v.to_le_bytes()).collect(),
                enc_id.to_le_bytes().to_vec(),
            ]
        })
        .collect()
}

inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || encodex_gpu("input", "output", 5),
        Some(fixture_inputs),
        Some(fixture_outputs),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_reference::value::Value;

    fn run(input: &[u8]) -> (Vec<u32>, u32) {
        let program = encodex_gpu("input", "output", input.len() as u32);
        let input_words = if input.is_empty() {
            vec![0]
        } else {
            input.iter().map(|&b| u32::from(b)).collect::<Vec<_>>()
        };
        let inputs = vec![
            Value::from(pack_words(&input_words)),
            Value::from(vec![0u8; 256 * 4]),
            Value::from(vec![0u8; 4]),
        ];
        let outputs = vyre_reference::reference_eval(&program, &inputs).expect("encodex must run");
        let histogram = outputs[0]
            .to_bytes()
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect();
        let enc_id = u32::from_le_bytes([
            outputs[1].to_bytes()[0],
            outputs[1].to_bytes()[1],
            outputs[1].to_bytes()[2],
            outputs[1].to_bytes()[3],
        ]);
        (histogram, enc_id)
    }

    #[test]
    fn ascii_detected() {
        let (histogram, enc_id) = run(b"Hello");
        assert_eq!(histogram[72], 1);
        assert_eq!(histogram[101], 1);
        assert_eq!(histogram[108], 2);
        assert_eq!(histogram[111], 1);
        assert_eq!(enc_id, ENC_ASCII);
    }

    #[test]
    fn utf8_detected() {
        // é encoded as UTF-8 = 0xC3 0xA9
        let (histogram, enc_id) = run(&[0xC3, 0xA9, 0xC3, 0xA9]);
        assert_eq!(histogram[0xC3], 2);
        assert_eq!(histogram[0xA9], 2);
        assert_eq!(enc_id, ENC_UTF8);
    }

    #[test]
    fn high_null_guesses_utf16le() {
        let (histogram, enc_id) = run(&[0x00, 0x00, 0x00, 0x41]);
        assert_eq!(histogram[0x00], 3);
        assert_eq!(histogram[0x41], 1);
        assert_eq!(enc_id, ENC_UTF16LE);
    }

    #[test]
    fn iso8859_1_detected() {
        let (histogram, enc_id) = run(&[0xE9, 0xE8, 0xEA]);
        assert_eq!(histogram[0xE9], 1);
        assert_eq!(histogram[0xE8], 1);
        assert_eq!(histogram[0xEA], 1);
        assert_eq!(enc_id, ENC_ISO8859_1);
    }

    #[test]
    fn empty_input_is_ascii() {
        let (histogram, enc_id) = run(b"");
        assert!(histogram.iter().all(|&v| v == 0));
        assert_eq!(enc_id, ENC_ASCII);
    }

    #[test]
    fn cpu_gpu_parity() {
        let inputs: Vec<&[u8]> = vec![
            b"Hello world",
            &[0xC3, 0xA9],
            &[0x00, 0x00, 0x41],
            &[0xE9, 0xE8],
            b"Pure ASCII text here",
        ];
        for input in inputs {
            let (_, gpu_id) = run(input);
            let cpu_id = encodex_cpu(input);
            assert_eq!(
                gpu_id, cpu_id,
                "GPU/CPU mismatch for input {:?}: gpu={} cpu={}",
                input, gpu_id, cpu_id
            );
        }
    }

    #[test]
    fn generic_default_names_are_family_scoped() {
        let program = encodex_gpu("input", "output", 8);
        assert_eq!(
            program.buffers()[0].name(),
            fixed_name(FAMILY_PREFIX, "input")
        );
        assert_eq!(
            program.buffers()[2].name(),
            fixed_name(FAMILY_PREFIX, "encoding_id")
        );
    }
}
