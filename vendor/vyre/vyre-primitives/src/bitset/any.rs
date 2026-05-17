//! `bitset_any` — emit 1 when any bit in the packed bitset is set.
//!
//! Single-lane Program driven by invocation 0: scans every word,
//! ORs them, writes a boolean (0 or 1) to `out[0]`. Used by SURGE
//! `exists` / `any(...)` aggregate lowerings.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::bitset::any";

/// Build a Program: `out[0] = 1` iff any bit of `input` is set.
///
/// AUDIT_2026-04-24 F-ANY-01: the inner loop short-circuits once a
/// non-zero word is observed (tracked via `found` flag). The IR has
/// no `break`, so the cheapest escape is to gate the load+or body on
/// `found == 0` — subsequent iterations become empty bodies and the
/// scan cost degrades to O(first_nonzero_word) instead of O(words).
/// Bitsets are typically sparse (e.g. taint frontiers with one or
/// two set bits) so the average cut is large.
#[must_use]
pub fn bitset_any(input: &str, out: &str, words: u32) -> Program {
    let body = vec![
        Node::let_bind("acc", Expr::u32(0)),
        Node::let_bind("found", Expr::u32(0)),
        Node::loop_for(
            "w",
            Expr::u32(0),
            Expr::u32(words),
            vec![Node::if_then(
                Expr::eq(Expr::var("found"), Expr::u32(0)),
                vec![
                    Node::assign(
                        "acc",
                        Expr::bitor(Expr::var("acc"), Expr::load(input, Expr::var("w"))),
                    ),
                    Node::if_then(
                        Expr::ne(Expr::var("acc"), Expr::u32(0)),
                        vec![Node::assign("found", Expr::u32(1))],
                    ),
                ],
            )],
        ),
        Node::store(
            out,
            Expr::u32(0),
            Expr::select(
                Expr::ne(Expr::var("acc"), Expr::u32(0)),
                Expr::u32(1),
                Expr::u32(0),
            ),
        ),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::U32).with_count(words),
            BufferDecl::storage(out, 1, BufferAccess::ReadWrite, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(
                Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
                body,
            )]),
        }],
    )
}

/// CPU reference.
#[must_use]
pub fn cpu_ref(input: &[u32]) -> u32 {
    if input.iter().any(|w| *w != 0) {
        1
    } else {
        0
    }
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || bitset_any("input", "out", 2),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0, 1]), to_bytes(&[0])]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[1])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_true_when_single_bit_set() {
        assert_eq!(cpu_ref(&[0, 1]), 1);
    }

    #[test]
    fn any_false_when_all_zero() {
        assert_eq!(cpu_ref(&[0, 0]), 0);
    }

    /// GPU parity tests for bitset_any — exercise every word boundary
    /// to expose the word-1+ bitset read bug.
    #[cfg(feature = "gpu")]
    mod gpu_tests {
        use super::*;
        use vyre_driver::DispatchConfig;
        use vyre_driver_cuda::CudaBackend;

        fn u32_bytes(values: &[u32]) -> Vec<u8> {
            values.iter().flat_map(|v| v.to_le_bytes()).collect()
        }

        fn bytes_to_u32(bytes: &[u8]) -> Vec<u32> {
            bytes
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect()
        }

        fn run_gpu_any(input: &[u32]) -> u32 {
            let words = input.len() as u32;
            let program = bitset_any("input", "out", words);
            let backend = CudaBackend::acquire().expect(
                "Fix: CUDA backend acquisition failed. \
                 Configuration error: no CUDA-capable GPU or driver available on this host.",
            );
            let outputs = backend
                .dispatch(
                    &program,
                    &[u32_bytes(input), u32_bytes(&[0])],
                    &DispatchConfig::default(),
                )
                .expect(
                    "Fix: CUDA dispatch failed for bitset_any. \
                     Configuration error: GPU present but kernel launch or readback failed.",
                );
            assert_eq!(
                outputs.len(),
                1,
                "Fix: bitset_any must return exactly one output buffer, got {}.",
                outputs.len()
            );
            let result = bytes_to_u32(&outputs[0]);
            assert_eq!(
                result.len(),
                1,
                "Fix: bitset_any output buffer must contain exactly one u32 word, got {}.",
                result.len()
            );
            result[0]
        }

        // ---- Word-boundary positive cases (one per word 0..7) ----

        #[test]
        fn gpu_any_true_only_word_0_bit_0() {
            let input = vec![1, 0, 0, 0, 0, 0, 0, 0];
            assert_eq!(
                run_gpu_any(&input),
                cpu_ref(&input),
                "FINDING-GPU-BITSET-ANY-W0B0: GPU output mismatch when only word-0 bit-0 is set"
            );
        }

        #[test]
        fn gpu_any_true_only_word_1_bit_0() {
            let input = vec![0, 1, 0, 0, 0, 0, 0, 0];
            assert_eq!(
                run_gpu_any(&input),
                cpu_ref(&input),
                "FINDING-GPU-BITSET-ANY-W1B0: GPU output mismatch when only word-1 is set"
            );
        }

        #[test]
        fn gpu_any_true_only_word_2_bit_0() {
            let input = vec![0, 0, 1, 0, 0, 0, 0, 0];
            assert_eq!(
                run_gpu_any(&input),
                cpu_ref(&input),
                "FINDING-GPU-BITSET-ANY-W2B0: GPU output mismatch when only word-2 is set"
            );
        }

        #[test]
        fn gpu_any_true_only_word_3_bit_0() {
            let input = vec![0, 0, 0, 1, 0, 0, 0, 0];
            assert_eq!(
                run_gpu_any(&input),
                cpu_ref(&input),
                "FINDING-GPU-BITSET-ANY-W3B0: GPU output mismatch when only word-3 is set"
            );
        }

        #[test]
        fn gpu_any_true_only_word_4_bit_0() {
            let input = vec![0, 0, 0, 0, 1, 0, 0, 0];
            assert_eq!(
                run_gpu_any(&input),
                cpu_ref(&input),
                "FINDING-GPU-BITSET-ANY-W4B0: GPU output mismatch when only word-4 is set"
            );
        }

        #[test]
        fn gpu_any_true_only_word_5_bit_0() {
            let input = vec![0, 0, 0, 0, 0, 1, 0, 0];
            assert_eq!(
                run_gpu_any(&input),
                cpu_ref(&input),
                "FINDING-GPU-BITSET-ANY-W5B0: GPU output mismatch when only word-5 is set"
            );
        }

        #[test]
        fn gpu_any_true_only_word_6_bit_0() {
            let input = vec![0, 0, 0, 0, 0, 0, 1, 0];
            assert_eq!(
                run_gpu_any(&input),
                cpu_ref(&input),
                "FINDING-GPU-BITSET-ANY-W6B0: GPU output mismatch when only word-6 is set"
            );
        }

        #[test]
        fn gpu_any_true_only_word_7_bit_0() {
            let input = vec![0, 0, 0, 0, 0, 0, 0, 1];
            assert_eq!(
                run_gpu_any(&input),
                cpu_ref(&input),
                "FINDING-GPU-BITSET-ANY-W7B0: GPU output mismatch when only word-7 is set"
            );
        }

        // ---- Adversarial corner cases at 32-bit word boundaries ----

        #[test]
        fn gpu_any_true_word_0_bit_31_boundary() {
            let input = vec![0x8000_0000, 0, 0, 0, 0, 0, 0, 0];
            assert_eq!(
                run_gpu_any(&input),
                cpu_ref(&input),
                "FINDING-GPU-BITSET-ANY-W0B31: GPU output mismatch at bit-31 boundary"
            );
        }

        #[test]
        fn gpu_any_true_word_1_bit_32_boundary() {
            let input = vec![0, 0x0000_0001, 0, 0, 0, 0, 0, 0];
            assert_eq!(
                run_gpu_any(&input),
                cpu_ref(&input),
                "FINDING-GPU-BITSET-ANY-W1B0-BIT32: GPU output mismatch at bit-32 boundary"
            );
        }

        #[test]
        fn gpu_any_true_word_1_bit_39_like_node_39() {
            let input = vec![0, 1 << 7, 0, 0, 0, 0, 0, 0];
            assert_eq!(
                run_gpu_any(&input),
                cpu_ref(&input),
                "FINDING-GPU-BITSET-ANY-W1B7: GPU output mismatch at bit-39 (word-1 bit-7)"
            );
        }

        #[test]
        fn gpu_any_true_word_1_bit_63_boundary() {
            let input = vec![0, 0x8000_0000, 0, 0, 0, 0, 0, 0];
            assert_eq!(
                run_gpu_any(&input),
                cpu_ref(&input),
                "FINDING-GPU-BITSET-ANY-W1B31-BIT63: GPU output mismatch at bit-63 boundary"
            );
        }

        #[test]
        fn gpu_any_true_word_2_bit_64_boundary() {
            let input = vec![0, 0, 0x0000_0001, 0, 0, 0, 0, 0];
            assert_eq!(
                run_gpu_any(&input),
                cpu_ref(&input),
                "FINDING-GPU-BITSET-ANY-W2B0-BIT64: GPU output mismatch at bit-64 boundary"
            );
        }

        #[test]
        fn gpu_any_true_word_2_bit_65_like_node_65() {
            let input = vec![0, 0, 1 << 1, 0, 0, 0, 0, 0];
            assert_eq!(
                run_gpu_any(&input),
                cpu_ref(&input),
                "FINDING-GPU-BITSET-ANY-W2B1: GPU output mismatch at bit-65 (word-2 bit-1)"
            );
        }

        #[test]
        fn gpu_any_true_word_3_bit_96_boundary() {
            let input = vec![0, 0, 0, 0x0000_0001, 0, 0, 0, 0];
            assert_eq!(
                run_gpu_any(&input),
                cpu_ref(&input),
                "FINDING-GPU-BITSET-ANY-W3B0-BIT96: GPU output mismatch at bit-96 boundary"
            );
        }

        #[test]
        fn gpu_any_true_word_4_bit_128_boundary() {
            let input = vec![0, 0, 0, 0, 0x0000_0001, 0, 0, 0];
            assert_eq!(
                run_gpu_any(&input),
                cpu_ref(&input),
                "FINDING-GPU-BITSET-ANY-W4B0-BIT128: GPU output mismatch at bit-128 boundary"
            );
        }

        #[test]
        fn gpu_any_true_word_5_bit_160_boundary() {
            let input = vec![0, 0, 0, 0, 0, 0x0000_0001, 0, 0];
            assert_eq!(
                run_gpu_any(&input),
                cpu_ref(&input),
                "FINDING-GPU-BITSET-ANY-W5B0-BIT160: GPU output mismatch at bit-160 boundary"
            );
        }

        #[test]
        fn gpu_any_true_word_6_bit_192_boundary() {
            let input = vec![0, 0, 0, 0, 0, 0, 0x0000_0001, 0];
            assert_eq!(
                run_gpu_any(&input),
                cpu_ref(&input),
                "FINDING-GPU-BITSET-ANY-W6B0-BIT192: GPU output mismatch at bit-192 boundary"
            );
        }

        #[test]
        fn gpu_any_true_word_7_bit_224_boundary() {
            let input = vec![0, 0, 0, 0, 0, 0, 0, 0x0000_0001];
            assert_eq!(
                run_gpu_any(&input),
                cpu_ref(&input),
                "FINDING-GPU-BITSET-ANY-W7B0-BIT224: GPU output mismatch at bit-224 boundary"
            );
        }

        #[test]
        fn gpu_any_true_word_7_bit_255_last_bit() {
            let input = vec![0, 0, 0, 0, 0, 0, 0, 0x8000_0000];
            assert_eq!(
                run_gpu_any(&input),
                cpu_ref(&input),
                "FINDING-GPU-BITSET-ANY-W7B31-BIT255: GPU output mismatch at last bit-255"
            );
        }

        #[test]
        fn gpu_any_false_all_zero_8_words() {
            let input = vec![0u32; 8];
            assert_eq!(
                run_gpu_any(&input),
                cpu_ref(&input),
                "FINDING-GPU-BITSET-ANY-ALLZERO: GPU output mismatch for all-zero bitset"
            );
        }

        #[test]
        fn gpu_any_true_all_ones_8_words() {
            let input = vec![0xffff_ffff; 8];
            assert_eq!(
                run_gpu_any(&input),
                cpu_ref(&input),
                "FINDING-GPU-BITSET-ANY-ALLONE: GPU output mismatch for all-ones bitset"
            );
        }

        // ---- Property test: random bitsets over 256 nodes ----

        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(1000))]

            #[test]
            fn gpu_any_matches_cpu_oracle_random_256(input in proptest::collection::vec(any::<u32>(), 8)) {
                let gpu = run_gpu_any(&input);
                let cpu = cpu_ref(&input);
                prop_assert_eq!(
                    gpu, cpu,
                    "FINDING-GPU-BITSET-ANY-PROP: GPU any({:?}) = {}, CPU oracle = {}",
                    input, gpu, cpu
                );
            }
        }
    }
}
