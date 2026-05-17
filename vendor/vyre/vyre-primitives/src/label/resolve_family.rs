//! `resolve_family` — `node_tags[v] & family_mask != 0` → NodeSet bit v.
//!
//! One invocation per node. Reads the per-node tag bitmap, ANDs it
//! against the compile-time family mask, atomically-ORs the result
//! bit into `nodeset_out[v / 32]`.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::label::resolve_family";

/// Build a Program: for each node `v`, if
/// `node_tags[v] & family_mask != 0`, set bit `v` in `nodeset_out`.
#[must_use]
pub fn resolve_family(
    node_tags: &str,
    nodeset_out: &str,
    node_count: u32,
    family_mask: u32,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let words = node_count.div_ceil(32);
    let body = vec![
        Node::let_bind("tag", Expr::load(node_tags, t.clone())),
        Node::if_then(
            Expr::ne(
                Expr::bitand(Expr::var("tag"), Expr::u32(family_mask)),
                Expr::u32(0),
            ),
            vec![
                Node::let_bind("word_idx", Expr::shr(t.clone(), Expr::u32(5))),
                Node::let_bind(
                    "bit",
                    Expr::shl(Expr::u32(1), Expr::bitand(t.clone(), Expr::u32(31))),
                ),
                Node::let_bind(
                    "_",
                    Expr::atomic_or(nodeset_out, Expr::var("word_idx"), Expr::var("bit")),
                ),
            ],
        ),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage(node_tags, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(node_count),
            BufferDecl::storage(nodeset_out, 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(words),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(
                Expr::lt(t.clone(), Expr::u32(node_count)),
                body,
            )]),
        }],
    )
}

/// CPU reference.
///
#[must_use]
pub fn cpu_ref(node_tags: &[u32], family_mask: u32) -> Vec<u32> {
    let mut out = Vec::new();
    cpu_ref_into(node_tags, family_mask, &mut out);
    out
}

/// CPU reference using a caller-owned nodeset bitset.
pub fn cpu_ref_into(node_tags: &[u32], family_mask: u32, out: &mut Vec<u32>) {
    let words = node_tags.len().div_ceil(32);
    out.clear();
    out.resize(words, 0);
    for (v, tag) in node_tags.iter().enumerate() {
        if (tag & family_mask) != 0 {
            let word = v / 32;
            let bit = 1u32 << (v % 32);
            out[word] |= bit;
        }
    }
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || resolve_family("tags", "nodeset", 4, 0b0010),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // node_tags: 0x01, 0x02, 0x06, 0x04 — family mask 0x02
            // hits nodes 1 and 2 (0x02 and 0x06 both have bit 1).
            vec![vec![to_bytes(&[0x01, 0x02, 0x06, 0x04]), to_bytes(&[0])]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0b0110])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_family_bit() {
        assert_eq!(cpu_ref(&[0x01, 0x02, 0x06, 0x04], 0x02), vec![0b0110]);
    }

    #[test]
    fn empty_family_yields_empty_nodeset() {
        assert_eq!(cpu_ref(&[0x01, 0x02], 0x00), vec![0]);
    }

    #[test]
    fn cpu_ref_into_reuses_nodeset_buffer() {
        let mut out = Vec::with_capacity(4);
        let ptr = out.as_ptr();
        cpu_ref_into(&[0x01, 0x02, 0x06, 0x04], 0x02, &mut out);
        assert_eq!(out, vec![0b0110]);
        assert_eq!(out.as_ptr(), ptr);
    }

    /// GPU parity tests for resolve_family — exercise every word boundary
    /// to expose the word-1+ atomic_or write bug.
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

        fn run_gpu_resolve_family(node_tags: &[u32], family_mask: u32) -> Vec<u32> {
            let node_count = node_tags.len() as u32;
            let words = node_count.div_ceil(32) as usize;
            let program = resolve_family("tags", "nodeset", node_count, family_mask);
            let backend = CudaBackend::acquire().expect(
                "Fix: CUDA backend acquisition failed. \
                 Configuration error: no CUDA-capable GPU or driver available on this host.",
            );
            let outputs = backend
                .dispatch(
                    &program,
                    &[u32_bytes(node_tags), u32_bytes(&vec![0u32; words])],
                    &DispatchConfig::default(),
                )
                .expect(
                    "Fix: CUDA dispatch failed for resolve_family. \
                     Configuration error: GPU present but kernel launch or readback failed.",
                );
            assert_eq!(
                outputs.len(),
                1,
                "Fix: resolve_family must return exactly one output buffer, got {}.",
                outputs.len()
            );
            let result = bytes_to_u32(&outputs[0]);
            assert_eq!(
                result.len(),
                words,
                "Fix: resolve_family output must contain {} u32 words, got {}.",
                words,
                result.len()
            );
            result
        }

        /// Build a tag vector where only `node` has the family bit set.
        fn tags_with_only(node: usize, node_count: usize, mask: u32) -> Vec<u32> {
            let mut tags = vec![0u32; node_count];
            tags[node] = mask;
            tags
        }

        // ---- Word-boundary positive cases (one node per word 0..7) ----

        #[test]
        fn gpu_resolve_family_node_0_word_0_bit_0() {
            let tags = tags_with_only(0, 256, 0x01);
            let expected = cpu_ref(&tags, 0x01);
            assert_eq!(
                run_gpu_resolve_family(&tags, 0x01),
                expected,
                "FINDING-GPU-RESOLVE-FAMILY-N0: GPU output mismatch at node 0 (word 0 bit 0)"
            );
        }

        #[test]
        fn gpu_resolve_family_node_31_word_0_bit_31() {
            let tags = tags_with_only(31, 256, 0x01);
            let expected = cpu_ref(&tags, 0x01);
            assert_eq!(
                run_gpu_resolve_family(&tags, 0x01),
                expected,
                "FINDING-GPU-RESOLVE-FAMILY-N31: GPU output mismatch at node 31 (word 0 bit 31)"
            );
        }

        #[test]
        fn gpu_resolve_family_node_32_word_1_bit_0() {
            let tags = tags_with_only(32, 256, 0x01);
            let expected = cpu_ref(&tags, 0x01);
            assert_eq!(
                run_gpu_resolve_family(&tags, 0x01),
                expected,
                "FINDING-GPU-RESOLVE-FAMILY-N32: GPU output mismatch at node 32 (word 1 bit 0 / bit-32 boundary)"
            );
        }

        #[test]
        fn gpu_resolve_family_node_33_word_1_bit_1() {
            let tags = tags_with_only(33, 256, 0x01);
            let expected = cpu_ref(&tags, 0x01);
            assert_eq!(
                run_gpu_resolve_family(&tags, 0x01),
                expected,
                "FINDING-GPU-RESOLVE-FAMILY-N33: GPU output mismatch at node 33 (word 1 bit 1)"
            );
        }

        #[test]
        fn gpu_resolve_family_node_39_word_1_bit_7() {
            let tags = tags_with_only(39, 256, 0x01);
            let expected = cpu_ref(&tags, 0x01);
            assert_eq!(
                run_gpu_resolve_family(&tags, 0x01),
                expected,
                "FINDING-GPU-RESOLVE-FAMILY-N39: GPU output mismatch at node 39 (word 1 bit 7)"
            );
        }

        #[test]
        fn gpu_resolve_family_node_63_word_1_bit_31() {
            let tags = tags_with_only(63, 256, 0x01);
            let expected = cpu_ref(&tags, 0x01);
            assert_eq!(
                run_gpu_resolve_family(&tags, 0x01),
                expected,
                "FINDING-GPU-RESOLVE-FAMILY-N63: GPU output mismatch at node 63 (word 1 bit 31 / bit-63 boundary)"
            );
        }

        #[test]
        fn gpu_resolve_family_node_64_word_2_bit_0() {
            let tags = tags_with_only(64, 256, 0x01);
            let expected = cpu_ref(&tags, 0x01);
            assert_eq!(
                run_gpu_resolve_family(&tags, 0x01),
                expected,
                "FINDING-GPU-RESOLVE-FAMILY-N64: GPU output mismatch at node 64 (word 2 bit 0 / bit-64 boundary)"
            );
        }

        #[test]
        fn gpu_resolve_family_node_65_word_2_bit_1() {
            let tags = tags_with_only(65, 256, 0x01);
            let expected = cpu_ref(&tags, 0x01);
            assert_eq!(
                run_gpu_resolve_family(&tags, 0x01),
                expected,
                "FINDING-GPU-RESOLVE-FAMILY-N65: GPU output mismatch at node 65 (word 2 bit 1)"
            );
        }

        #[test]
        fn gpu_resolve_family_node_96_word_3_bit_0() {
            let tags = tags_with_only(96, 256, 0x01);
            let expected = cpu_ref(&tags, 0x01);
            assert_eq!(
                run_gpu_resolve_family(&tags, 0x01),
                expected,
                "FINDING-GPU-RESOLVE-FAMILY-N96: GPU output mismatch at node 96 (word 3 bit 0 / bit-96 boundary)"
            );
        }

        #[test]
        fn gpu_resolve_family_node_127_word_3_bit_31() {
            let tags = tags_with_only(127, 256, 0x01);
            let expected = cpu_ref(&tags, 0x01);
            assert_eq!(
                run_gpu_resolve_family(&tags, 0x01),
                expected,
                "FINDING-GPU-RESOLVE-FAMILY-N127: GPU output mismatch at node 127 (word 3 bit 31)"
            );
        }

        #[test]
        fn gpu_resolve_family_node_128_word_4_bit_0() {
            let tags = tags_with_only(128, 256, 0x01);
            let expected = cpu_ref(&tags, 0x01);
            assert_eq!(
                run_gpu_resolve_family(&tags, 0x01),
                expected,
                "FINDING-GPU-RESOLVE-FAMILY-N128: GPU output mismatch at node 128 (word 4 bit 0 / bit-128 boundary)"
            );
        }

        #[test]
        fn gpu_resolve_family_node_129_word_4_bit_1() {
            let tags = tags_with_only(129, 256, 0x01);
            let expected = cpu_ref(&tags, 0x01);
            assert_eq!(
                run_gpu_resolve_family(&tags, 0x01),
                expected,
                "FINDING-GPU-RESOLVE-FAMILY-N129: GPU output mismatch at node 129 (word 4 bit 1)"
            );
        }

        #[test]
        fn gpu_resolve_family_node_160_word_5_bit_0() {
            let tags = tags_with_only(160, 256, 0x01);
            let expected = cpu_ref(&tags, 0x01);
            assert_eq!(
                run_gpu_resolve_family(&tags, 0x01),
                expected,
                "FINDING-GPU-RESOLVE-FAMILY-N160: GPU output mismatch at node 160 (word 5 bit 0 / bit-160 boundary)"
            );
        }

        #[test]
        fn gpu_resolve_family_node_191_word_5_bit_31() {
            let tags = tags_with_only(191, 256, 0x01);
            let expected = cpu_ref(&tags, 0x01);
            assert_eq!(
                run_gpu_resolve_family(&tags, 0x01),
                expected,
                "FINDING-GPU-RESOLVE-FAMILY-N191: GPU output mismatch at node 191 (word 5 bit 31)"
            );
        }

        #[test]
        fn gpu_resolve_family_node_192_word_6_bit_0() {
            let tags = tags_with_only(192, 256, 0x01);
            let expected = cpu_ref(&tags, 0x01);
            assert_eq!(
                run_gpu_resolve_family(&tags, 0x01),
                expected,
                "FINDING-GPU-RESOLVE-FAMILY-N192: GPU output mismatch at node 192 (word 6 bit 0 / bit-192 boundary)"
            );
        }

        #[test]
        fn gpu_resolve_family_node_193_word_6_bit_1() {
            let tags = tags_with_only(193, 256, 0x01);
            let expected = cpu_ref(&tags, 0x01);
            assert_eq!(
                run_gpu_resolve_family(&tags, 0x01),
                expected,
                "FINDING-GPU-RESOLVE-FAMILY-N193: GPU output mismatch at node 193 (word 6 bit 1)"
            );
        }

        #[test]
        fn gpu_resolve_family_node_224_word_7_bit_0() {
            let tags = tags_with_only(224, 256, 0x01);
            let expected = cpu_ref(&tags, 0x01);
            assert_eq!(
                run_gpu_resolve_family(&tags, 0x01),
                expected,
                "FINDING-GPU-RESOLVE-FAMILY-N224: GPU output mismatch at node 224 (word 7 bit 0 / bit-224 boundary)"
            );
        }

        #[test]
        fn gpu_resolve_family_node_255_word_7_bit_31() {
            let tags = tags_with_only(255, 256, 0x01);
            let expected = cpu_ref(&tags, 0x01);
            assert_eq!(
                run_gpu_resolve_family(&tags, 0x01),
                expected,
                "FINDING-GPU-RESOLVE-FAMILY-N255: GPU output mismatch at node 255 (word 7 bit 31 / last bit)"
            );
        }

        #[test]
        fn gpu_resolve_family_empty_mask_yields_empty_nodeset() {
            let tags = vec![0xffff_ffffu32; 256];
            let expected = cpu_ref(&tags, 0x00);
            assert_eq!(
                run_gpu_resolve_family(&tags, 0x00),
                expected,
                "FINDING-GPU-RESOLVE-FAMILY-EMPTYMASK: GPU output mismatch with zero family mask"
            );
        }

        #[test]
        fn gpu_resolve_family_full_mask_all_nodes_match() {
            let tags = vec![0xffff_ffffu32; 256];
            let expected = cpu_ref(&tags, 0xffff_ffff);
            assert_eq!(
                run_gpu_resolve_family(&tags, 0xffff_ffff),
                expected,
                "FINDING-GPU-RESOLVE-FAMILY-FULLMASK: GPU output mismatch with full family mask"
            );
        }

        #[test]
        fn gpu_resolve_family_multiple_hits_same_word() {
            let mut tags = vec![0u32; 256];
            tags[32] = 0x01;
            tags[33] = 0x01;
            tags[34] = 0x01;
            let expected = cpu_ref(&tags, 0x01);
            assert_eq!(
                run_gpu_resolve_family(&tags, 0x01),
                expected,
                "FINDING-GPU-RESOLVE-FAMILY-MULTI-W1: GPU output mismatch with multiple hits in word 1"
            );
        }

        // ---- Property test: random tags + mask over 256 nodes ----

        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(1000))]

            #[test]
            fn gpu_resolve_family_matches_cpu_oracle_random_256(
                tags in proptest::collection::vec(any::<u32>(), 256),
                mask in any::<u32>()
            ) {
                let gpu = run_gpu_resolve_family(&tags, mask);
                let cpu = cpu_ref(&tags, mask);
                prop_assert_eq!(
                    &gpu, &cpu,
                    "FINDING-GPU-RESOLVE-FAMILY-PROP: GPU resolve_family(tags=[256 words], mask={:#010x}) = {:?}, CPU oracle = {:?}",
                    mask, gpu, cpu
                );
            }
        }
    }
}
