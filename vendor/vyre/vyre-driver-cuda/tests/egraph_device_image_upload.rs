//! CUDA e-graph device-image upload planning tests.

use vyre_driver_cuda::{
    pack_cuda_egraph_canonical_rewrite_device_image, plan_cuda_egraph_device_upload,
    plan_cuda_egraph_device_upload_from_image, plan_cuda_egraph_device_upload_from_image_ref,
    plan_cuda_egraph_signature_buckets, plan_cuda_egraph_structural_equivalence_launch_artifact,
    plan_cuda_egraph_union_compaction, CudaBackend, CudaEGraphCanonicalRewrite,
    CudaEGraphDeviceByteLayout, CudaEGraphDeviceByteSpan, CudaEGraphDeviceUploadError,
    CudaEGraphFixedPointReadback, CudaEGraphKernelLaunchConfig,
    CudaEGraphSignatureBucketDeviceImage, CudaEGraphSignaturePairWave,
    CudaEGraphStructuralEquivalenceLaunchArtifact, CudaEGraphStructuralEquivalenceOutputPlan,
    CudaEGraphUnionCompactionPass, CudaEGraphUnionCompactionPlan,
    CUDA_EGRAPH_SIGNATURE_BUCKET_RECORD_WORDS, CUDA_EGRAPH_STRUCTURAL_EQUIVALENCE_KERNEL_ENTRY,
};
use vyre_foundation::optimizer::eqsat_gpu::{
    Equivalence, GpuEGraphDeviceImageError, GpuEGraphSnapshot,
};

fn expected_column_snapshot_bytes(layout: CudaEGraphDeviceByteLayout) -> usize {
    [
        layout.row_eclass_ids(),
        layout.row_language_op_ids(),
        layout.row_children_offsets(),
        layout.row_children_lens(),
        layout.row_signatures(),
        layout.children(),
    ]
    .iter()
    .map(CudaEGraphDeviceByteSpan::byte_len)
    .sum()
}

#[test]
fn egraph_device_image_upload_plan_preserves_single_slab_layout() {
    let snapshot = GpuEGraphSnapshot::build([
        (2u32, "lit", &[][..]),
        (1u32, "lit", &[][..]),
        (2u32, "add", &[1u32, 2u32][..]),
    ]);

    let plan = plan_cuda_egraph_device_upload(&snapshot)
        .expect("Fix: valid foundation e-graph image must produce a CUDA upload plan");
    let layout = plan.byte_layout();

    assert_eq!(plan.byte_len(), plan.words().len() * 4);
    assert_eq!(layout.row_count(), 3);
    assert_eq!(layout.child_count(), 2);
    assert_eq!(layout.eclass_group_count(), 2);
    assert_eq!(layout.row_eclass_ids().offset(), 0);
    assert_eq!(layout.row_eclass_ids().byte_len(), 12);
    assert_eq!(layout.row_language_op_ids().offset(), 12);
    assert_eq!(layout.row_children_offsets().offset(), 24);
    assert_eq!(layout.row_children_lens().offset(), 36);
    assert_eq!(layout.row_signatures().offset(), 48);
    assert_eq!(layout.row_signatures().byte_len(), 12);
    assert_eq!(layout.children().offset(), 60);
    assert_eq!(layout.children().byte_len(), 8);
    assert_eq!(layout.group_eclass_ids().offset(), 68);
    assert_eq!(layout.group_offsets().offset(), 76);
    assert_eq!(layout.group_rows().offset(), 88);
}

#[test]
fn borrowed_egraph_device_image_upload_plan_matches_owned_plan_without_image_clone() {
    let snapshot = GpuEGraphSnapshot::build([
        (2u32, "lit", &[][..]),
        (1u32, "lit", &[][..]),
        (2u32, "add", &[1u32, 2u32][..]),
    ]);
    let image = snapshot
        .try_pack_device_image()
        .expect("Fix: valid foundation e-graph image must pack.");
    let owned = plan_cuda_egraph_device_upload_from_image(image.clone())
        .expect("Fix: owned CUDA e-graph upload plan must build.");
    let borrowed = plan_cuda_egraph_device_upload_from_image_ref(&image)
        .expect("Fix: borrowed CUDA e-graph upload plan must build.");

    assert_eq!(borrowed.words(), owned.words());
    assert_eq!(borrowed.byte_layout(), owned.byte_layout());
    assert_eq!(borrowed.byte_len(), owned.byte_len());
}

#[test]
fn egraph_device_image_upload_plan_rejects_malformed_snapshot() {
    let mut snapshot = GpuEGraphSnapshot::build([(0u32, "lit", &[][..])]);
    snapshot.rows[0].language_op_id = 99;

    let error = plan_cuda_egraph_device_upload(&snapshot)
        .expect_err("Fix: CUDA upload planning must reject malformed e-graph images");

    match error {
        CudaEGraphDeviceUploadError::Image(GpuEGraphDeviceImageError::Integrity(error)) => {
            assert_eq!(error.context(), "unknown language_op_id");
            assert_eq!(error.row(), 0);
            assert_eq!(error.value(), 99);
        }
        other => panic!("expected integrity error from foundation image packer, got {other}"),
    }
}

#[test]
fn borrowed_egraph_device_image_upload_round_trips_through_cuda_resident_memory() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let snapshot = GpuEGraphSnapshot::build([
        (10u32, "lit", &[][..]),
        (20u32, "lit", &[][..]),
        (30u32, "add", &[10u32, 20u32][..]),
        (40u32, "add", &[10u32, 20u32][..]),
    ]);
    let image = snapshot
        .try_pack_device_image()
        .expect("Fix: valid foundation e-graph image must pack.");
    let borrowed = plan_cuda_egraph_device_upload_from_image_ref(&image)
        .expect("Fix: borrowed CUDA e-graph upload plan must build.");
    let expected_bytes = borrowed
        .words()
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();

    let resident = backend
        .upload_egraph_device_image_borrowed_plan(borrowed)
        .expect("Fix: borrowed CUDA e-graph resident image upload failed.");
    let output = backend
        .download_resident(resident.handle())
        .expect("Fix: borrowed CUDA e-graph resident image download failed.");

    assert_eq!(output, expected_bytes);
    assert_eq!(resident.byte_len(), borrowed.byte_len());
    assert_eq!(resident.word_count(), borrowed.words().len());

    backend
        .free_resident(resident.handle())
        .expect("Fix: borrowed CUDA e-graph resident image free failed.");
}

#[test]
fn egraph_device_image_upload_round_trips_through_cuda_resident_memory() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let snapshot = GpuEGraphSnapshot::build([
        (2u32, "lit", &[][..]),
        (1u32, "lit", &[][..]),
        (2u32, "add", &[1u32, 2u32][..]),
    ]);
    let plan = plan_cuda_egraph_device_upload(&snapshot)
        .expect("Fix: valid foundation e-graph image must produce a CUDA upload plan");
    let expected_bytes = plan
        .words()
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();

    let resident = backend
        .upload_egraph_device_image_plan(plan)
        .expect("Fix: CUDA e-graph resident image upload failed.");
    let output = backend
        .download_resident(resident.handle())
        .expect("Fix: CUDA e-graph resident image download failed.");

    assert_eq!(resident.byte_len(), expected_bytes.len());
    assert_eq!(resident.word_count(), expected_bytes.len() / 4);
    assert_eq!(output, expected_bytes);

    let view = backend
        .egraph_device_kernel_view(resident)
        .expect("Fix: resident e-graph image must resolve to checked kernel pointers.");
    assert_ne!(view.base_ptr(), 0);
    assert_eq!(view.byte_len(), expected_bytes.len());
    assert_eq!(view.row_count(), 3);
    assert_eq!(view.child_count(), 2);
    assert_eq!(view.eclass_group_count(), 2);
    assert_eq!(view.row_eclass_ids_ptr(), view.base_ptr());
    assert_eq!(view.row_language_op_ids_ptr(), view.base_ptr() + 12);
    assert_eq!(view.row_children_offsets_ptr(), view.base_ptr() + 24);
    assert_eq!(view.row_children_lens_ptr(), view.base_ptr() + 36);
    assert_eq!(view.row_signatures_ptr(), view.base_ptr() + 48);
    assert_eq!(view.children_ptr(), view.base_ptr() + 60);
    assert_eq!(view.group_eclass_ids_ptr(), view.base_ptr() + 68);
    assert_eq!(view.group_offsets_ptr(), view.base_ptr() + 76);
    assert_eq!(view.group_rows_ptr(), view.base_ptr() + 88);

    backend
        .free_resident(resident.handle())
        .expect("Fix: CUDA e-graph resident image free failed.");
}

#[test]
fn egraph_structural_discovery_uses_borrowed_upload_plan_without_image_clone() {
    let source = include_str!("../src/egraph_kernel_plan.rs");
    let method_start = source
        .find("pub fn discover_egraph_structural_equivalences")
        .expect("Fix: structural discovery method must remain present.");
    let method_end = source[method_start..]
        .find("    /// Generate and warm-load the canonical e-graph rewrite kernel")
        .map(|offset| method_start + offset)
        .expect("Fix: structural discovery method boundary must remain discoverable.");
    let method = &source[method_start..method_end];

    assert!(
        method.contains("plan_cuda_egraph_device_upload_from_image_ref(&image)")
            && method.contains("upload_egraph_device_image_borrowed_plan"),
        "Fix: CUDA e-graph structural discovery must upload from a borrowed packed image so the same image can feed signature planning without a slab clone."
    );
    assert!(
        !method.contains("image.clone()"),
        "Fix: CUDA e-graph structural discovery must not clone the packed foundation image before upload."
    );
}

#[test]
fn egraph_device_image_upload_uses_resident_io_boundary_not_raw_cuda_ffi() {
    let source = include_str!("../src/egraph_device_image.rs");

    assert!(
        source.contains("self.allocate_resident")
            && source.contains("upload_egraph_words_to_resident")
            && source.contains("backend.upload_resident"),
        "Fix: e-graph image upload must reuse CUDA resident allocation/upload infrastructure through the staging-free helper."
    );
    for forbidden in ["cuMemAlloc", "cuMemcpyHtoD", "cuMemcpyDtoH"] {
        assert!(
            !source.contains(forbidden),
            "Fix: e-graph image upload must not introduce a raw CUDA FFI branch `{forbidden}`."
        );
    }
}

#[test]
fn egraph_device_image_upload_uses_zero_staging_byte_view_on_little_endian_hosts() {
    let source = include_str!("../src/egraph_device_image.rs");
    let method_start = source
        .find("pub fn upload_egraph_device_image_plan")
        .expect("Fix: e-graph upload plan method must remain present.");
    let method_end = source[method_start..]
        .find("    /// Resolve a resident e-graph image")
        .map(|offset| method_start + offset)
        .expect("Fix: e-graph upload method boundary must remain discoverable.");
    let method = &source[method_start..method_end];
    let helper_start = source
        .find("fn upload_egraph_words_to_resident")
        .expect("Fix: e-graph upload must use a dedicated word upload helper.");
    let helper_end = source[helper_start..]
        .find("#[cfg(not(target_endian = \"little\"))]")
        .map(|offset| helper_start + offset)
        .expect("Fix: little-endian upload helper boundary must remain discoverable.");
    let helper = &source[helper_start..helper_end];

    assert!(
        method.contains(
            "self.upload_egraph_device_image_words(plan.words(), plan.byte_layout(), plan.byte_len())"
        ) && method.contains("upload_egraph_words_to_resident(self, handle, words)"),
        "Fix: e-graph upload must route owned and borrowed plans through the shared staging-free helper."
    );
    assert!(
        helper.contains("#[cfg(target_endian = \"little\")]")
            && helper.contains("bytemuck::cast_slice(words)")
            && helper.contains("backend.upload_resident(handle"),
        "Fix: little-endian CUDA e-graph upload must cast the packed u32 slab to bytes without per-word staging."
    );
}

#[test]
fn egraph_signature_snapshot_uses_range_readback_not_full_slab_download() {
    let source = include_str!("../src/egraph_kernel_plan.rs");
    let method_start = source
        .find("pub fn download_egraph_resident_signature_snapshot")
        .expect("Fix: signature snapshot method must remain present.");
    let method_end = source[method_start..]
        .find("    /// Run one CUDA-resident structural canonicalization round")
        .map(|offset| method_start + offset)
        .expect("Fix: signature snapshot method boundary must remain discoverable.");
    let method = &source[method_start..method_end];

    assert!(
        method.contains("download_resident_range"),
        "Fix: signature-only e-graph snapshots must use ranged CUDA readback."
    );
    assert!(
        !method.contains("download_resident(image.handle())"),
        "Fix: signature-only e-graph snapshots must not download the whole resident image."
    );
}

#[test]
fn egraph_column_snapshot_uses_fused_range_readbacks_not_full_slab_download() {
    let source = include_str!("../src/egraph_kernel_plan.rs");
    let method_start = source
        .find("pub fn download_egraph_resident_column_snapshot")
        .expect("Fix: column snapshot method must remain present.");
    let method_end = source[method_start..]
        .find("    /// Download only the current CUDA-resident row-signature column")
        .map(|offset| method_start + offset)
        .expect("Fix: column snapshot method boundary must remain discoverable.");
    let method = &source[method_start..method_end];

    assert!(
        method.contains("download_resident_ranges_into(&ranges, &mut outputs)"),
        "Fix: full-column e-graph snapshots must use fused ranged CUDA readback for the required planning columns."
    );
    assert!(
        !method.contains("download_resident(image.handle())"),
        "Fix: full-column e-graph snapshots must not download group metadata or unrelated resident slab bytes."
    );
}

#[test]
fn egraph_u32_scratch_upload_uses_zero_staging_byte_view_on_little_endian_hosts() {
    let source = include_str!("../src/egraph_kernel_plan.rs");
    let function_start = source
        .find("fn upload_u32_words(")
        .expect("Fix: e-graph u32 scratch upload helper must remain present.");
    let function_end = source[function_start..]
        .find("fn upload_resident_bytes")
        .map(|offset| function_start + offset)
        .expect("Fix: e-graph u32 scratch upload helper boundary must remain discoverable.");
    let function = &source[function_start..function_end];

    assert!(
        function.contains("upload_u32_words_to_resident")
            && function.contains("#[cfg(target_endian = \"little\")]")
            && function.contains("bytemuck::cast_slice(words)")
            && function.contains("EMPTY_U32_UPLOAD"),
        "Fix: CUDA e-graph u32 scratch metadata upload must avoid host byte staging on little-endian hosts while preserving empty-buffer zero initialization."
    );
}

#[test]
fn egraph_structural_equivalence_kernel_ptx_loads_on_live_cuda_driver() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let before = backend
        .cached_module_count()
        .expect("Fix: CUDA module cache count must be readable before e-graph kernel warm-load.");

    let kernel = backend
        .warm_egraph_structural_equivalence_kernel()
        .expect("Fix: CUDA driver rejected the generated e-graph structural-equivalence PTX.");
    let after_first = backend
        .cached_module_count()
        .expect("Fix: CUDA module cache count must be readable after e-graph kernel warm-load.");
    let second = backend
        .warm_egraph_structural_equivalence_kernel()
        .expect("Fix: CUDA e-graph structural-equivalence PTX must remain cache-loadable.");
    let after_second = backend
        .cached_module_count()
        .expect("Fix: CUDA module cache count must be readable after cached warm-load.");

    assert_eq!(
        kernel.entry_name,
        CUDA_EGRAPH_STRUCTURAL_EQUIVALENCE_KERNEL_ENTRY
    );
    assert_eq!(second.source, kernel.source);
    assert!(
        after_first >= before,
        "Fix: CUDA e-graph PTX warm-load must not shrink the module cache."
    );
    assert_eq!(
        after_second, after_first,
        "Fix: repeated e-graph PTX warm-load should hit the module cache instead of inserting duplicate modules."
    );
}

#[test]
fn egraph_structural_equivalence_kernel_emits_live_cuda_pairs() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let snapshot = GpuEGraphSnapshot::build([
        (10u32, "lit", &[][..]),
        (20u32, "lit", &[][..]),
        (30u32, "add", &[10u32, 20u32][..]),
        (40u32, "add", &[10u32, 20u32][..]),
        (50u32, "add", &[20u32, 10u32][..]),
    ]);
    let image = snapshot
        .try_pack_device_image()
        .expect("Fix: valid foundation e-graph image must pack.");
    let upload_plan = plan_cuda_egraph_device_upload_from_image(image.clone())
        .expect("Fix: packed e-graph image must produce a CUDA upload plan.");
    let resident = backend
        .upload_egraph_device_image_plan(upload_plan)
        .expect("Fix: CUDA e-graph resident image upload failed.");
    let view = backend
        .egraph_device_kernel_view(resident)
        .expect("Fix: CUDA e-graph resident image must expose kernel pointers.");
    let signature_plan = plan_cuda_egraph_signature_buckets(
        &image,
        view,
        CudaEGraphKernelLaunchConfig {
            threads_per_block: 8,
            max_blocks_per_launch: 1,
        },
    )
    .expect("Fix: CUDA e-graph signature bucket planning must succeed.");
    let artifact = plan_cuda_egraph_structural_equivalence_launch_artifact(&signature_plan)
        .expect("Fix: CUDA e-graph structural-equivalence artifact must build.");

    let result = backend
        .run_egraph_structural_equivalence_kernel(resident, &artifact)
        .expect("Fix: live CUDA e-graph structural-equivalence kernel launch failed.");

    assert_eq!(result.device_reported_count, 2);
    assert!(!result.overflowed_output_capacity);
    assert_eq!(
        result.unique,
        vec![
            Equivalence {
                left: 10,
                right: 20,
            },
            Equivalence {
                left: 30,
                right: 40,
            },
        ]
    );

    backend
        .free_resident(resident.handle())
        .expect("Fix: CUDA e-graph resident image free failed.");
}

#[test]
fn egraph_structural_equivalence_discovery_api_runs_end_to_end() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let snapshot = GpuEGraphSnapshot::build([
        (10u32, "lit", &[][..]),
        (20u32, "lit", &[][..]),
        (30u32, "add", &[10u32, 20u32][..]),
        (40u32, "add", &[10u32, 20u32][..]),
        (50u32, "add", &[20u32, 10u32][..]),
        (60u32, "mul", &[30u32, 40u32][..]),
        (70u32, "mul", &[30u32, 40u32][..]),
    ]);
    let image = snapshot
        .try_pack_device_image()
        .expect("Fix: valid foundation e-graph image must pack.");

    let result = backend
        .discover_egraph_structural_equivalences(
            image,
            CudaEGraphKernelLaunchConfig {
                threads_per_block: 4,
                max_blocks_per_launch: 1,
            },
        )
        .expect(
            "Fix: live CUDA e-graph discovery API must own upload, launch, readback, and cleanup.",
        );

    assert_eq!(result.device_reported_count, 3);
    assert!(!result.overflowed_output_capacity);
    assert_eq!(
        result.unique,
        vec![
            Equivalence {
                left: 10,
                right: 20,
            },
            Equivalence {
                left: 30,
                right: 40,
            },
            Equivalence {
                left: 60,
                right: 70,
            },
        ]
    );
}

#[test]

fn egraph_structural_equivalence_kernel_rejects_forced_ordering_bucket() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let snapshot = GpuEGraphSnapshot::build([
        (10u32, "lit", &[][..]),
        (20u32, "lit", &[][..]),
        (30u32, "add", &[10u32, 20u32][..]),
        (40u32, "add", &[20u32, 10u32][..]),
    ]);
    let image = snapshot
        .try_pack_device_image()
        .expect("Fix: valid foundation e-graph image must pack.");
    let upload_plan = plan_cuda_egraph_device_upload_from_image(image.clone())
        .expect("Fix: packed e-graph image must produce a CUDA upload plan.");
    let resident = backend
        .upload_egraph_device_image_plan(upload_plan)
        .expect("Fix: CUDA e-graph resident image upload failed.");
    let artifact = CudaEGraphStructuralEquivalenceLaunchArtifact {
        bucket_image: CudaEGraphSignatureBucketDeviceImage {
            bucket_words: vec![image.row_signatures()[2], 0, 2, 1, 0],
            bucket_rows: vec![2, 3],
            bucket_count: 1,
            bucket_record_words: CUDA_EGRAPH_SIGNATURE_BUCKET_RECORD_WORDS,
            candidate_pair_count: 1,
        },
        output: CudaEGraphStructuralEquivalenceOutputPlan {
            max_equivalences: 1,
            output_pair_words: 2,
            output_pair_bytes: 8,
            output_counter_words: 2,
            output_counter_bytes: 8,
        },
        pair_waves: vec![CudaEGraphSignaturePairWave {
            bucket_index: 0,
            first_pair: 0,
            pair_count: 1,
            blocks: 1,
            threads_per_block: 1,
        }],
    };

    let result = backend.run_egraph_structural_equivalence_kernel(resident, &artifact);
    backend
        .free_resident(resident.handle())
        .expect("Fix: CUDA e-graph resident image free failed.");
    let result = result.expect(
        "Fix: live CUDA e-graph kernel must reject forced non-equivalent ordering without failing launch.",
    );

    assert_eq!(result.device_reported_count, 0);
    assert_eq!(result.emitted_pair_count, 0);
    assert!(!result.overflowed_output_capacity);
    assert!(result.unique.is_empty());
}

#[test]
fn egraph_union_compaction_plan_canonicalizes_duplicates_reversals_and_chains() {
    let plan = plan_cuda_egraph_union_compaction(
        &[
            Equivalence { left: 5, right: 3 },
            Equivalence { left: 3, right: 5 },
            Equivalence { left: 8, right: 5 },
            Equivalence { left: 9, right: 9 },
            Equivalence {
                left: 11,
                right: 10,
            },
            Equivalence {
                left: 12,
                right: 11,
            },
        ],
        CudaEGraphKernelLaunchConfig {
            threads_per_block: 2,
            max_blocks_per_launch: 1,
        },
    )
    .expect(
        "Fix: CUDA e-graph union compaction planning must accept hostile duplicate merge batches.",
    );

    assert_eq!(plan.ignored_self_pair_count, 1);
    assert_eq!(plan.duplicate_pair_count, 1);
    assert_eq!(
        plan.canonical_pairs,
        vec![
            Equivalence { left: 3, right: 5 },
            Equivalence { left: 5, right: 8 },
            Equivalence {
                left: 10,
                right: 11,
            },
            Equivalence {
                left: 11,
                right: 12,
            },
        ]
    );
    assert_eq!(plan.affected_eclasses, vec![3, 5, 8, 10, 11, 12]);
    assert_eq!(
        plan.canonical_rewrites,
        vec![
            CudaEGraphCanonicalRewrite {
                eclass_id: 5,
                representative: 3,
            },
            CudaEGraphCanonicalRewrite {
                eclass_id: 8,
                representative: 3,
            },
            CudaEGraphCanonicalRewrite {
                eclass_id: 11,
                representative: 10,
            },
            CudaEGraphCanonicalRewrite {
                eclass_id: 12,
                representative: 10,
            },
        ]
    );
    assert_eq!(plan.total_items, 8);
    assert_eq!(plan.total_blocks, 4);
    assert_eq!(plan.waves.len(), 4);
    assert_eq!(
        plan.waves[0].pass,
        CudaEGraphUnionCompactionPass::UnionPairs
    );
    assert_eq!(plan.waves[0].first_item, 0);
    assert_eq!(plan.waves[0].item_count, 2);
    assert_eq!(
        plan.waves[1].pass,
        CudaEGraphUnionCompactionPass::UnionPairs
    );
    assert_eq!(plan.waves[1].first_item, 2);
    assert_eq!(
        plan.waves[2].pass,
        CudaEGraphUnionCompactionPass::CanonicalRewrites
    );
    assert_eq!(plan.waves[2].first_item, 0);
    assert_eq!(
        plan.waves[3].pass,
        CudaEGraphUnionCompactionPass::CanonicalRewrites
    );
    assert_eq!(plan.waves[3].first_item, 2);
}

#[test]
fn egraph_union_compaction_plan_splits_oversized_merge_batches() {
    let pairs = (0..17)
        .map(|index| Equivalence {
            left: index,
            right: index + 1,
        })
        .collect::<Vec<_>>();

    let plan = plan_cuda_egraph_union_compaction(
        &pairs,
        CudaEGraphKernelLaunchConfig {
            threads_per_block: 4,
            max_blocks_per_launch: 2,
        },
    )
    .expect("Fix: CUDA e-graph union compaction planning must split oversized batches.");

    assert_eq!(plan.canonical_pairs.len(), 17);
    assert_eq!(plan.canonical_rewrites.len(), 17);
    assert_eq!(plan.total_items, 34);
    assert_eq!(plan.waves.len(), 6);
    assert_eq!(
        plan.waves[0].pass,
        CudaEGraphUnionCompactionPass::UnionPairs
    );
    assert_eq!(plan.waves[0].item_count, 8);
    assert_eq!(plan.waves[1].item_count, 8);
    assert_eq!(plan.waves[2].item_count, 1);
    assert_eq!(
        plan.waves[3].pass,
        CudaEGraphUnionCompactionPass::CanonicalRewrites
    );
    assert_eq!(plan.waves[3].item_count, 8);
    assert_eq!(plan.waves[4].item_count, 8);
    assert_eq!(plan.waves[5].item_count, 1);
}

#[test]
fn egraph_union_compaction_plan_rejects_zero_launch_dimensions() {
    let pair = [Equivalence { left: 1, right: 2 }];
    use vyre_driver_cuda::egraph_kernel_plan::CudaEGraphKernelPlanError;
    assert_eq!(
        plan_cuda_egraph_union_compaction(
            &pair,
            CudaEGraphKernelLaunchConfig {
                threads_per_block: 0,
                max_blocks_per_launch: 1,
            },
        )
        .unwrap_err(),
        CudaEGraphKernelPlanError::ZeroThreadsPerBlock
    );
    assert_eq!(
        plan_cuda_egraph_union_compaction(
            &pair,
            CudaEGraphKernelLaunchConfig {
                threads_per_block: 1,
                max_blocks_per_launch: 0,
            },
        )
        .unwrap_err(),
        CudaEGraphKernelPlanError::ZeroMaxBlocksPerLaunch
    );
}

#[test]
fn egraph_union_compaction_plan_fast_paths_empty_batches() {
    let plan = plan_cuda_egraph_union_compaction(
        &[],
        CudaEGraphKernelLaunchConfig {
            threads_per_block: 4,
            max_blocks_per_launch: 2,
        },
    )
    .expect("Fix: CUDA e-graph union compaction must accept empty convergence batches.");

    assert!(plan.canonical_pairs.is_empty());
    assert!(plan.affected_eclasses.is_empty());
    assert!(plan.canonical_rewrites.is_empty());
    assert!(plan.waves.is_empty());
    assert_eq!(plan.ignored_self_pair_count, 0);
    assert_eq!(plan.duplicate_pair_count, 0);
    assert_eq!(plan.total_items, 0);
    assert_eq!(plan.total_blocks, 0);

    let self_pair_only = plan_cuda_egraph_union_compaction(
        &[Equivalence { left: 7, right: 7 }],
        CudaEGraphKernelLaunchConfig {
            threads_per_block: 4,
            max_blocks_per_launch: 2,
        },
    )
    .expect("Fix: CUDA e-graph union compaction must accept self-pair-only convergence batches.");

    assert!(self_pair_only.canonical_pairs.is_empty());
    assert!(self_pair_only.affected_eclasses.is_empty());
    assert!(self_pair_only.canonical_rewrites.is_empty());
    assert!(self_pair_only.waves.is_empty());
    assert_eq!(self_pair_only.ignored_self_pair_count, 1);
    assert_eq!(self_pair_only.duplicate_pair_count, 0);
    assert_eq!(self_pair_only.total_items, 0);
    assert_eq!(self_pair_only.total_blocks, 0);
}

#[test]
fn egraph_union_compaction_plan_handles_generated_adversarial_batches() {
    let config = CudaEGraphKernelLaunchConfig {
        threads_per_block: 7,
        max_blocks_per_launch: 3,
    };
    let max_items_per_wave = u64::from(config.threads_per_block * config.max_blocks_per_launch);
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64;

    for case_index in 0..4096_u32 {
        let class_count = 4 + (next_u32(&mut seed) % 37);
        let base = case_index
            .checked_mul(1000)
            .expect("Fix: generated e-graph case base must fit u32.");
        let edge_count = 2 * class_count + (next_u32(&mut seed) % class_count);
        let mut pairs = Vec::new();
        for edge_index in 0..edge_count {
            let left = base + (next_u32(&mut seed) % class_count);
            let right = base + (next_u32(&mut seed) % class_count);
            pairs.push(Equivalence { left, right });
            if edge_index % 3 == 0 {
                pairs.push(Equivalence {
                    left: right,
                    right: left,
                });
            }
            if edge_index % 5 == 0 {
                pairs.push(Equivalence { left, right: left });
            }
        }

        let plan = plan_cuda_egraph_union_compaction(&pairs, config)
            .expect("Fix: generated hostile e-graph union batches must remain plannable.");

        assert_sorted_unique_pairs(&plan);
        assert_rewrites_are_final_representatives(&plan);
        assert_wave_coverage(&plan, max_items_per_wave);
    }
}

fn next_u32(seed: &mut u64) -> u32 {
    *seed = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    (*seed >> 32) as u32
}

fn assert_sorted_unique_pairs(plan: &CudaEGraphUnionCompactionPlan) {
    let mut previous = None;
    for pair in &plan.canonical_pairs {
        assert!(
            pair.left < pair.right,
            "Fix: CUDA e-graph union planner must drop self pairs and order reversed pairs."
        );
        if let Some(previous) = previous {
            assert!(
                previous < (pair.left, pair.right),
                "Fix: CUDA e-graph union planner must sort and deduplicate merge pairs."
            );
        }
        previous = Some((pair.left, pair.right));
    }
}

fn assert_rewrites_are_final_representatives(plan: &CudaEGraphUnionCompactionPlan) {
    for rewrite in &plan.canonical_rewrites {
        assert!(
            rewrite.representative < rewrite.eclass_id,
            "Fix: CUDA e-graph union compaction must choose the minimum e-class id as representative."
        );
        assert!(
            plan.affected_eclasses
                .binary_search(&rewrite.representative)
                .is_ok(),
            "Fix: CUDA e-graph union representative must be part of the affected e-class set."
        );
        assert_eq!(
            planned_representative(plan, rewrite.representative),
            rewrite.representative,
            "Fix: CUDA e-graph canonical rewrites must be final, not transitive chains."
        );
    }
    for pair in &plan.canonical_pairs {
        assert_eq!(
            planned_representative(plan, pair.left),
            planned_representative(plan, pair.right),
            "Fix: every planned union pair endpoint must collapse to one representative."
        );
    }
}

fn planned_representative(plan: &CudaEGraphUnionCompactionPlan, eclass_id: u32) -> u32 {
    plan.canonical_rewrites
        .iter()
        .find(|rewrite| rewrite.eclass_id == eclass_id)
        .map_or(eclass_id, |rewrite| rewrite.representative)
}

fn assert_wave_coverage(plan: &CudaEGraphUnionCompactionPlan, max_items_per_wave: u64) {
    let union_items = plan
        .waves
        .iter()
        .filter(|wave| wave.pass == CudaEGraphUnionCompactionPass::UnionPairs)
        .map(|wave| {
            assert!(wave.item_count <= max_items_per_wave);
            assert!(u64::from(wave.blocks * wave.threads_per_block) >= wave.item_count);
            wave.item_count
        })
        .sum::<u64>();
    let rewrite_items = plan
        .waves
        .iter()
        .filter(|wave| wave.pass == CudaEGraphUnionCompactionPass::CanonicalRewrites)
        .map(|wave| {
            assert!(wave.item_count <= max_items_per_wave);
            assert!(u64::from(wave.blocks * wave.threads_per_block) >= wave.item_count);
            wave.item_count
        })
        .sum::<u64>();

    assert_eq!(union_items, plan.canonical_pairs.len() as u64);
    assert_eq!(rewrite_items, plan.canonical_rewrites.len() as u64);
    assert_eq!(plan.total_items, union_items + rewrite_items);
}

#[test]
fn egraph_canonical_rewrite_kernel_updates_live_cuda_resident_image() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let snapshot = GpuEGraphSnapshot::build([
        (10u32, "lit", &[][..]),
        (20u32, "lit", &[][..]),
        (30u32, "add", &[10u32, 20u32][..]),
        (40u32, "add", &[20u32, 10u32][..]),
        (50u32, "mul", &[30u32, 40u32][..]),
    ]);
    let image = snapshot
        .try_pack_device_image()
        .expect("Fix: valid foundation e-graph image must pack.");
    let upload_plan = plan_cuda_egraph_device_upload_from_image(image)
        .expect("Fix: packed e-graph image must produce a CUDA upload plan.");
    let byte_layout = upload_plan.byte_layout();
    let resident = backend
        .upload_egraph_device_image_plan(upload_plan)
        .expect("Fix: CUDA e-graph resident image upload failed.");
    let union_plan = plan_cuda_egraph_union_compaction(
        &[
            Equivalence {
                left: 20,
                right: 10,
            },
            Equivalence {
                left: 40,
                right: 30,
            },
        ],
        CudaEGraphKernelLaunchConfig {
            threads_per_block: 3,
            max_blocks_per_launch: 2,
        },
    )
    .expect("Fix: CUDA e-graph union compaction plan must build.");
    let rewrite_image = pack_cuda_egraph_canonical_rewrite_device_image(&union_plan)
        .expect("Fix: CUDA e-graph canonical rewrite image must pack.");

    let result = backend
        .run_egraph_canonical_rewrite_kernel(
            resident,
            &rewrite_image,
            CudaEGraphKernelLaunchConfig {
                threads_per_block: 3,
                max_blocks_per_launch: 2,
            },
        )
        .expect("Fix: live CUDA canonical rewrite kernel must update resident e-graph image.");
    let output = backend
        .download_resident(resident.handle())
        .expect("Fix: CUDA e-graph resident image download failed after canonical rewrite.");

    assert_eq!(result.rewrite_count, 2);
    assert_eq!(result.row_count, 5);
    assert_eq!(result.child_count, 6);
    assert_eq!(result.launch_count, 2);
    assert_eq!(result.total_items, 11);
    assert_eq!(
        read_u32_span(&output, byte_layout.row_eclass_ids(), 5),
        vec![10, 10, 30, 30, 50]
    );
    assert_eq!(
        read_u32_span(&output, byte_layout.children(), 6),
        vec![10, 10, 10, 10, 30, 30]
    );

    backend
        .free_resident(resident.handle())
        .expect("Fix: CUDA e-graph resident image free failed.");
}

#[test]
fn egraph_structural_canonicalization_round_discovers_and_rewrites_live_cuda_image() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let snapshot = GpuEGraphSnapshot::build([
        (10u32, "lit", &[][..]),
        (20u32, "lit", &[][..]),
        (30u32, "add", &[10u32, 20u32][..]),
        (40u32, "add", &[10u32, 20u32][..]),
        (50u32, "mul", &[30u32, 40u32][..]),
        (60u32, "mul", &[30u32, 40u32][..]),
    ]);
    let image = snapshot
        .try_pack_device_image()
        .expect("Fix: valid foundation e-graph image must pack.");
    let upload_plan = plan_cuda_egraph_device_upload_from_image(image.clone())
        .expect("Fix: packed e-graph image must produce a CUDA upload plan.");
    let byte_layout = upload_plan.byte_layout();
    let resident = backend
        .upload_egraph_device_image_plan(upload_plan)
        .expect("Fix: CUDA e-graph resident image upload failed.");

    let result = backend
        .run_egraph_structural_canonicalization_round(
            resident,
            &image,
            CudaEGraphKernelLaunchConfig {
                threads_per_block: 4,
                max_blocks_per_launch: 2,
            },
        )
        .expect("Fix: live CUDA e-graph canonicalization round must discover, plan, and rewrite.");
    let output = backend
        .download_resident(resident.handle())
        .expect("Fix: CUDA e-graph resident image download failed after canonicalization round.");

    assert_eq!(
        result.discovery.unique,
        vec![
            Equivalence {
                left: 10,
                right: 20,
            },
            Equivalence {
                left: 30,
                right: 40,
            },
            Equivalence {
                left: 50,
                right: 60,
            },
        ]
    );
    assert_eq!(result.union_plan.canonical_rewrites.len(), 3);
    assert_eq!(result.rewrite.rewrite_count, 3);
    assert_eq!(result.rewrite.row_count, 6);
    assert_eq!(result.rewrite.child_count, 8);
    assert_eq!(result.signature_refresh.row_count, 6);
    assert_eq!(result.signature_refresh.total_rows, 6);
    assert_eq!(
        read_u32_span(&output, byte_layout.row_eclass_ids(), 6),
        vec![10, 10, 30, 30, 50, 50]
    );
    assert_eq!(
        read_u32_span(&output, byte_layout.children(), 8),
        vec![10, 10, 10, 10, 30, 30, 30, 30]
    );

    backend
        .free_resident(resident.handle())
        .expect("Fix: CUDA e-graph resident image free failed.");
}

#[test]

fn egraph_signature_refresh_exposes_post_rewrite_structural_duplicates() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let snapshot = GpuEGraphSnapshot::build([
        (10u32, "lit", &[][..]),
        (20u32, "lit", &[][..]),
        (30u32, "add", &[10u32, 10u32][..]),
        (40u32, "add", &[10u32, 20u32][..]),
    ]);
    let image = snapshot
        .try_pack_device_image()
        .expect("Fix: valid foundation e-graph image must pack.");
    assert_ne!(
        image.row_signatures()[2],
        image.row_signatures()[3],
        "Fix: this fixture must require canonical rewrite before rows become structural duplicates."
    );
    let upload_plan = plan_cuda_egraph_device_upload_from_image(image.clone())
        .expect("Fix: packed e-graph image must produce a CUDA upload plan.");
    let byte_layout = upload_plan.byte_layout();
    let resident = backend
        .upload_egraph_device_image_plan(upload_plan)
        .expect("Fix: CUDA e-graph resident image upload failed.");

    let result = backend
        .run_egraph_structural_canonicalization_round(
            resident,
            &image,
            CudaEGraphKernelLaunchConfig {
                threads_per_block: 2,
                max_blocks_per_launch: 2,
            },
        )
        .expect("Fix: live CUDA canonicalization round must refresh row signatures after rewrite.");
    let output = backend
        .download_resident(resident.handle())
        .expect("Fix: CUDA e-graph resident image download failed after signature refresh.");
    let row_signatures = read_u32_span(&output, byte_layout.row_signatures(), 4);

    assert_eq!(
        result.discovery.unique,
        vec![Equivalence {
            left: 10,
            right: 20,
        }]
    );
    assert_eq!(result.rewrite.rewrite_count, 1);
    assert_eq!(result.signature_refresh.row_count, 4);
    assert_eq!(result.signature_refresh.total_rows, 4);
    assert_eq!(
        read_u32_span(&output, byte_layout.children(), 4),
        vec![10, 10, 10, 10]
    );
    assert_eq!(
        row_signatures[2], row_signatures[3],
        "Fix: CUDA signature refresh must expose duplicates created by canonical child rewrites."
    );

    backend
        .free_resident(resident.handle())
        .expect("Fix: CUDA e-graph resident image free failed.");
}

#[test]
fn egraph_structural_canonicalization_fixed_point_chases_chained_cuda_duplicates() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let snapshot = GpuEGraphSnapshot::build([
        (10u32, "lit", &[][..]),
        (20u32, "lit", &[][..]),
        (30u32, "add", &[10u32, 10u32][..]),
        (40u32, "add", &[10u32, 20u32][..]),
        (50u32, "mul", &[30u32, 30u32][..]),
        (60u32, "mul", &[30u32, 40u32][..]),
    ]);
    let image = snapshot
        .try_pack_device_image()
        .expect("Fix: valid foundation e-graph image must pack.");
    let upload_plan = plan_cuda_egraph_device_upload_from_image(image.clone())
        .expect("Fix: packed e-graph image must produce a CUDA upload plan.");
    let byte_layout = upload_plan.byte_layout();
    let resident = backend
        .upload_egraph_device_image_plan(upload_plan)
        .expect("Fix: CUDA e-graph resident image upload failed.");

    let result = backend
        .run_egraph_structural_canonicalization_fixed_point(
            resident,
            &image,
            CudaEGraphKernelLaunchConfig {
                threads_per_block: 2,
                max_blocks_per_launch: 2,
            },
            5,
        )
        .expect("Fix: live CUDA fixed-point canonicalization must chase chained duplicates.");
    let output = backend
        .download_resident(resident.handle())
        .expect("Fix: CUDA e-graph resident image download failed after fixed point.");
    let signature_snapshot = backend
        .download_egraph_resident_signature_snapshot(resident)
        .expect("Fix: CUDA e-graph signature-only snapshot must read refreshed signatures.");

    assert!(result.converged);
    assert_eq!(result.rounds.len(), 4);
    assert_eq!(result.total_discovered_pairs, 3);
    assert_eq!(result.total_rewrites, 3);
    assert_eq!(
        result.rounds[0].discovery.unique,
        vec![Equivalence {
            left: 10,
            right: 20,
        }]
    );
    assert_eq!(
        result.rounds[1].discovery.unique,
        vec![Equivalence {
            left: 30,
            right: 40,
        }]
    );
    assert_eq!(
        result.rounds[2].discovery.unique,
        vec![Equivalence {
            left: 50,
            right: 60,
        }]
    );
    assert!(result.rounds[3].discovery.unique.is_empty());
    assert!(result.rounds[3].union_plan.canonical_pairs.is_empty());
    assert_eq!(result.rounds[3].union_plan.canonical_rewrites.len(), 0);
    assert!(result.rounds[3].union_plan.waves.is_empty());
    assert_eq!(result.rounds[3].union_plan.total_items, 0);
    assert_eq!(result.rounds[3].union_plan.total_blocks, 0);
    assert_eq!(result.rounds[3].rewrite.rewrite_count, 0);
    assert_eq!(result.rounds[3].rewrite.launch_count, 0);
    assert_eq!(result.rounds[3].rewrite.total_items, 0);
    assert_eq!(result.rounds[3].signature_refresh.launch_count, 0);
    assert_eq!(result.rounds[3].signature_refresh.total_rows, 0);
    assert_eq!(
        read_u32_span(&output, byte_layout.row_eclass_ids(), 6),
        vec![10, 10, 30, 30, 50, 50]
    );
    assert_eq!(
        read_u32_span(&output, byte_layout.children(), 8),
        vec![10, 10, 10, 10, 30, 30, 30, 30]
    );
    assert_eq!(
        result.final_snapshot.row_eclass_ids,
        vec![10, 10, 30, 30, 50, 50]
    );
    assert_eq!(
        result.final_snapshot.children,
        vec![10, 10, 10, 10, 30, 30, 30, 30]
    );
    assert_eq!(
        signature_snapshot.row_signatures,
        result.final_snapshot.row_signatures
    );
    assert_eq!(
        signature_snapshot.child_count(),
        result.final_snapshot.child_count()
    );

    backend
        .free_resident(resident.handle())
        .expect("Fix: CUDA e-graph resident image free failed.");
}

#[test]
fn egraph_fixed_point_signature_readback_skips_full_final_snapshot() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let snapshot = GpuEGraphSnapshot::build([
        (10u32, "lit", &[][..]),
        (20u32, "lit", &[][..]),
        (30u32, "add", &[10u32, 10u32][..]),
        (40u32, "add", &[10u32, 20u32][..]),
        (50u32, "mul", &[30u32, 30u32][..]),
        (60u32, "mul", &[30u32, 40u32][..]),
    ]);
    let image = snapshot
        .try_pack_device_image()
        .expect("Fix: valid foundation e-graph image must pack.");

    for final_readback in [
        CudaEGraphFixedPointReadback::FullColumns,
        CudaEGraphFixedPointReadback::Signatures,
        CudaEGraphFixedPointReadback::None,
    ] {
        let upload_plan = plan_cuda_egraph_device_upload_from_image(image.clone())
            .expect("Fix: packed e-graph image must produce a CUDA upload plan.");
        let expected_full_bytes = expected_column_snapshot_bytes(upload_plan.byte_layout());
        let expected_signature_bytes = upload_plan.byte_layout().row_signatures().byte_len();
        let resident = backend
            .upload_egraph_device_image_plan(upload_plan)
            .expect("Fix: CUDA e-graph resident image upload failed.");

        let result = backend
            .run_egraph_structural_canonicalization_fixed_point_with_readback(
                resident,
                &image,
                CudaEGraphKernelLaunchConfig {
                    threads_per_block: 2,
                    max_blocks_per_launch: 2,
                },
                5,
                final_readback,
            )
            .expect("Fix: live CUDA fixed-point canonicalization must support policy-controlled final readback.");

        assert!(result.converged);
        assert_eq!(result.total_discovered_pairs, 3);
        assert_eq!(result.total_rewrites, 3);
        assert_eq!(result.final_readback, final_readback);
        assert_eq!(result.final_full_readback_bytes, expected_full_bytes);
        assert_eq!(
            result.final_signature_snapshot_bytes,
            expected_signature_bytes
        );
        match final_readback {
            CudaEGraphFixedPointReadback::FullColumns => {
                assert_eq!(result.final_additional_readback_bytes, 0);
                assert_eq!(result.avoided_final_readback_bytes, expected_full_bytes);
                assert!(
                    result.final_snapshot.is_some(),
                    "Fix: full-column fixed-point readback must return final resident columns."
                );
                assert!(
                    result.final_signature_snapshot.is_some(),
                    "Fix: full-column fixed-point readback must expose a derivable signature snapshot."
                );
            }
            CudaEGraphFixedPointReadback::Signatures => {
                let device_signature_snapshot = backend
                    .download_egraph_resident_signature_snapshot(resident)
                    .expect(
                        "Fix: CUDA e-graph signature-only snapshot must read refreshed signatures.",
                    );
                assert_eq!(result.final_additional_readback_bytes, 0);
                assert_eq!(result.avoided_final_readback_bytes, expected_full_bytes);
                assert!(
                    result.final_snapshot.is_none(),
                    "Fix: signature-only fixed-point readback must not force full resident column download."
                );
                assert_eq!(
                    result
                        .final_signature_snapshot
                        .as_ref()
                        .expect("Fix: signature-only fixed-point readback must return signatures."),
                    &device_signature_snapshot
                );
            }
            CudaEGraphFixedPointReadback::None => {
                assert_eq!(result.final_additional_readback_bytes, 0);
                assert_eq!(result.avoided_final_readback_bytes, expected_full_bytes);
                assert!(
                    result.final_snapshot.is_none(),
                    "Fix: no-readback fixed-point policy must not return full resident columns."
                );
                assert!(
                    result.final_signature_snapshot.is_none(),
                    "Fix: no-readback fixed-point policy must not return a signature snapshot."
                );
            }
        }

        backend
            .free_resident(resident.handle())
            .expect("Fix: CUDA e-graph resident image free failed.");
    }
}

#[test]
fn egraph_fixed_point_signature_readback_after_max_rounds_reads_only_signatures() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let snapshot = GpuEGraphSnapshot::build([
        (10u32, "lit", &[][..]),
        (20u32, "lit", &[][..]),
        (30u32, "add", &[10u32, 10u32][..]),
        (40u32, "add", &[10u32, 20u32][..]),
    ]);
    let image = snapshot
        .try_pack_device_image()
        .expect("Fix: valid foundation e-graph image must pack.");
    let upload_plan = plan_cuda_egraph_device_upload_from_image(image.clone())
        .expect("Fix: packed e-graph image must produce a CUDA upload plan.");
    let expected_full_bytes = expected_column_snapshot_bytes(upload_plan.byte_layout());
    let expected_signature_bytes = upload_plan.byte_layout().row_signatures().byte_len();
    let resident = backend
        .upload_egraph_device_image_plan(upload_plan)
        .expect("Fix: CUDA e-graph resident image upload failed.");

    let result = backend
        .run_egraph_structural_canonicalization_fixed_point_with_readback(
            resident,
            &image,
            CudaEGraphKernelLaunchConfig {
                threads_per_block: 2,
                max_blocks_per_launch: 2,
            },
            1,
            CudaEGraphFixedPointReadback::Signatures,
        )
        .expect("Fix: signature-only fixed-point readback after max rounds must use ranged CUDA readback.");
    let device_signature_snapshot = backend
        .download_egraph_resident_signature_snapshot(resident)
        .expect("Fix: CUDA e-graph signature-only snapshot must read refreshed signatures.");

    assert!(!result.converged);
    assert_eq!(result.rounds.len(), 1);
    assert_eq!(result.total_discovered_pairs, 1);
    assert_eq!(result.total_rewrites, 1);
    assert!(result.final_snapshot.is_none());
    assert_eq!(result.final_full_readback_bytes, expected_full_bytes);
    assert_eq!(
        result.final_signature_snapshot_bytes,
        expected_signature_bytes
    );
    assert_eq!(result.final_additional_readback_bytes, 0);
    assert_eq!(result.avoided_final_readback_bytes, expected_full_bytes);
    assert_eq!(
        result
            .final_signature_snapshot
            .as_ref()
            .expect("Fix: signature-only fixed-point result must include refreshed signatures."),
        &device_signature_snapshot
    );

    backend
        .free_resident(resident.handle())
        .expect("Fix: CUDA e-graph resident image free failed.");
}

fn read_u32_span(bytes: &[u8], span: CudaEGraphDeviceByteSpan, count: usize) -> Vec<u32> {
    (0..count)
        .map(|index| {
            let offset = span.offset() + (index * 4);
            let mut raw = [0u8; 4];
            raw.copy_from_slice(&bytes[offset..offset + 4]);
            u32::from_le_bytes(raw)
        })
        .collect()
}
