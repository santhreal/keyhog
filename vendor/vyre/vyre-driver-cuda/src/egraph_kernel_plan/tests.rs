use super::*;
use crate::CudaEGraphDeviceKernelView;
use vyre_foundation::optimizer::eqsat_gpu::{GpuEGraphDeviceImage, Equivalence};
use crate::egraph_kernel_plan::args::{EGraphStructuralKernelArgs, EGraphCanonicalRewriteKernelArgs};
use crate::plan_cuda_egraph_device_upload;
use vyre_foundation::optimizer::eqsat_gpu::GpuEGraphSnapshot;

fn synthetic_view(rows: usize, children: usize, groups: usize) -> CudaEGraphDeviceKernelView {
    assert!(groups <= rows);
    assert!(children <= rows.saturating_mul(2));
    let mut child_storage = Vec::new();
    let mut row_specs = Vec::with_capacity(rows);
    for row in 0..rows {
        let start = child_storage.len();
        if child_storage.len() < children && row > 0 {
            child_storage.push((row - 1) as u32);
        }
        if child_storage.len() < children && row > 1 {
            child_storage.push((row / 2) as u32);
        }
        let eclass = if groups == 0 { row } else { row % groups };
        row_specs.push((
            eclass as u32,
            if row & 1 == 0 { "lit" } else { "add" },
            start,
            child_storage.len() - start,
        ));
    }
    while child_storage.len() < children {
        child_storage.push(0);
        let last = row_specs
            .last_mut()
            .expect("Fix: synthetic child-only view requires at least one row");
        last.3 += 1;
    }
    let build_rows = row_specs
        .iter()
        .map(|&(class, op, start, len)| (class, op, &child_storage[start..start + len]))
        .collect::<Vec<_>>();
    let snapshot = GpuEGraphSnapshot::build(build_rows);
    let plan = plan_cuda_egraph_device_upload(&snapshot).expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - synthetic plan must pack");
    CudaEGraphDeviceKernelView::from_checked_parts(0x1000, plan.byte_len(), plan.byte_layout())
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - synthetic view must be valid")
}

fn view_for_image(image: &GpuEGraphDeviceImage) -> CudaEGraphDeviceKernelView {
    let plan = crate::plan_cuda_egraph_device_upload_from_image(image.clone())
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - packed egraph image must have a CUDA upload plan");
    CudaEGraphDeviceKernelView::from_checked_parts(0x4000, plan.byte_len(), plan.byte_layout())
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - upload plan must resolve to a checked kernel view")
}

#[test]
fn planner_emits_passes_in_row_child_group_order() {
    let view = synthetic_view(3, 2, 2);
    let plan = plan_cuda_egraph_kernel_work(
        view,
        CudaEGraphKernelLaunchConfig {
            threads_per_block: 4,
            max_blocks_per_launch: 2,
        },
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - valid egraph kernel plan");

    assert_eq!(plan.waves.len(), 3);
    assert_eq!(plan.waves[0].pass, CudaEGraphKernelPass::RowScan);
    assert_eq!(plan.waves[0].item_count, 3);
    assert_eq!(plan.waves[0].blocks, 1);
    assert_eq!(plan.waves[1].pass, CudaEGraphKernelPass::ChildEdgeScan);
    assert_eq!(plan.waves[1].item_count, 2);
    assert_eq!(plan.waves[2].pass, CudaEGraphKernelPass::EclassGroupScan);
    assert_eq!(plan.waves[2].item_count, 2);
    assert_eq!(plan.total_items, 7);
    assert_eq!(plan.total_blocks, 3);
}

#[test]
fn planner_splits_large_passes_into_bounded_waves() {
    let view = synthetic_view(19, 0, 0);
    let plan = plan_cuda_egraph_kernel_work(
        view,
        CudaEGraphKernelLaunchConfig {
            threads_per_block: 4,
            max_blocks_per_launch: 2,
        },
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - valid split egraph kernel plan");

    let items = plan
        .waves
        .iter()
        .map(|wave| (wave.first_item, wave.item_count, wave.blocks))
        .collect::<Vec<_>>();
    assert_eq!(
        items,
        vec![
            (0, 8, 2),
            (8, 8, 2),
            (16, 3, 1),
            (0, 8, 2),
            (8, 8, 2),
            (16, 3, 1),
        ]
    );
    assert_eq!(plan.total_items, 38);
    assert_eq!(plan.total_blocks, 10);
}

#[test]
fn planner_rejects_zero_launch_dimensions() {
    let view = synthetic_view(1, 0, 0);
    assert_eq!(
        plan_cuda_egraph_kernel_work(
            view,
            CudaEGraphKernelLaunchConfig {
                threads_per_block: 0,
                max_blocks_per_launch: 1,
            },
        )
        .expect_err("zero threads must be rejected"),
        CudaEGraphKernelPlanError::ZeroThreadsPerBlock
    );
    assert_eq!(
        plan_cuda_egraph_kernel_work(
            view,
            CudaEGraphKernelLaunchConfig {
                threads_per_block: 1,
                max_blocks_per_launch: 0,
            },
        )
        .expect_err("zero max blocks must be rejected"),
        CudaEGraphKernelPlanError::ZeroMaxBlocksPerLaunch
    );
}

#[test]
fn signature_bucket_planner_groups_only_candidate_duplicate_rows() {
    let snapshot = GpuEGraphSnapshot::build([
        (0u32, "lit", &[][..]),
        (1u32, "lit", &[][..]),
        (2u32, "add", &[0u32, 1u32][..]),
        (3u32, "add", &[0u32, 1u32][..]),
        (4u32, "add", &[1u32, 0u32][..]),
        (5u32, "mul", &[0u32, 1u32][..]),
    ]);
    let image = snapshot
        .try_pack_device_image()
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - valid egraph image must pack");
    let plan = plan_cuda_egraph_signature_buckets(
        &image,
        view_for_image(&image),
        CudaEGraphKernelLaunchConfig {
            threads_per_block: 8,
            max_blocks_per_launch: 1,
        },
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - signature bucket plan must build");

    let grouped_rows = plan
        .buckets
        .iter()
        .map(|bucket| {
            let start = bucket.first_bucket_row as usize;
            let end = start + bucket.row_count as usize;
            plan.bucket_rows[start..end].to_vec()
        })
        .collect::<Vec<_>>();

    assert_eq!(grouped_rows.len(), 2);
    assert!(grouped_rows.contains(&vec![0, 1]));
    assert!(grouped_rows.contains(&vec![2, 3]));
    assert_eq!(plan.candidate_pair_count, 2);
    assert_eq!(plan.pair_waves.len(), 2);
    assert!(plan
        .pair_waves
        .iter()
        .all(|wave| wave.pair_count == 1 && wave.blocks == 1));
}

#[test]
fn consuming_launch_artifact_matches_borrowed_artifact_without_plan_clone_contract() {
    let snapshot = GpuEGraphSnapshot::build([
        (0u32, "lit", &[][..]),
        (1u32, "lit", &[][..]),
        (2u32, "add", &[0u32, 1u32][..]),
        (3u32, "add", &[0u32, 1u32][..]),
        (4u32, "mul", &[0u32, 1u32][..]),
        (5u32, "mul", &[0u32, 1u32][..]),
    ]);
    let image = snapshot
        .try_pack_device_image()
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - valid egraph image must pack");
    let plan = plan_cuda_egraph_signature_buckets(
        &image,
        view_for_image(&image),
        CudaEGraphKernelLaunchConfig {
            threads_per_block: 8,
            max_blocks_per_launch: 1,
        },
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - signature bucket plan must build");

    let borrowed = plan_cuda_egraph_structural_equivalence_launch_artifact(&plan)
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - borrowed launch artifact must build");
    let consumed = plan_cuda_egraph_structural_equivalence_launch_artifact_from_plan(plan)
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - consuming launch artifact must build");

    assert_eq!(consumed, borrowed);
}

#[test]
fn resident_snapshot_try_constructors_match_infallible_snapshots() {
    let snapshot = GpuEGraphSnapshot::build([
        (0u32, "lit", &[][..]),
        (1u32, "lit", &[][..]),
        (2u32, "add", &[0u32, 1u32][..]),
        (3u32, "mul", &[1u32, 2u32][..]),
    ]);
    let image = snapshot
        .try_pack_device_image()
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - valid egraph image must pack");

    let full = CudaEGraphResidentColumnSnapshot::try_from_device_image(&image)
        .expect("Fix: caller must pre-size buffers; use fallible reserve or return ResourceExhausted - fallible full snapshot should reserve");
    let infallible_full = CudaEGraphResidentColumnSnapshot::from_device_image(&image);
    assert_eq!(full, infallible_full);

    let signatures = CudaEGraphResidentSignatureSnapshot::try_from_device_image(&image)
        .expect("Fix: caller must pre-size buffers; use fallible reserve or return ResourceExhausted - fallible signature snapshot should reserve");
    let from_full = CudaEGraphResidentSignatureSnapshot::try_from_column_snapshot(&full)
        .expect("Fix: caller must pre-size buffers; use fallible reserve or return ResourceExhausted - fallible signature snapshot from full columns should reserve");
    assert_eq!(signatures, from_full);
    assert_eq!(
        signatures,
        CudaEGraphResidentSignatureSnapshot::from_device_image(&image)
    );
}

#[test]
fn resident_signature_bucket_planning_does_not_clone_full_signature_snapshot() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/egraph_kernel_plan.rs"
    ))
    .expect("Fix: CUDA egraph kernel planner source must be readable");
    let forbidden_snapshot_clone = [
        "let signature_snapshot = CudaEGraphResidentSignatureSnapshot",
        "::from_column_snapshot(snapshot)",
    ]
    .concat();
    assert!(
            !source.contains(&forbidden_snapshot_clone),
            "Fix: resident CUDA e-graph bucket planning must borrow the resident signature column instead of cloning it into a temporary snapshot."
        );
    assert!(
            source.contains("plan_cuda_egraph_structural_equivalence_launch_artifact_from_plan"),
            "Fix: CUDA e-graph release execution must use the consuming launch-artifact path so bucket rows and pair waves move into the artifact."
        );
}

#[test]
fn union_compaction_uses_reserved_eclass_index_for_generated_large_components() {
    let edge_count = 1024_u32;
    let mut equivalences = Vec::new();
    equivalences.reserve((edge_count as usize) * 3);
    let mut expected_self_pairs = 0_u64;
    for edge in 0..edge_count {
        equivalences.push(Equivalence {
            left: edge + 1,
            right: edge,
        });
        equivalences.push(Equivalence {
            left: edge,
            right: edge + 1,
        });
        if edge % 7 == 0 {
            expected_self_pairs += 1;
            equivalences.push(Equivalence {
                left: edge,
                right: edge,
            });
        }
    }

    let plan = plan_cuda_egraph_union_compaction(
        &equivalences,
        CudaEGraphKernelLaunchConfig {
            threads_per_block: 128,
            max_blocks_per_launch: 16,
        },
    )
    .expect("Fix: generated CUDA e-graph union compaction plan should fit");

    assert_eq!(plan.canonical_pairs.len(), edge_count as usize);
    assert_eq!(plan.duplicate_pair_count, edge_count as u64);
    assert_eq!(plan.ignored_self_pair_count, expected_self_pairs);
    assert_eq!(plan.affected_eclasses.len(), edge_count as usize + 1);
    assert_eq!(plan.canonical_rewrites.len(), edge_count as usize);
    assert!(plan
        .canonical_rewrites
        .iter()
        .all(|rewrite| rewrite.representative == 0 && rewrite.eclass_id != 0));

    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/egraph_kernel_plan.rs"
    ))
    .expect("Fix: CUDA egraph kernel planner source must be readable");
    let production = source
        .split("#[cfg(test)]")
        .next()
        .expect("Fix: production egraph planner source must precede tests");
    let old_left_lookup = ["affected_eclasses.", "binary_search(&pair.left)"].concat();
    let old_right_lookup = ["affected_eclasses.", "binary_search(&pair.right)"].concat();
    assert!(
            production.contains("FxHashMap::<u32, usize>")
                && production.contains("let mut eclass_indices")
                && production.contains(".get(&pair.left)")
                && production.contains(".get(&pair.right)")
                && !production.contains(&old_left_lookup)
                && !production.contains(&old_right_lookup),
            "Fix: CUDA e-graph union compaction must build one reserved e-class index table instead of doing binary-search lookup for every emitted merge edge."
        );
}

#[test]
fn egraph_planner_uses_shared_monotonic_sort_fast_path() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/egraph_kernel_plan.rs"
    ))
    .expect("Fix: CUDA egraph kernel planner source must be readable");
    let production = source
        .split("#[cfg(test)]")
        .next()
        .expect("Fix: CUDA egraph kernel planner production source must precede tests");
    let readback_source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/egraph_readback.rs"
    ))
    .expect("Fix: CUDA egraph readback source must be readable");
    let readback_production = readback_source
        .split("#[cfg(test)]")
        .next()
        .expect("Fix: CUDA egraph readback production source must precede tests");

    assert!(
            production.contains(
                "use crate::backend::ordering::{sort_unstable_by_key_if_needed, sort_unstable_if_needed};",
            )
                && production.contains("sort_unstable_by_key_if_needed(&mut sorted_rows")
                && production.contains("sort_unstable_by_key_if_needed(&mut canonical_pairs")
                && readback_production.contains("sort_unstable_by_key_if_needed(&mut unique")
                && production.contains("sort_unstable_if_needed(&mut equivalence_keys)")
                && production.contains("sort_unstable_if_needed(&mut affected_eclasses)"),
            "Fix: CUDA e-graph planning/readback must reuse the shared monotonic sort fast path."
        );
    assert!(
            !production.contains(".sort_unstable_by_key("),
            "Fix: CUDA e-graph release paths must not unconditionally sort already monotonic rows or equivalence pairs."
        );
    assert!(
            !readback_production.contains(".sort_unstable_by_key("),
            "Fix: CUDA e-graph readback must not unconditionally sort already monotonic equivalence pairs."
        );
    assert!(
            !production.contains(".sort_unstable();"),
            "Fix: CUDA e-graph release paths must not unconditionally sort already monotonic primitive queues."
        );
}

#[test]
fn egraph_planner_uses_shared_cuda_numeric_policy_for_host_boundary_counts() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/egraph_kernel_plan.rs"
    ))
    .expect("Fix: CUDA egraph kernel planner source must be readable");
    let production = source
        .split("#[cfg(test)]")
        .next()
        .expect("Fix: CUDA egraph kernel planner production source must precede tests");

    assert!(
            production.contains("use crate::numeric::CUDA_NUMERIC;")
                && production.contains(".usize_to_u64(value, field)"),
            "Fix: CUDA e-graph host/count boundary conversions must use the shared backend numeric policy."
        );
    assert!(
        !production.contains("u64::try_from(value)"),
        "Fix: CUDA e-graph planner must not reintroduce local usize-to-u64 conversion policy."
    );
}

#[test]
fn egraph_kernel_argument_tables_reuse_wave_staging() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/egraph_kernel_plan.rs"
    ))
    .expect("Fix: CUDA egraph kernel planner source must be readable");
    let args_source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/egraph_kernel_plan/args.rs"
    ))
    .expect("Fix: CUDA egraph kernel argument source must be readable");

    assert!(
            args_source.contains("fn write_kernel_args_into(")
                && args_source.contains("fn reserve_egraph_kernel_args(")
                && source.matches("let mut kernel_args = SmallVec::<[*mut std::ffi::c_void; 8]>::new();").count() >= 3,
            "Fix: CUDA e-graph multi-wave kernels must reuse caller-owned argument tables across waves."
        );
    let forbidden_as_kernel_args = ["fn as_", "kernel_args("].concat();
    let forbidden_smallvec_macro = ["smallvec::", "smallvec!["].concat();
    assert!(
            !args_source.contains(&forbidden_as_kernel_args)
                && !args_source.contains(&forbidden_smallvec_macro),
            "Fix: CUDA e-graph wave launch code must not allocate a fresh SmallVec argument table per wave."
        );
}

#[test]
fn structural_equivalence_readback_skips_bucket_metadata() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/egraph_kernel_plan.rs"
    ))
    .expect("Fix: CUDA egraph kernel planner source must be readable");
    let forbidden_full_scratch_download = ["self.download_", "resident(scratch.handle)"].concat();

    assert!(
            source.contains("download_structural_equivalence_output_ranges(self, &scratch)")
                && source.contains("download_resident_ranges_into(&ranges, &mut outputs)"),
            "Fix: CUDA e-graph structural-equivalence readback must use ranged fused D2H for output counter + output pairs only."
        );
    assert!(
            !source.contains(&forbidden_full_scratch_download),
            "Fix: CUDA e-graph structural-equivalence readback must not download bucket metadata after launch."
        );
}

#[test]
fn egraph_warm_helpers_reuse_resolved_cuda_function_for_launch() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/egraph_kernel_plan.rs"
    ))
    .expect("Fix: CUDA egraph kernel planner source must be readable");
    let warm_lookup = concat!("module_for_ptx", "_with_key(&kernel.source, module_key)");
    let stale_inner_lookup = concat!("module_for_ptx", "_with_key(ptx_src, module_key)");
    let stale_inner_param = concat!(
        "ptx_src: &str,",
        "\n        module_key: crate::backend::ModuleCacheKey"
    );

    assert_eq!(
        source.matches(warm_lookup).count(),
        3,
        "Fix: each e-graph warm helper should resolve its CUDA function exactly once."
    );
    assert!(
        source.matches("Ok((kernel, function))").count() >= 3
            && source.matches("cudarc::driver::sys::CUfunction").count() >= 6,
        "Fix: e-graph warm helpers must return the resolved CUfunction to run-inner launch paths."
    );
    assert!(
        !source.contains(stale_inner_lookup) && !source.contains(&stale_inner_param),
        "Fix: e-graph run-inner paths must not repeat module-cache lookups after warm resolution."
    );
}

#[test]

fn egraph_kernel_args_into_reuses_capacity_and_preserves_abi_order() {
    let mut table = smallvec::SmallVec::<[*mut std::ffi::c_void; 8]>::new();
    let mut structural = EGraphStructuralKernelArgs {
        row_eclass_ids_ptr: 1,
        row_language_op_ids_ptr: 2,
        row_children_offsets_ptr: 3,
        row_children_lens_ptr: 4,
        row_signatures_ptr: 5,
        children_ptr: 6,
        bucket_words_ptr: 7,
        bucket_rows_ptr: 8,
        output_pairs_ptr: 9,
        output_count_ptr: 10,
        bucket_index: 11,
        first_pair: 12,
        pair_count: 13,
    };

    structural
        .write_kernel_args_into(&mut table)
        .expect("Fix: structural e-graph kernel args should build");
    let capacity = table.capacity();
    assert_eq!(table.len(), 13);
    assert_eq!(
        table[0],
        &mut structural.row_eclass_ids_ptr as *mut _ as *mut std::ffi::c_void
    );
    assert_eq!(
        table[12],
        &mut structural.pair_count as *mut _ as *mut std::ffi::c_void
    );

    let mut rewrite = EGraphCanonicalRewriteKernelArgs {
        row_eclass_ids_ptr: 21,
        children_ptr: 22,
        rewrite_words_ptr: 23,
        rewrite_count: 24,
        row_count: 25,
        child_count: 26,
        first_item: 27,
    };
    rewrite
        .write_kernel_args_into(&mut table)
        .expect("Fix: canonical rewrite e-graph kernel args should reuse table");
    assert_eq!(table.capacity(), capacity);
    assert_eq!(table.len(), 7);
    assert_eq!(
        table[0],
        &mut rewrite.row_eclass_ids_ptr as *mut _ as *mut std::ffi::c_void
    );
    assert_eq!(
        table[6],
        &mut rewrite.first_item as *mut _ as *mut std::ffi::c_void
    );
}

#[test]
fn signature_bucket_planner_splits_large_candidate_bucket() {
    let snapshot = GpuEGraphSnapshot::build([
        (0u32, "lit", &[][..]),
        (1u32, "lit", &[][..]),
        (2u32, "lit", &[][..]),
        (3u32, "lit", &[][..]),
        (4u32, "lit", &[][..]),
    ]);
    let image = snapshot
        .try_pack_device_image()
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - valid egraph image must pack");
    let plan = plan_cuda_egraph_signature_buckets(
        &image,
        view_for_image(&image),
        CudaEGraphKernelLaunchConfig {
            threads_per_block: 2,
            max_blocks_per_launch: 2,
        },
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - signature bucket plan must build");

    assert_eq!(plan.buckets.len(), 1);
    assert_eq!(plan.buckets[0].row_count, 5);
    assert_eq!(plan.candidate_pair_count, 10);
    assert_eq!(plan.bucket_rows, vec![0, 1, 2, 3, 4]);
    assert_eq!(
        plan.pair_waves,
        vec![
            CudaEGraphSignaturePairWave {
                bucket_index: 0,
                first_pair: 0,
                pair_count: 4,
                blocks: 2,
                threads_per_block: 2,
            },
            CudaEGraphSignaturePairWave {
                bucket_index: 0,
                first_pair: 4,
                pair_count: 4,
                blocks: 2,
                threads_per_block: 2,
            },
            CudaEGraphSignaturePairWave {
                bucket_index: 0,
                first_pair: 8,
                pair_count: 2,
                blocks: 1,
                threads_per_block: 2,
            },
        ]
    );
    assert_eq!(plan.total_blocks, 5);
}

#[test]
fn signature_pair_ordinals_decode_to_row_pairs_without_materialized_pairs() {
    let snapshot = GpuEGraphSnapshot::build([
        (0u32, "lit", &[][..]),
        (1u32, "lit", &[][..]),
        (2u32, "lit", &[][..]),
        (3u32, "lit", &[][..]),
        (4u32, "lit", &[][..]),
    ]);
    let image = snapshot
        .try_pack_device_image()
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - valid egraph image must pack");
    let plan = plan_cuda_egraph_signature_buckets(
        &image,
        view_for_image(&image),
        CudaEGraphKernelLaunchConfig {
            threads_per_block: 4,
            max_blocks_per_launch: 1,
        },
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - signature bucket plan must build");

    let decoded = (0..plan.candidate_pair_count)
        .map(|ordinal| cuda_egraph_signature_pair_rows(&plan, 0, ordinal).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        decoded,
        vec![
            (0, 1),
            (0, 2),
            (0, 3),
            (0, 4),
            (1, 2),
            (1, 3),
            (1, 4),
            (2, 3),
            (2, 4),
            (3, 4),
        ]
    );
}

#[test]
fn signature_pair_decoder_rejects_out_of_bounds_ordinals() {
    let snapshot = GpuEGraphSnapshot::build([(0u32, "lit", &[][..]), (1u32, "lit", &[][..])]);
    let image = snapshot
        .try_pack_device_image()
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - valid egraph image must pack");
    let plan = plan_cuda_egraph_signature_buckets(
        &image,
        view_for_image(&image),
        CudaEGraphKernelLaunchConfig::default(),
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - signature bucket plan must build");

    assert_eq!(
        cuda_egraph_signature_pair_rows(&plan, 0, 1)
            .expect_err("one two-row bucket has exactly one pair"),
        CudaEGraphKernelPlanError::SignaturePairOrdinalOutOfBounds {
            bucket_index: 0,
            pair_ordinal: 1,
            candidate_pair_count: 1,
        }
    );
    assert_eq!(
        cuda_egraph_signature_pair_rows(&plan, 7, 0).expect_err("missing bucket must be rejected"),
        CudaEGraphKernelPlanError::SignaturePairOrdinalOutOfBounds {
            bucket_index: 7,
            pair_ordinal: 0,
            candidate_pair_count: 0,
        }
    );
}

#[test]
fn signature_pair_decoder_rejects_malformed_bucket_row_ranges() {
    let snapshot = GpuEGraphSnapshot::build([(0u32, "lit", &[][..]), (1u32, "lit", &[][..])]);
    let image = snapshot
        .try_pack_device_image()
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - valid egraph image must pack");
    let plan = CudaEGraphSignatureBucketPlan {
        view: view_for_image(&image),
        buckets: vec![CudaEGraphSignatureBucket {
            signature: image.row_signatures()[0],
            first_bucket_row: 1,
            row_count: 2,
            candidate_pair_count: 1,
        }],
        bucket_rows: vec![0, 1],
        pair_waves: Vec::new(),
        candidate_pair_count: 1,
        total_blocks: 0,
    };

    assert_eq!(
        cuda_egraph_signature_pair_rows(&plan, 0, 0)
            .expect_err("malformed bucket row range must be rejected"),
        CudaEGraphKernelPlanError::SignatureBucketRowsOutOfBounds {
            bucket_index: 0,
            first_bucket_row: 1,
            row_count: 2,
            bucket_rows_len: 2,
        }
    );
}

#[test]
fn structural_equivalence_plan_emits_unique_exact_eclass_merges() {
    let snapshot = GpuEGraphSnapshot::build([
        (10u32, "lit", &[][..]),
        (20u32, "lit", &[][..]),
        (30u32, "add", &[10u32, 20u32][..]),
        (40u32, "add", &[10u32, 20u32][..]),
        (50u32, "add", &[20u32, 10u32][..]),
        (30u32, "add", &[10u32, 20u32][..]),
    ]);
    let image = snapshot
        .try_pack_device_image()
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - valid egraph image must pack");

    let plan = plan_cuda_egraph_structural_equivalences(
        &image,
        view_for_image(&image),
        CudaEGraphKernelLaunchConfig {
            threads_per_block: 8,
            max_blocks_per_launch: 1,
        },
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - structural equivalence plan must build");

    assert_eq!(
        plan.equivalences,
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
    assert_eq!(plan.exact_pair_count, 4);
    assert_eq!(plan.redundant_pair_count, 1);
    assert_eq!(plan.rejected_candidate_pair_count, 0);
    assert_eq!(plan.equivalence_output_words, 4);
}

#[test]
fn structural_equivalence_collection_filters_signature_collision_bucket() {
    let snapshot = GpuEGraphSnapshot::build([(0u32, "lit", &[][..]), (1u32, "add", &[0u32][..])]);
    let image = snapshot
        .try_pack_device_image()
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - valid egraph image must pack");
    let signature_plan = CudaEGraphSignatureBucketPlan {
        view: view_for_image(&image),
        buckets: vec![CudaEGraphSignatureBucket {
            signature: image.row_signatures()[0],
            first_bucket_row: 0,
            row_count: 2,
            candidate_pair_count: 1,
        }],
        bucket_rows: vec![0, 1],
        pair_waves: vec![CudaEGraphSignaturePairWave {
            bucket_index: 0,
            first_pair: 0,
            pair_count: 1,
            blocks: 1,
            threads_per_block: 1,
        }],
        candidate_pair_count: 1,
        total_blocks: 1,
    };

    let plan = collect_cuda_egraph_structural_equivalences(&image, signature_plan)
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - collision-safe structural collection must complete");

    assert!(plan.equivalences.is_empty());
    assert_eq!(plan.exact_pair_count, 0);
    assert_eq!(plan.redundant_pair_count, 0);
    assert_eq!(plan.rejected_candidate_pair_count, 1);
    assert_eq!(plan.equivalence_output_words, 0);
}

#[test]
fn signature_bucket_device_image_packs_fixed_width_records() {
    let snapshot = GpuEGraphSnapshot::build([
        (0u32, "lit", &[][..]),
        (1u32, "lit", &[][..]),
        (2u32, "lit", &[][..]),
    ]);
    let image = snapshot
        .try_pack_device_image()
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - valid egraph image must pack");
    let signature_plan = plan_cuda_egraph_signature_buckets(
        &image,
        view_for_image(&image),
        CudaEGraphKernelLaunchConfig {
            threads_per_block: 2,
            max_blocks_per_launch: 1,
        },
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - signature bucket plan must build");

    let device_image = pack_cuda_egraph_signature_bucket_device_image(&signature_plan)
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - signature bucket device image must pack");

    assert_eq!(device_image.bucket_count, 1);
    assert_eq!(device_image.bucket_record_words, 5);
    assert_eq!(device_image.bucket_rows, vec![0, 1, 2]);
    assert_eq!(
        device_image.bucket_words,
        vec![image.row_signatures()[0], 0, 3, 3, 0,]
    );
    assert_eq!(device_image.candidate_pair_count, 3);
}

#[test]
fn structural_equivalence_launch_artifact_sizes_worst_case_output() {
    let snapshot = GpuEGraphSnapshot::build([
        (0u32, "lit", &[][..]),
        (1u32, "lit", &[][..]),
        (2u32, "lit", &[][..]),
        (3u32, "lit", &[][..]),
    ]);
    let image = snapshot
        .try_pack_device_image()
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - valid egraph image must pack");
    let signature_plan = plan_cuda_egraph_signature_buckets(
        &image,
        view_for_image(&image),
        CudaEGraphKernelLaunchConfig {
            threads_per_block: 4,
            max_blocks_per_launch: 1,
        },
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - signature bucket plan must build");

    let artifact = plan_cuda_egraph_structural_equivalence_launch_artifact(&signature_plan)
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - structural equivalence launch artifact must build");

    assert_eq!(artifact.bucket_image.bucket_count, 1);
    assert_eq!(artifact.output.max_equivalences, 6);
    assert_eq!(artifact.output.output_pair_words, 12);
    assert_eq!(artifact.output.output_pair_bytes, 48);
    assert_eq!(artifact.output.output_counter_words, 2);
    assert_eq!(artifact.output.output_counter_bytes, 8);
    assert_eq!(artifact.pair_waves.len(), 2);
}

#[test]
fn structural_equivalence_kernel_ptx_pins_entry_abi_and_target() {
    let kernel = cuda_egraph_structural_equivalence_kernel_ptx(90)
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - valid CUDA egraph structural-equivalence PTX must emit");

    assert_eq!(kernel.target_sm, 90);
    assert_eq!(kernel.ptx_version, "8.0");
    assert_eq!(
        kernel.entry_name,
        CUDA_EGRAPH_STRUCTURAL_EQUIVALENCE_KERNEL_ENTRY
    );
    assert_eq!(
        kernel.parameter_count,
        CUDA_EGRAPH_STRUCTURAL_EQUIVALENCE_KERNEL_PARAM_COUNT
    );
    assert_eq!(
        kernel.bucket_record_words,
        CUDA_EGRAPH_SIGNATURE_BUCKET_RECORD_WORDS
    );
    assert!(kernel.source.contains(".version 8.0"));
    assert!(kernel.source.contains(".target sm_90"));
    assert!(kernel.source.contains(".visible .entry main("));
    for param in [
        "row_eclass_ids_ptr",
        "row_language_op_ids_ptr",
        "row_children_offsets_ptr",
        "row_children_lens_ptr",
        "row_signatures_ptr",
        "children_ptr",
        "bucket_words_ptr",
        "bucket_rows_ptr",
        "output_pairs_ptr",
        "output_count_ptr",
        "bucket_index",
        "first_pair",
        "pair_count",
    ] {
        assert!(
            kernel.source.contains(param),
            "Fix: structural-equivalence PTX ABI must include parameter `{param}`."
        );
    }
}

#[test]
fn structural_equivalence_kernel_ptx_contains_non_stub_exact_compare_body() {
    let kernel = cuda_egraph_structural_equivalence_kernel_ptx(120)
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - valid CUDA egraph structural-equivalence PTX must emit");

    assert_eq!(kernel.ptx_version, "8.7");
    for required in [
        "PAIR_DECODE_LOOP:",
        "CHILD_LOOP:",
        "ld.global.u32",
        "setp.ne.u32",
        "atom.global.add.u64",
        "st.global.u32",
        "selp.u32",
    ] {
        assert!(
                kernel.source.contains(required),
                "Fix: structural-equivalence PTX must contain real exact-compare/output logic `{required}`."
            );
    }
    let ret_index = kernel
        .source
        .find("ret;")
        .expect("Fix: structural-equivalence PTX must return.");
    let first_load_index = kernel
        .source
        .find("ld.global.u32")
        .expect("Fix: structural-equivalence PTX must load packed columns before returning.");
    assert!(
        first_load_index < ret_index,
        "Fix: structural-equivalence PTX must not be a return-only stub."
    );
}

#[test]
fn structural_equivalence_kernel_ptx_rejects_invalid_sm_target() {
    assert_eq!(
        cuda_egraph_structural_equivalence_kernel_ptx(0)
            .expect_err("sm_0 is not a valid CUDA PTX target"),
        CudaEGraphKernelPlanError::InvalidPtxTarget { target_sm: 0 }
    );
}

#[test]

fn signature_bucket_planner_rejects_mismatched_image_and_view() {
    let image = GpuEGraphSnapshot::build([(0u32, "lit", &[][..]), (1u32, "lit", &[][..])])
        .try_pack_device_image()
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - valid egraph image must pack");
    let mismatched_view = synthetic_view(1, 0, 1);

    assert_eq!(
        plan_cuda_egraph_signature_buckets(
            &image,
            mismatched_view,
            CudaEGraphKernelLaunchConfig::default(),
        )
        .expect_err("image/view row mismatch must be rejected"),
        CudaEGraphKernelPlanError::ImageViewMismatch {
            field: "row count",
            image: 2,
            view: 1,
        }
    );
}

