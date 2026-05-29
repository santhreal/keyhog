use super::super::*;




    #[test]
    fn persistent_bfs_reaches_closure() {
        let (frontier, changed) = cpu_ref(
            4,
            &[0, 2, 3, 4, 4],
            &[1, 2, 3, 3],
            &[1, 1, 1, 1],
            &[0b0001],
            0xFFFF_FFFF,
            4,
        );
        assert_eq!(frontier, vec![0b1111]);
        assert_eq!(changed, 1);
    }

    #[test]
    fn cpu_ref_into_reuses_frontier_storage() {
        let mut frontier = Vec::with_capacity(8);
        let changed = cpu_ref_into(
            4,
            &[0, 1, 2, 3, 3],
            &[1, 2, 3],
            &[1, 1, 1],
            &[0b0001],
            0xFFFF_FFFF,
            8,
            &mut frontier,
        );
        let capacity = frontier.capacity();
        assert_eq!(frontier, vec![0b1111]);
        assert_eq!(changed, 1);

        let changed = cpu_ref_into(
            4,
            &[0, 1, 2, 3, 3],
            &[1, 2, 3],
            &[1, 1, 1],
            &[0],
            0xFFFF_FFFF,
            8,
            &mut frontier,
        );
        assert_eq!(frontier.capacity(), capacity);
        assert_eq!(frontier, vec![0]);
        assert_eq!(changed, 0);
    }

    #[test]
    fn try_cpu_ref_into_with_scratch_reuses_step_storage_and_clears_stale_state() {
        let mut frontier = Vec::with_capacity(8);
        let mut step = Vec::with_capacity(8);
        step.extend_from_slice(&[0xDEAD_BEEF, 0xCAFE_BABE, 0xBADC_0FFE]);
        let mut scratch = PersistentBfsCpuScratch { step };
        let frontier_capacity = frontier.capacity();
        let step_capacity = scratch.step.capacity();

        let changed = try_cpu_ref_into_with_scratch(
            4,
            &[0, 1, 2, 3, 3],
            &[1, 2, 3],
            &[1, 1, 1],
            &[0b0001],
            0xFFFF_FFFF,
            8,
            &mut frontier,
            &mut scratch,
        )
        .expect("Fix: valid persistent BFS chain must run with reusable scratch.");
        assert_eq!(frontier, vec![0b1111]);
        assert_eq!(changed, 1);
        assert_eq!(frontier.capacity(), frontier_capacity);
        assert_eq!(scratch.step.capacity(), step_capacity);
        assert_eq!(scratch.step.len(), 1);

        let changed = try_cpu_ref_into_with_scratch(
            4,
            &[0, 1, 2, 3, 3],
            &[1, 2, 3],
            &[1, 1, 1],
            &[0],
            0xFFFF_FFFF,
            8,
            &mut frontier,
            &mut scratch,
        )
        .expect("Fix: second persistent BFS run must clear stale step bits.");
        assert_eq!(frontier, vec![0]);
        assert_eq!(changed, 0);
        assert_eq!(frontier.capacity(), frontier_capacity);
        assert_eq!(scratch.step.capacity(), step_capacity);
        assert_eq!(
            scratch.step,
            vec![0],
            "Fix: reusable step scratch must be resized to live words and cleared by traversal."
        );
    }

    #[test]
    fn try_cpu_ref_into_rejects_bad_input_without_clobbering_frontier() {
        let mut frontier = vec![0xDEAD_BEEF];
        let capacity = frontier.capacity();

        let err = try_cpu_ref_into(
            4,
            &[0, 1, 2],
            &[1, 2, 3],
            &[1, 1, 1],
            &[0b0001],
            0xFFFF_FFFF,
            8,
            &mut frontier,
        )
        .expect_err("Fix: fallible persistent BFS oracle must reject malformed CSR inputs");

        assert!(err.contains("CSR offsets"));
        assert_eq!(frontier, vec![0xDEAD_BEEF]);
        assert_eq!(frontier.capacity(), capacity);
    }

    #[test]
    fn try_cpu_ref_into_with_scratch_rejects_bad_input_without_clobbering_storage() {
        let mut frontier = vec![0xDEAD_BEEF];
        let mut scratch = PersistentBfsCpuScratch {
            step: vec![0xCAFE_BABE, 0xBADC_0FFE],
        };

        let err = try_cpu_ref_into_with_scratch(
            4,
            &[0, 1, 2],
            &[1, 2, 3],
            &[1, 1, 1],
            &[0b0001],
            0xFFFF_FFFF,
            8,
            &mut frontier,
            &mut scratch,
        )
        .expect_err("Fix: fallible persistent BFS oracle must reject malformed CSR inputs.");

        assert!(err.contains("CSR offsets"));
        assert_eq!(
            frontier,
            vec![0xDEAD_BEEF],
            "Fix: validation failures must not clobber reusable frontier output."
        );
        assert_eq!(
            scratch.step,
            vec![0xCAFE_BABE, 0xBADC_0FFE],
            "Fix: validation failures must not clear reusable step scratch."
        );
    }

    #[test]
    fn fallible_cpu_ref_matches_compatibility_oracle_on_generated_chains() {
        for node_count in [0_u32, 1, 2, 3, 31, 32, 33, 64, 65, 257] {
            let mut offsets = Vec::with_capacity(node_count as usize + 1);
            let mut targets = Vec::new();
            let mut masks = Vec::new();
            offsets.push(0);
            for node in 0..node_count {
                if node + 1 < node_count {
                    targets.push(node + 1);
                    masks.push(1);
                }
                offsets.push(targets.len() as u32);
            }
            let words = bitset_words(node_count) as usize;
            let mut seed = vec![0; words];
            if node_count != 0 {
                seed[0] = 1;
            }

            let expected = cpu_ref(
                node_count,
                &offsets,
                &targets,
                &masks,
                &seed,
                0xFFFF_FFFF,
                node_count.saturating_add(1),
            );
            let actual = try_cpu_ref(
                node_count,
                &offsets,
                &targets,
                &masks,
                &seed,
                0xFFFF_FFFF,
                node_count.saturating_add(1),
            )
            .expect("Fix: generated valid persistent BFS chain should run fallibly");
            assert_eq!(actual, expected, "node_count={node_count}");
        }
    }

    #[test]
    fn generated_try_cpu_ref_into_with_scratch_matches_allocating_reference() {
        let mut frontier = Vec::new();
        let mut scratch = PersistentBfsCpuScratch::new();

        for case in 0..1024usize {
            let node_count = (case % 67) as u32;
            let mut offsets = Vec::with_capacity(node_count as usize + 1);
            let mut targets = Vec::new();
            let mut masks = Vec::new();
            offsets.push(0);
            for src in 0..node_count {
                for dst in 0..node_count {
                    let mixed = case
                        .wrapping_mul(43)
                        .wrapping_add((src as usize).wrapping_mul(17))
                        .wrapping_add((dst as usize).wrapping_mul(29));
                    if src != dst && (mixed % 23 == 0 || (case % 19 == 0 && dst == src + 1)) {
                        targets.push(dst);
                        masks.push(if mixed % 2 == 0 { 1 } else { 2 });
                    }
                }
                offsets.push(targets.len() as u32);
            }

            let words = bitset_words(node_count) as usize;
            let mut seed = vec![0; words];
            for node in 0..node_count {
                let mixed = case
                    .wrapping_mul(11)
                    .wrapping_add((node as usize).wrapping_mul(7));
                if mixed % 13 == 0 || (node == 0 && node_count != 0) {
                    seed[(node / 32) as usize] |= 1u32 << (node % 32);
                }
            }
            let allow_mask = if case % 3 == 0 { 1 } else { 0xFFFF_FFFF };
            let max_iters = (case % 11) as u32;
            let expected = try_cpu_ref(
                node_count, &offsets, &targets, &masks, &seed, allow_mask, max_iters,
            )
            .expect("Fix: generated persistent BFS graph must be valid for allocating oracle.");
            let changed = try_cpu_ref_into_with_scratch(
                node_count,
                &offsets,
                &targets,
                &masks,
                &seed,
                allow_mask,
                max_iters,
                &mut frontier,
                &mut scratch,
            )
            .expect("Fix: generated persistent BFS graph must run with reusable scratch.");
            assert_eq!(
                (frontier.clone(), changed),
                expected,
                "Fix: scratch-backed persistent BFS diverged from allocating oracle at case {case}."
            );
        }
    }

    #[test]
    fn reusable_layout_validation_rejects_bad_csr_and_frontier() {
        let err = validate_persistent_bfs_graph_layout(2, &[0, 2, 1], &[1], &[1]).unwrap_err();
        assert!(err.contains("final CSR offset") || err.contains("non-monotonic"));

        let err = validate_persistent_bfs_graph_layout(2, &[0, 1, 1], &[2], &[1]).unwrap_err();
        assert!(err.contains("outside node_count"));

        let err = validate_persistent_bfs_inputs(33, &[0; 34], &[], &[], &[0]).unwrap_err();
        assert!(err.contains("frontier length 2 words"));
    }

    #[test]
    fn reusable_graph_layout_returns_dispatch_shape() {
        assert_eq!(
            validate_persistent_bfs_graph_layout(33, &[0; 34], &[], &[]).unwrap(),
            PersistentBfsLayout {
                node_count: 33,
                edge_count: 0,
                words: 2,
                words_u32: 2,
                node_words: 33,
                edge_storage_words: 1,
            }
        );
        assert_eq!(
            validate_persistent_bfs_inputs(4, &[0, 1, 2, 3, 3], &[1, 2, 3], &[1, 1, 1], &[0])
                .unwrap(),
            PersistentBfsLayout {
                node_count: 4,
                edge_count: 3,
                words: 1,
                words_u32: 1,
                node_words: 4,
                edge_storage_words: 3,
            }
        );
    }

    #[test]
    fn dispatch_plans_pin_grid_cache_shape_and_program_builders() {
        let edge_offsets = [0, 1, 2, 3, 3];
        let edge_targets = [1, 2, 3];
        let edge_kind_mask = [1, 1, 1];
        let plan = plan_persistent_bfs_dispatch(
            4,
            &edge_offsets,
            &edge_targets,
            &edge_kind_mask,
            &[0b0001],
            0xFFFF_FFFF,
            8,
        )
        .expect("Fix: canonical persistent-BFS dispatch plan should validate");

        assert_eq!(plan.layout().node_count, 4);
        assert_eq!(plan.layout().edge_count, 3);
        assert_eq!(plan.frontier_words(), 1);
        assert_eq!(plan.node_words(), 4);
        assert_eq!(plan.edge_storage_words(), 3);
        assert_eq!(plan.dispatch_grid(), PERSISTENT_BFS_SINGLE_DISPATCH_GRID);
        assert_eq!(
            plan.layout_hash(),
            persistent_bfs_layout_hash(4, &edge_offsets, &edge_targets, &edge_kind_mask)
        );
        assert_eq!(
            plan.cache_key(0xCAFE),
            PersistentBfsPlanCacheKey {
                layout_hash: plan.layout_hash(),
                node_count: 4,
                edge_count: 3,
                words_per_query: 1,
                query_count: 1,
                allow_mask: 0xFFFF_FFFF,
                max_iters: 8,
                device_features: 0xCAFE,
                kind: PersistentBfsPlanCacheKind::Single,
            }
        );
        assert_eq!(
            plan.program_cache_key(0xCAFE),
            PersistentBfsPlanCacheKey {
                layout_hash: persistent_bfs_program_layout_hash(
                    4,
                    3,
                    1,
                    1,
                    PersistentBfsPlanCacheKind::Single,
                ),
                node_count: 4,
                edge_count: 3,
                words_per_query: 1,
                query_count: 1,
                allow_mask: 0xFFFF_FFFF,
                max_iters: 8,
                device_features: 0xCAFE,
                kind: PersistentBfsPlanCacheKind::Single,
            }
        );
        assert_eq!(
            plan.program("frontier_in", "frontier_out").workgroup_size,
            PERSISTENT_BFS_WORKGROUP_SIZE
        );

        let empty_edge_plan =
            plan_persistent_bfs_dispatch(2, &[0, 0, 0], &[], &[], &[0], 0xFFFF_FFFF, 1)
                .expect("Fix: zero-edge persistent-BFS graph is a valid dispatch shape");
        assert_eq!(empty_edge_plan.layout().edge_count, 0);
        assert_eq!(empty_edge_plan.edge_storage_words(), 1);
        assert_eq!(
            empty_edge_plan
                .program("frontier_in", "frontier_out")
                .workgroup_size,
            PERSISTENT_BFS_WORKGROUP_SIZE
        );

        let resident = plan_persistent_bfs_resident_dispatch(4, 3, 1, &[0b0001], 0xFF, 4)
            .expect("Fix: resident single-frontier plan should validate");
        assert_eq!(resident.frontier_words(), 1);
        assert_eq!(resident.words_u32(), 1);
        assert_eq!(
            resident.dispatch_grid(),
            PERSISTENT_BFS_SINGLE_DISPATCH_GRID
        );
        assert_eq!(
            resident.cache_key(0xABCD, 0x10),
            PersistentBfsPlanCacheKey {
                layout_hash: 0xABCD,
                node_count: 4,
                edge_count: 3,
                words_per_query: 1,
                query_count: 1,
                allow_mask: 0xFF,
                max_iters: 4,
                device_features: 0x10,
                kind: PersistentBfsPlanCacheKind::Single,
            }
        );
        assert_eq!(
            resident.program_cache_key(0x10),
            PersistentBfsPlanCacheKey {
                layout_hash: persistent_bfs_program_layout_hash(
                    4,
                    3,
                    1,
                    1,
                    PersistentBfsPlanCacheKind::Single,
                ),
                node_count: 4,
                edge_count: 3,
                words_per_query: 1,
                query_count: 1,
                allow_mask: 0xFF,
                max_iters: 4,
                device_features: 0x10,
                kind: PersistentBfsPlanCacheKind::Single,
            }
        );

        let batch = plan_persistent_bfs_resident_batch_dispatch(4, 3, 1, &[1, 2], 2, 0xFF, 4)
            .expect("Fix: resident batch plan should validate");
        assert_eq!(batch.query_count(), 2);
        assert_eq!(batch.query_count_u32(), 2);
        assert_eq!(batch.total_words(), 2);
        assert_eq!(batch.words_per_query(), 1);
        assert_eq!(batch.dispatch_grid(), [1, 2, 1]);
        assert_eq!(
            batch
                .program("frontier_in", "frontier_out", "changed")
                .workgroup_size,
            PERSISTENT_BFS_WORKGROUP_SIZE
        );
        assert_eq!(
            batch.cache_key(0xABCD, 0x20),
            PersistentBfsPlanCacheKey {
                layout_hash: 0xABCD,
                node_count: 4,
                edge_count: 3,
                words_per_query: 1,
                query_count: 2,
                allow_mask: 0xFF,
                max_iters: 4,
                device_features: 0x20,
                kind: PersistentBfsPlanCacheKind::Batch,
            }
        );
        assert_eq!(
            batch.program_cache_key(0x20),
            PersistentBfsPlanCacheKey {
                layout_hash: persistent_bfs_program_layout_hash(
                    4,
                    3,
                    1,
                    2,
                    PersistentBfsPlanCacheKind::Batch,
                ),
                node_count: 4,
                edge_count: 3,
                words_per_query: 1,
                query_count: 2,
                allow_mask: 0xFF,
                max_iters: 4,
                device_features: 0x20,
                kind: PersistentBfsPlanCacheKind::Batch,
            }
        );
    }
