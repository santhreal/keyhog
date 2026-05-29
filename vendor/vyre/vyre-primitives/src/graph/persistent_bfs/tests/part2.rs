use super::super::*;
use crate::graph::program_graph::ProgramGraphShape;


    #[test]
    fn reusable_batch_frontier_validation_accepts_empty_and_canonical_batches() {
        assert_eq!(
            validate_persistent_bfs_batch_frontiers(2, &[], 0).unwrap(),
            PersistentBfsBatchLayout {
                query_count: 0,
                total_words: 0,
            }
        );

        assert_eq!(
            validate_persistent_bfs_batch_frontiers(2, &[1, 0, 2, 0, 4, 0], 3).unwrap(),
            PersistentBfsBatchLayout {
                query_count: 3,
                total_words: 6,
            }
        );
    }

    #[test]
    fn reusable_batch_frontier_validation_rejects_bad_shape_and_overflow() {
        let err = validate_persistent_bfs_batch_frontiers(2, &[1, 0, 2], 2).unwrap_err();
        assert!(err.contains("expected 4 frontier word"));

        let err = validate_persistent_bfs_batch_frontiers(usize::MAX, &[], 2).unwrap_err();
        assert!(err.contains("word count overflows usize"));

        let err =
            validate_persistent_bfs_batch_frontiers(1, &[], u32::MAX as usize + 1).unwrap_err();
        assert!(err.contains("query_count"));
    }

    #[test]
    fn reusable_single_frontier_validation_accepts_canonical_frontier() {
        assert_eq!(
            validate_persistent_bfs_frontier(2, &[1, 0]).unwrap(),
            PersistentBfsFrontierLayout {
                words: 2,
                words_u32: 2,
            }
        );
    }

    #[test]
    fn reusable_single_frontier_validation_rejects_bad_shape_and_overflow() {
        let err = validate_persistent_bfs_frontier(2, &[1]).unwrap_err();
        assert!(err.contains("expected frontier length 2 word"));

        let err = validate_persistent_bfs_frontier(u32::MAX as usize + 1, &[]).unwrap_err();
        assert!(err.contains("frontier word count"));
    }


    #[test]
    fn layout_hash_distinguishes_edges_and_masks() {
        let a = persistent_bfs_layout_hash(2, &[0, 1, 1], &[1], &[1]);
        let b = persistent_bfs_layout_hash(2, &[0, 1, 1], &[1], &[2]);
        let c = persistent_bfs_layout_hash(2, &[0, 1, 1], &[0], &[1]);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn program_cache_key_reuses_same_shape_graph_variants() {
        let a = plan_persistent_bfs_dispatch(
            4,
            &[0, 1, 2, 3, 3],
            &[1, 2, 3],
            &[1, 1, 1],
            &[1],
            0xFFFF_FFFF,
            8,
        )
        .unwrap();
        let b = plan_persistent_bfs_dispatch(
            4,
            &[0, 1, 2, 3, 3],
            &[2, 3, 0],
            &[1, 1, 1],
            &[1],
            0xFFFF_FFFF,
            8,
        )
        .unwrap();

        assert_ne!(a.layout_hash(), b.layout_hash());
        assert_ne!(a.cache_key(0xCAFE), b.cache_key(0xCAFE));
        assert_eq!(a.program_cache_key(0xCAFE), b.program_cache_key(0xCAFE));
    }

    #[test]
    fn empty_frontier_stays_empty() {
        let (frontier, changed) = cpu_ref(
            4,
            &[0, 2, 3, 4, 4],
            &[1, 2, 3, 3],
            &[1, 1, 1, 1],
            &[0],
            0xFFFF_FFFF,
            4,
        );
        assert_eq!(frontier, vec![0]);
        assert_eq!(changed, 0);
    }

    #[test]
    fn edge_mask_limits_reachability() {
        // 0→1 (mask 0b10), 0→2 (mask 0b01), 1→3 (mask 0b01), 2→3 (mask 0b01)
        let (frontier, changed) = cpu_ref(
            4,
            &[0, 2, 3, 4, 4],
            &[1, 2, 3, 3],
            &[0b10, 0b01, 0b01, 0b01],
            &[0b0001],
            0b01,
            4,
        );
        // From 0, only 0→2 is allowed. Then 2→3 is allowed.
        assert_eq!(frontier, vec![0b1101]);
        assert_eq!(changed, 1);
    }

    #[test]
    fn max_iters_caps_expansion() {
        // Chain: 0→1, 1→2, 2→3. Frontier = {0}.
        let (frontier, changed) = cpu_ref(
            4,
            &[0, 1, 2, 3, 3],
            &[1, 2, 3],
            &[1, 1, 1],
            &[0b0001],
            0xFFFF_FFFF,
            2,
        );
        // After 2 steps: {0,1,2}
        assert_eq!(frontier, vec![0b0111]);
        assert_eq!(changed, 1);
    }

    #[test]
    fn zero_max_iters_is_noop() {
        let (frontier, changed) = cpu_ref(
            4,
            &[0, 2, 3, 4, 4],
            &[1, 2, 3, 3],
            &[1, 1, 1, 1],
            &[0b0001],
            0xFFFF_FFFF,
            0,
        );
        assert_eq!(frontier, vec![0b0001]);
        assert_eq!(changed, 0);
    }

    #[test]
    fn program_builds_and_validates() {
        let program = persistent_bfs(ProgramGraphShape::new(8, 8), "fin", "fout", 0xFF, 4);
        assert_eq!(program.workgroup_size, [256, 1, 1]);
        // 5 canonical PG buffers + frontier_in + frontier_out + changed + wg_scratch + wg_active
        assert_eq!(program.buffers().len(), 10);
    }

    #[test]
    fn program_carries_device_side_convergence_flag() {
        let program = persistent_bfs(ProgramGraphShape::new(8, 8), "fin", "fout", 0xFF, 8);
        let debug = format!("{:?}", program.entry);
        assert!(
            debug.contains("wg_active"),
            "persistent_bfs must gate later device work through a workgroup-resident active flag"
        );
    }

    #[test]
    fn persistent_bfs_seed_copy_covers_frontiers_larger_than_one_workgroup() {
        let source = include_str!("../program.rs");
        let single_source = source
            .split("pub fn persistent_bfs(")
            .nth(1)
            .expect("Fix: persistent_bfs builder source must be present")
            .split("/// Build a batched persistent-BFS Program.")
            .next()
            .expect("Fix: persistent_bfs builder source must precede batch builder");

        assert!(
            single_source.contains("Node::loop_for(\n                \"seed_word_idx\""),
            "Fix: persistent_bfs must copy every frontier word, not only the first workgroup lane range."
        );
        assert!(
            !single_source.contains("Node::let_bind(\"seed_word_idx\", t.clone())"),
            "Fix: persistent_bfs seed copy must not be capped by gid_x."
        );
    }

    #[test]
    fn batch_program_carries_per_query_convergence_flag() {
        let program = persistent_bfs_batch(
            ProgramGraphShape::new(8, 8),
            "fin",
            "fout",
            "changed",
            4,
            0xFF,
            8,
        );
        let debug = format!("{:?}", program.entry);
        assert!(
            debug.contains("batch_active"),
            "persistent_bfs_batch must gate later per-query device work through an active flag"
        );
    }

    #[test]
    fn persistent_bfs_batch_seed_copy_covers_frontiers_larger_than_one_workgroup() {
        let source = include_str!("../program.rs");
        let batch_source = source
            .split("pub fn try_persistent_bfs_batch(")
            .nth(1)
            .expect("Fix: checked batch builder source must be present")
            .split("fn checked_batch_frontier_words(")
            .next()
            .expect("Fix: checked batch builder source must precede sizing helper");

        assert!(
            batch_source.contains("Node::loop_for(\n                \"batch_copy_word\""),
            "Fix: persistent_bfs_batch must copy every frontier word for each query."
        );
        assert!(
            !batch_source.contains("Expr::lt(t.clone(), Expr::u32(words))"),
            "Fix: persistent_bfs_batch seed copy must not be capped by the first workgroup lane range."
        );
    }

    #[test]
    fn checked_batch_builder_rejects_flat_frontier_overflow() {
        let error = try_persistent_bfs_batch(
            ProgramGraphShape::new(u32::MAX, 0),
            "fin",
            "fout",
            "changed",
            33,
            0xFF,
            1,
        )
        .expect_err("checked batched persistent BFS builder must reject flat frontier overflow");

        assert!(
            error.contains("frontier words overflow u32"),
            "error should describe the flat frontier overflow: {error}"
        );
    }

    #[test]
    fn legacy_batch_builder_fails_fast_on_flat_frontier_overflow() {
        let panic = std::panic::catch_unwind(|| {
            let _ = persistent_bfs_batch(
                ProgramGraphShape::new(u32::MAX, 0),
                "fin",
                "fout",
                "changed",
                33,
                0xFF,
                1,
            );
        })
        .expect_err("legacy batched persistent BFS builder must fail fast on flat frontier overflow");

        let message = panic_payload_message(panic);
        assert!(
            message.contains("frontier words overflow u32"),
            "error should describe the flat frontier overflow: {message}"
        );
    }

    #[test]
    fn persistent_bfs_batch_release_source_has_checked_builder_without_panics() {
        let source = include_str!("../program.rs");
        let batch_source = source
            .split("/// Build a batched persistent-BFS Program.")
            .nth(1)
            .expect("Fix: persistent BFS batch builder source must be present")
            .split("/// CPU reference:")
            .next()
            .expect("Fix: persistent BFS batch builder source must precede CPU oracle");

        assert!(
            batch_source.contains("pub fn try_persistent_bfs_batch(")
                && !batch_source.contains("inert_")
                && !batch_source.contains("Err(_) =>")
                && !batch_source.contains("Node::return_()"),
            "Fix: persistent_bfs_batch must expose checked release API and must not compile inert no-op kernels."
        );
    }

    fn panic_payload_message(payload: Box<dyn std::any::Any + Send>) -> String {
        if let Some(message) = payload.downcast_ref::<&str>() {
            message.to_string()
        } else if let Some(message) = payload.downcast_ref::<String>() {
            message.clone()
        } else {
            format!("{payload:?}")
        }
    }
