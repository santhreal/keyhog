use super::*;
use crate::GpuInitPolicy;
#[cfg(feature = "gpu")]
use crate::ScanBackend;

fn test_pattern(src: &str, case_insensitive: bool) -> CompiledPattern {
    test_pattern_with_shape(src, case_insensitive, 0, false)
}

fn test_pattern_with_shape(
    src: &str,
    case_insensitive: bool,
    detector_index: usize,
    homoglyph_variant: bool,
) -> CompiledPattern {
    let regex = if case_insensitive {
        LazyRegex::detector(src)
    } else {
        LazyRegex::plain(src)
    };
    CompiledPattern {
        detector_index,
        regex,
        group: None,
        client_safe: false,
        weak_anchor: false,
        match_proves_keyword_nearby: false,
        homoglyph_variant,
    }
}

fn forced_multi_shard_literal(index: usize) -> String {
    let mut state = (index as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut literal = format!("forced_{index:04x}_");
    for _ in 0..96 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        literal.push(char::from(b'a' + (state % 26) as u8));
    }
    literal
}

fn forced_multi_shard_patterns() -> Vec<(CompiledPattern, Vec<String>)> {
    (0..256usize)
        .map(|index| {
            (
                test_pattern(&forced_multi_shard_literal(index), false),
                Vec::new(),
            )
        })
        .collect()
}

fn forced_multi_shard_catalog() -> Phase2GpuDfaCatalog {
    let patterns = forced_multi_shard_patterns();
    let candidates: Vec<usize> = (0..patterns.len()).collect();
    Phase2GpuDfaCatalog::build_from_selected_candidates(
        &patterns,
        candidates.len(),
        0,
        &candidates,
        Phase2GpuDfaProgramKind::CudaCompatible,
    )
    .expect("forced multi-shard pattern set must lower completely")
}

fn replay_catalog_admission(
    catalog: &Phase2GpuDfaCatalog,
    chunks: &[keyhog_core::Chunk],
) -> Vec<bool> {
    let mut scratch = Phase2GpuDfaScratch::default();
    build_packed_region_batch(chunks, &mut scratch).expect("region batch");
    let mut admitted = vec![false; chunks.len()];
    for shard in &catalog.shards {
        replay_shard_admission(shard, &scratch, &mut admitted);
    }
    admitted
}

fn replay_shard_admission(
    shard: &Phase2GpuDfaShard,
    scratch: &Phase2GpuDfaScratch,
    admitted: &mut [bool],
) {
    let dfa = &shard.pipeline.dfa;
    for origin in 0..scratch.haystack.len() {
        let mut state = 0u32;
        for (relative_pos, &byte) in scratch.haystack[origin..].iter().enumerate() {
            state = dfa.transitions[(state as usize) * 256 + byte as usize];
            let begin = dfa.output_offsets[state as usize] as usize;
            let end = dfa.output_offsets[state as usize + 1] as usize;
            if begin == end {
                continue;
            }
            let end_offset = origin.saturating_add(relative_pos).saturating_add(1);
            let Some(region) = match_region(
                &scratch.region_starts,
                scratch.haystack.len(),
                origin as u32,
                end_offset as u32,
            ) else {
                continue;
            };
            if let Some(slot) = admitted.get_mut(region) {
                *slot = true;
            }
        }
    }
}

#[test]
fn packed_region_batch_preserves_case_separates_pads_and_clears() {
    let chunks = [
        keyhog_core::Chunk::from("GhP_TOKEN"),
        keyhog_core::Chunk::from("Zz9"),
    ];
    let mut scratch = Phase2GpuDfaScratch::default();
    {
        let guard = ZeroPhase2GpuDfaScratch::new(&mut scratch);
        build_packed_region_batch(&chunks, guard.scratch).expect("batch");
        assert_eq!(guard.scratch.haystack, b"GhP_TOKEN\0Zz9");
        assert_eq!(guard.scratch.haystack_len, b"GhP_TOKEN\0Zz9".len());
        assert_eq!(
            guard.scratch.dispatch.haystack_bytes,
            b"GhP_TOKEN\0Zz9\0\0\0".to_vec(),
            "production upload scratch must be u32-padded directly without a second pack step"
        );
        assert_eq!(guard.scratch.region_starts, &[0, 10]);
    }
    assert!(scratch.haystack.is_empty());
    assert_eq!(scratch.haystack_len, 0);
    assert!(scratch.region_starts.is_empty());
    assert!(scratch.dispatch.haystack_bytes.is_empty());
}

#[test]
fn match_region_rejects_degenerate_and_cross_region_hits() {
    let starts = [0, 5, 10];
    assert_eq!(match_region(&starts, 14, 1, 4), Some(0));
    assert_eq!(match_region(&starts, 14, 5, 8), Some(1));
    assert_eq!(match_region(&starts, 14, 2, 2), None);
    assert_eq!(match_region(&starts, 14, 4, 6), None);
}

#[test]
fn match_region_rejects_separator_only_and_separator_touching_hits() {
    let chunks = [
        keyhog_core::Chunk::from("abcd"),
        keyhog_core::Chunk::from("wxyz"),
    ];
    let mut scratch = Phase2GpuDfaScratch::default();
    build_packed_region_batch(&chunks, &mut scratch).expect("region batch");
    assert_eq!(scratch.haystack, b"abcd\0wxyz");
    assert_eq!(scratch.region_starts, &[0, 5]);

    assert_eq!(
        match_region(&scratch.region_starts, scratch.haystack.len(), 0, 4),
        Some(0)
    );
    assert_eq!(
        match_region(&scratch.region_starts, scratch.haystack.len(), 5, 9),
        Some(1)
    );
    assert_eq!(
        match_region(&scratch.region_starts, scratch.haystack.len(), 4, 5),
        None,
        "the separator byte between regions must not admit the previous chunk"
    );
    assert_eq!(
        match_region(&scratch.region_starts, scratch.haystack.len(), 3, 5),
        None,
        "a match that includes the separator tail must not admit a chunk"
    );
    assert_eq!(
        match_region(&scratch.region_starts, scratch.haystack.len(), 4, 6),
        None,
        "a match that spans the separator into the next chunk must not admit either chunk"
    );
}

#[test]
fn program_kind_is_backend_keyed() {
    assert_eq!(
        Phase2GpuDfaProgramKind::for_backend_id(Some("cuda")),
        Phase2GpuDfaProgramKind::CudaCompatible
    );
    assert_eq!(
        Phase2GpuDfaProgramKind::for_backend_id(Some("vulkan")),
        Phase2GpuDfaProgramKind::SubgroupCoalesced
    );
    assert_eq!(
        Phase2GpuDfaProgramKind::for_backend_id(None),
        Phase2GpuDfaProgramKind::SubgroupCoalesced
    );
    assert!(!Phase2GpuDfaProgramKind::CudaCompatible.use_subgroup_coalesce());
    assert!(Phase2GpuDfaProgramKind::SubgroupCoalesced.use_subgroup_coalesce());
}

#[test]
fn catalog_preparation_cost_is_recorded_once_and_reused() {
    let patterns = vec![(test_pattern("[a-z]{6}[0-9]{2}", false), Vec::new())];
    let cache = Phase2GpuDfaCatalogCache::default();

    let first = cache.catalog(&patterns, &[0], Some("cuda"));
    assert!(
        first.is_some(),
        "the test pattern must lower into a GPU DFA"
    );
    let first_preparation_ns = cache.preparation_ns(Some("cuda"));
    assert!(
        first_preparation_ns > 0,
        "catalog initialization must record a nonzero cold cost"
    );

    let second = cache.catalog(&patterns, &[0], Some("cuda"));
    assert!(std::ptr::eq(
        first.expect("first catalog"),
        second.expect("second catalog")
    ));
    assert_eq!(
        cache.preparation_ns(Some("cuda")),
        first_preparation_ns,
        "reusing an immutable catalog must not replace its measured cold cost"
    );
}

#[test]
fn gpu_dfa_ascii_plan_excludes_only_redundant_homoglyph_variants() {
    let patterns = vec![
        (
            test_pattern_with_shape("glyph0[0-9]{2}", false, 0, true),
            Vec::new(),
        ),
        (
            test_pattern_with_shape("base0[0-9]{2}", true, 0, false),
            Vec::new(),
        ),
        (
            test_pattern_with_shape("glyph1[0-9]{2}", false, 1, true),
            Vec::new(),
        ),
        (
            test_pattern_with_shape("base2[0-9]{2}", true, 2, false),
            Vec::new(),
        ),
        (
            test_pattern_with_shape("base2b[0-9]{2}", true, 2, false),
            Vec::new(),
        ),
    ];
    let candidates = [0, 1, 2, 3, 4];

    assert_eq!(
        ascii_phase2_gpu_dfa_candidates(&patterns, &candidates),
        vec![1, 3, 4],
        "ASCII admission keeps every base regex in stable order and excludes generated homoglyph shadows"
    );
}

#[test]
#[should_panic]
fn gpu_dfa_candidate_selection_fails_loud_on_corrupt_indices() {
    let patterns = vec![
        (
            test_pattern_with_shape("base0[0-9]{2}", true, 0, false),
            Vec::new(),
        ),
        (
            test_pattern_with_shape("base1[0-9]{2}", true, 1, false),
            Vec::new(),
        ),
    ];
    let candidates = [usize::MAX, 1, 9, 0];

    // LAW10: intentional should-panic probe for corrupt construction-owned phase-2 indices; test-only no runtime effect in production.
    ascii_phase2_gpu_dfa_candidates(&patterns, &candidates);
}

#[test]
fn regex_dfa_source_preserves_detector_case_policy() {
    let detector = test_pattern("abc[0-9]{2}", true);
    let plain = test_pattern("abc[0-9]{2}", false);

    assert_eq!(
            regex_dfa_source_for_pattern(&detector).as_ref(),
            "(?i:abc[0-9]{2})",
            "detector regexes are compiled case-insensitive on the CPU path and must lower the same way for GPU DFA admission"
        );
    assert_eq!(
        regex_dfa_source_for_pattern(&plain).as_ref(),
        "abc[0-9]{2}",
        "plain homoglyph variants must stay case-sensitive when lowered"
    );
}

#[test]
fn replayed_gpu_dfa_admission_matches_cpu_regex_case_policy() {
    let patterns = vec![(test_pattern("abc[0-9]{2}", true), Vec::new())];
    let catalog = Phase2GpuDfaCatalog::build_from_selected_candidates(
        &patterns,
        1,
        0,
        &[0],
        Phase2GpuDfaProgramKind::CudaCompatible,
    )
    .expect("case-insensitive detector pattern should lower");
    let chunks = [
        keyhog_core::Chunk::from("prefix ABC12 suffix"),
        keyhog_core::Chunk::from("prefix abc34 suffix"),
        keyhog_core::Chunk::from("prefix xyz99 suffix"),
    ];
    let gpu_admitted = replay_catalog_admission(&catalog, &chunks);
    let cpu_admitted: Vec<bool> = chunks
        .iter()
        .map(|chunk| patterns[0].0.regex.get().is_match(&chunk.data))
        .collect();

    assert_eq!(
        gpu_admitted, cpu_admitted,
        "GPU regex-DFA admission must mirror the detector LazyRegex case policy"
    );
    assert_eq!(gpu_admitted, vec![true, true, false]);
}

#[test]
fn replayed_gpu_dfa_admission_keeps_plain_patterns_case_sensitive() {
    let patterns = vec![(test_pattern("abc[0-9]{2}", false), Vec::new())];
    let catalog = Phase2GpuDfaCatalog::build_from_selected_candidates(
        &patterns,
        1,
        0,
        &[0],
        Phase2GpuDfaProgramKind::CudaCompatible,
    )
    .expect("plain pattern should lower");
    let chunks = [
        keyhog_core::Chunk::from("prefix ABC12 suffix"),
        keyhog_core::Chunk::from("prefix abc34 suffix"),
    ];
    let gpu_admitted = replay_catalog_admission(&catalog, &chunks);
    let cpu_admitted: Vec<bool> = chunks
        .iter()
        .map(|chunk| patterns[0].0.regex.get().is_match(&chunk.data))
        .collect();

    assert_eq!(
        gpu_admitted, cpu_admitted,
        "plain phase-2 variants must not become case-insensitive in the GPU DFA catalog"
    );
    assert_eq!(gpu_admitted, vec![false, true]);
}

#[test]
fn embedded_detector_set_has_complete_ascii_prefixless_catalog() {
    let detectors = keyhog_core::load_embedded_detectors_or_fail()
        .expect("embedded detector corpus must parse");
    let scanner = CompiledScanner::compile_with_gpu_policy(detectors, GpuInitPolicy::ForceDisabled)
        .expect("embedded detector corpus must compile without GPU acquisition");
    let candidates = prefixless_always_active_candidates(
        &scanner.phase2_patterns,
        &scanner.phase2_always_active_indices,
    );
    assert!(
        !candidates.is_empty(),
        "generated homoglyph shadows remain represented in phase two"
    );
    let selected = ascii_phase2_gpu_dfa_candidates(&scanner.phase2_patterns, &candidates);
    assert!(selected
        .iter()
        .all(|&idx| !scanner.phase2_patterns[idx].0.homoglyph_variant));
    assert_eq!(
        selected.len(),
        candidates
            .iter()
            .filter(|&&idx| !scanner.phase2_patterns[idx].0.homoglyph_variant)
            .count()
    );
    for &idx in &selected {
        let mut shards = Vec::new();
        let mut uncovered = 0;
        build_shards_recursive(
            &scanner.phase2_patterns,
            &[idx],
            false,
            &mut shards,
            &mut uncovered,
        );
        assert_eq!(uncovered, 0, "phase-2 pattern {idx} did not lower");
        assert_eq!(shards.len(), 1);
    }
    let catalog = Phase2GpuDfaCatalog::build_from_selected_candidates(
        &scanner.phase2_patterns,
        selected.len(),
        candidates.len().saturating_sub(selected.len()),
        &selected,
        Phase2GpuDfaProgramKind::CudaCompatible,
    )
    .expect("the complete embedded ASCII no-trigger plan must produce a catalog receipt");
    let covered: usize = catalog
        .shards
        .iter()
        .map(|shard| shard.phase2_indices.len())
        .sum();
    assert_eq!(catalog.uncovered_ascii_patterns, 0);
    assert_eq!(covered, selected.len());
    assert_eq!(
        catalog.excluded_ascii_redundant_patterns,
        candidates.len().saturating_sub(selected.len())
    );
    assert!(
        catalog.shards.len() <= selected.len(),
        "recursive lowering may split shards for state bounds but cannot require more work than one shard per selected pattern"
    );
}

#[test]
fn resident_capacity_growth_preserves_gpu_element_alignment() {
    let packed = 8 * 1024 * 1024 + 8;
    let (capacity, regions) =
        resident::resident_capacity_for_test(packed, 8).expect("aligned batch capacity");
    assert_eq!(capacity, 10_485_772);
    assert_eq!(capacity % std::mem::size_of::<u32>(), 0);
    assert!(capacity >= packed);
    assert_eq!(regions, 8);
}

#[test]
fn resident_capacity_rejects_unaligned_and_oversized_batches() {
    let unaligned = resident::resident_capacity_for_test(5, 1)
        .expect_err("unaligned packed input must fail before GPU allocation");
    assert!(unaligned.contains("not aligned"), "{unaligned}");

    let ceiling = vyre_libs::scan::dispatch_io::DEFAULT_MAX_SCAN_BYTES as usize;
    let oversized = resident::resident_capacity_for_test(ceiling + 4, 1)
        .expect_err("batch above the backend ceiling must fail");
    assert!(oversized.contains("above Vyrë's"), "{oversized}");
}

#[test]
fn forced_catalog_exercises_multiple_complete_dfa_shards() {
    let catalog = forced_multi_shard_catalog();
    let coverage = catalog.coverage();
    assert!(
        coverage.shards >= 2,
        "fixture must cross the DFA state cap, got {coverage:?}",
    );
    assert_eq!(coverage.covered_ascii_patterns, 256);
    assert_eq!(coverage.uncovered_ascii_patterns, 0);
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires a hardware CUDA or WGPU peer and records performance evidence"]
fn forced_multi_shard_resident_sequence_beats_per_shard_upload_baseline() {
    const CHUNK_BYTES: usize = 1024 * 1024;
    const CHUNK_COUNT: usize = 8;
    const TRIALS: usize = 12;

    let catalog = forced_multi_shard_catalog();
    let single_shard_catalogs = catalog.single_shard_catalogs_for_test();
    let shard_count = single_shard_catalogs.len();
    assert!(
        shard_count >= 2,
        "benchmark fixture must remain multi-shard"
    );

    let scanner = CompiledScanner::compile_with_gpu_policy(
        keyhog_core::load_embedded_detectors_or_fail().expect("embedded detectors"),
        GpuInitPolicy::ForceEnabled,
    )
    .expect("scanner with GPU census");
    let route = ScanBackend::GpuCuda;
    let backend = scanner
        .gpu_backends
        .get(route)
        .cloned()
        .expect("known RTX host must acquire CUDA for release evidence");

    let chunks: Vec<keyhog_core::Chunk> = (0..CHUNK_COUNT)
        .map(|index| {
            let mut bytes = vec![b'x'; CHUNK_BYTES];
            let literal = forced_multi_shard_literal(index * 17);
            let offset = 4096 + index * 257;
            bytes[offset..offset + literal.len()].copy_from_slice(literal.as_bytes());
            keyhog_core::Chunk::from(String::from_utf8(bytes).expect("ASCII benchmark chunk"))
        })
        .collect();

    let reference = catalog
        .scan_admission_chunks(&backend, &chunks)
        .expect("warm fused resident scan");
    assert_eq!(reference.admitted, vec![true; CHUNK_COUNT]);
    let mut baseline_reference = vec![false; CHUNK_COUNT];
    for shard in &single_shard_catalogs {
        let admission = shard
            .scan_admission_chunks(&backend, &chunks)
            .expect("warm single-shard baseline scan");
        for (merged, admitted) in baseline_reference
            .iter_mut()
            .zip(admission.admitted.into_iter())
        {
            *merged |= admitted;
        }
    }
    assert_eq!(
        baseline_reference, reference.admitted,
        "resident sequence and per-shard baseline must admit identical regions",
    );

    let metric_snapshot = || {
        backend
            .backend_metric_snapshot()
            .into_iter()
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let metric = |snapshot: &std::collections::BTreeMap<&'static str, u64>, name| {
        *snapshot
            .get(name)
            .unwrap_or_else(|| panic!("CUDA release metric `{name}` must be exposed"))
    };
    let before_fused = metric_snapshot();
    let telemetry_fused = catalog
        .scan_admission_chunks(&backend, &chunks)
        .expect("telemetry fused resident scan");
    assert_eq!(telemetry_fused.admitted, reference.admitted);
    let after_fused = metric_snapshot();
    let before_baseline = after_fused.clone();
    let mut telemetry_baseline = vec![false; CHUNK_COUNT];
    for shard in &single_shard_catalogs {
        let admission = shard
            .scan_admission_chunks(&backend, &chunks)
            .expect("telemetry per-shard baseline scan");
        for (merged, hit) in telemetry_baseline
            .iter_mut()
            .zip(admission.admitted.into_iter())
        {
            *merged |= hit;
        }
    }
    assert_eq!(telemetry_baseline, reference.admitted);
    let after_baseline = metric_snapshot();
    let delta = |before: &std::collections::BTreeMap<&'static str, u64>,
                 after: &std::collections::BTreeMap<&'static str, u64>,
                 name| {
        metric(after, name)
            .checked_sub(metric(before, name))
            .unwrap_or_else(|| panic!("CUDA metric `{name}` must be monotonic"))
    };
    let fused_upload_bytes = delta(&before_fused, &after_fused, "cuda_host_to_device_bytes");
    let baseline_upload_bytes = delta(
        &before_baseline,
        &after_baseline,
        "cuda_host_to_device_bytes",
    );
    let fused_upload_operations = delta(&before_fused, &after_fused, "cuda_host_upload_operations");
    let baseline_upload_operations = delta(
        &before_baseline,
        &after_baseline,
        "cuda_host_upload_operations",
    );
    let fused_readbacks = delta(
        &before_fused,
        &after_fused,
        "cuda_device_readback_operations",
    );
    let baseline_readbacks = delta(
        &before_baseline,
        &after_baseline,
        "cuda_device_readback_operations",
    );
    assert!(
        baseline_upload_bytes > fused_upload_bytes,
        "per-shard baseline must re-upload more bytes: fused={fused_upload_bytes} baseline={baseline_upload_bytes}",
    );
    assert!(
        baseline_upload_operations > fused_upload_operations,
        "resident sequence must reduce upload operations: fused={fused_upload_operations} baseline={baseline_upload_operations}",
    );
    assert_eq!(
        fused_readbacks, shard_count as u64,
        "resident sequence must read each shard result exactly once",
    );
    assert_eq!(
        baseline_readbacks, shard_count as u64,
        "per-shard baseline must read each shard result exactly once",
    );

    let mut fused_ns = Vec::with_capacity(TRIALS);
    let mut baseline_ns = Vec::with_capacity(TRIALS);
    for trial in 0..TRIALS {
        let run_fused = || {
            let started = std::time::Instant::now();
            let admission = catalog
                .scan_admission_chunks(&backend, &chunks)
                .expect("fused resident trial");
            assert_eq!(admission.admitted, reference.admitted);
            started.elapsed().as_nanos() as u64
        };
        let run_baseline = || {
            let started = std::time::Instant::now();
            let mut admitted = vec![false; CHUNK_COUNT];
            for shard in &single_shard_catalogs {
                let shard_admission = shard
                    .scan_admission_chunks(&backend, &chunks)
                    .expect("per-shard baseline trial");
                for (merged, hit) in admitted
                    .iter_mut()
                    .zip(shard_admission.admitted.into_iter())
                {
                    *merged |= hit;
                }
            }
            assert_eq!(admitted, reference.admitted);
            started.elapsed().as_nanos() as u64
        };
        if trial % 2 == 0 {
            fused_ns.push(run_fused());
            baseline_ns.push(run_baseline());
        } else {
            baseline_ns.push(run_baseline());
            fused_ns.push(run_fused());
        }
    }
    fused_ns.sort_unstable();
    baseline_ns.sort_unstable();
    let fused_median = fused_ns[TRIALS / 2];
    let baseline_median = baseline_ns[TRIALS / 2];
    eprintln!(
        "forced_multi_shard_gpu backend={} bytes={} shards={} trials={} fused_upload_bytes={} baseline_upload_bytes={} fused_upload_operations={} baseline_upload_operations={} fused_readbacks={} baseline_readbacks={} fused_median_ns={} baseline_median_ns={} ratio={:.4}",
        route.label(),
        CHUNK_BYTES * CHUNK_COUNT,
        shard_count,
        TRIALS,
        fused_upload_bytes,
        baseline_upload_bytes,
        fused_upload_operations,
        baseline_upload_operations,
        fused_readbacks,
        baseline_readbacks,
        fused_median,
        baseline_median,
        fused_median as f64 / baseline_median as f64,
    );
    assert!(
        fused_median < baseline_median,
        "one resident sequence must beat repeated per-shard upload/readback: fused={fused_median}ns baseline={baseline_median}ns",
    );
}

#[test]
fn empty_ascii_plan_is_complete_without_a_dispatch_catalog() {
    let catalog = Phase2GpuDfaCatalog::build_from_selected_candidates(
        &[],
        0,
        7,
        &[],
        Phase2GpuDfaProgramKind::CudaCompatible,
    )
    .expect("an empty ASCII plan is a complete negative proof");

    assert!(catalog.shards.is_empty());
    assert_eq!(catalog.uncovered_ascii_patterns, 0);
    assert_eq!(catalog.excluded_ascii_redundant_patterns, 7);
}
