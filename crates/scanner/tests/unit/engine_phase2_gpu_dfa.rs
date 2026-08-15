use super::*;
#[cfg(feature = "gpu")]
use crate::engine::gpu_region_batch::with_test_region_presence_byte_limit;
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
        pattern_index: 0,
        regex,
        group: None,
        client_safe: false,
        weak_anchor: false,
        structural_password_slot: false,
        match_proves_keyword_nearby: false,
        allows_repeated_keyword_separator: false,
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

#[cfg(feature = "gpu")]
/// WHY: an admission-dispatch fault must recover only unfinished input
/// shards; this does not cover process or device loss during fence retirement.
#[test]
fn automatic_phase2_gpu_recovery_preserves_completed_shards() {
    let _gpu_test_guard = crate::testing::gpu_test_lock();
    let patterns = vec![(test_pattern(r"tok_[A-Za-z0-9]{16}", false), Vec::new())];
    let catalog = Phase2GpuDfaCatalog::build_from_selected_candidates(
        &patterns,
        1,
        0,
        &[0],
        Phase2GpuDfaProgramKind::CudaCompatible,
    )
    .expect("phase-two recovery catalog");
    let scanner = CompiledScanner::compile_with_gpu_policy(
        keyhog_core::load_embedded_detectors_or_fail().expect("embedded detectors"),
        GpuInitPolicy::ForceEnabled,
    )
    .expect("scanner with GPU peers");
    let backend = [ScanBackend::GpuCuda, ScanBackend::GpuWgpu]
        .into_iter()
        .find_map(|route| scanner.gpu_backend(route).cloned())
        .expect("known GPU test host must acquire a hardware backend");
    let chunks = vec![
        keyhog_core::Chunk::from(format!("{}tok_AAAAAAAAAAAAAAAA", "a".repeat(24))),
        keyhog_core::Chunk::from(format!("{}tok_BBBBBBBBBBBBBBBB", "b".repeat(24))),
        keyhog_core::Chunk::from(format!("{}tok_CCCCCCCCCCCCCCCC", "c".repeat(24))),
    ];

    let outcome = with_test_region_presence_byte_limit(64, || {
        crate::engine::gpu_region_dispatch_helpers::with_test_phase2_dispatch_failure(1, || {
            crate::engine::gpu_region_dispatch_helpers::scan_phase2_gpu_chunks_sharded(
                &catalog, &backend, &chunks, true,
            )
            .expect("phase-two dispatch recovery")
        })
    });

    assert!(outcome.fault.is_some(), "typed recovery fault is required");
    assert_eq!(outcome.recovered_rows, vec![1..3]);
    assert_eq!(outcome.haystack_uploads, 1);
    assert_eq!(outcome.admission.admitted, vec![true, false, false]);
    assert_eq!(outcome.admission.complete, vec![true, false, false]);
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
fn generated_coverage_evidence_accounts_for_the_compiled_phase2_universe() {
    let detectors = keyhog_core::load_embedded_detectors_or_fail()
        .expect("embedded detector corpus must parse");
    let scanner = CompiledScanner::compile_with_gpu_policy(detectors, GpuInitPolicy::ForceDisabled)
        .expect("embedded detector corpus must compile");
    let catalog = Phase2GpuDfaCatalog::build(
        &scanner.phase2_patterns,
        &scanner.phase2_always_active_indices,
        Phase2GpuDfaProgramKind::CudaCompatible,
    )
    .expect("every row-relevant embedded ASCII pattern must lower");

    assert_eq!(catalog.evidence.len(), scanner.phase2_patterns.len());
    assert_eq!(
        catalog.coverage().total_patterns,
        scanner.phase2_patterns.len()
    );
    assert_eq!(
        catalog.coverage().covered_ascii_patterns + catalog.coverage().cpu_required_patterns,
        scanner.phase2_patterns.len()
    );
    for (index, entry) in catalog.evidence.iter().enumerate() {
        assert_eq!(entry.phase2_index as usize, index);
        match entry.disposition {
            PatternCoverageDisposition::GpuCovered { shard } => {
                assert!(catalog.shards[shard as usize]
                    .phase2_indices
                    .contains(&index));
            }
            PatternCoverageDisposition::CpuRequired(reason) => {
                assert!(matches!(
                    reason,
                    CpuRequiredReason::KeywordGated
                        | CpuRequiredReason::GatePrefixed
                        | CpuRequiredReason::AsciiHomoglyphRedundant
                        | CpuRequiredReason::LoweringUnsupported
                ));
            }
        }
    }

    let bytes = catalog
        .coverage_artifact_bytes_for_test()
        .expect("coverage artifact serialization");
    catalog
        .validate_coverage_artifact_for_test(&bytes)
        .expect("coverage artifact round trip");
    let cache = Phase2GpuDfaCatalogCache::from_artifact(
        &scanner.phase2_patterns,
        &scanner.phase2_always_active_indices,
        Some("cuda"),
        &bytes,
    )
    .expect("production cache consumes validated artifact");
    let loaded = cache
        .catalog(
            &scanner.phase2_patterns,
            &scanner.phase2_always_active_indices,
            Some("cuda"),
        )
        .expect("validated artifact-backed catalog");
    assert_eq!(loaded.catalog_digest, catalog.catalog_digest);
    let mut changed_patterns = scanner.phase2_patterns.clone();
    changed_patterns.push((test_pattern("[A-Z]{7}[0-9]{5}", false), Vec::new()));
    let mut changed_always_active = scanner.phase2_always_active_indices.clone();
    changed_always_active.push(changed_patterns.len() - 1);
    let changed_error = Phase2GpuDfaCatalogCache::from_artifact(
        &changed_patterns,
        &changed_always_active,
        Some("cuda"),
        &bytes,
    )
    .expect_err("a new registry member requires rebuilt coverage evidence");
    assert!(
        changed_error.contains("detector digest") || changed_error.contains("partial"),
        "{changed_error}"
    );
}

#[test]
fn lowered_production_patterns_are_language_equivalent_over_full_fixture_matrix() {
    const MAX_CASES_PER_DETECTOR: usize = 4096;
    const MAX_CASE_BYTES_PER_DETECTOR: usize = 4 * 1024 * 1024;

    let detectors =
        keyhog_core::load_embedded_detectors_or_fail().expect("embedded detector corpus");
    let scanner =
        CompiledScanner::compile_with_gpu_policy(detectors.clone(), GpuInitPolicy::ForceDisabled)
            .expect("embedded scanner");
    let catalog = Phase2GpuDfaCatalog::build(
        &scanner.phase2_patterns,
        &scanner.phase2_always_active_indices,
        Phase2GpuDfaProgramKind::CudaCompatible,
    )
    .expect("complete production coverage");

    for entry in &catalog.evidence {
        let PatternCoverageDisposition::GpuCovered { .. } = entry.disposition else {
            continue;
        };
        let phase2_index = entry.phase2_index as usize;
        let pattern = &scanner.phase2_patterns[phase2_index].0;
        let detector = &detectors[pattern.detector_index];
        let mut fixture_count = 0usize;
        let mut fixture_bytes = 0usize;
        for fixture in &detector.tests {
            for value in [
                fixture.test_positive.as_deref(),
                fixture.test_negative.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                fixture_count = fixture_count
                    .checked_add(1)
                    .expect("fixture count overflow");
                fixture_bytes = fixture_bytes
                    .checked_add(value.len())
                    .expect("fixture byte count overflow");
            }
        }
        assert!(fixture_count <= MAX_CASES_PER_DETECTOR);
        assert!(fixture_bytes <= MAX_CASE_BYTES_PER_DETECTOR);

        let mut cases = Vec::new();
        cases
            .try_reserve(fixture_count.saturating_mul(3).saturating_add(10))
            .expect("bounded language matrix reserve");
        for fixture in &detector.tests {
            for value in [
                fixture.test_positive.as_deref(),
                fixture.test_negative.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                cases.push(value.to_owned());
                cases.push(format!("\r\n{value}\r\n"));
                cases.push(format!("λ{value}雪"));
            }
        }
        cases.extend(
            [
                "",
                "\r\n",
                "ordinary source without credentials",
                "AAAA",
                "00000000000000000000000000000000",
                "λ雪",
                "prefix\0suffix",
                "a-b_c.d/e",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        let cpu: Vec<bool> = cases
            .iter()
            .map(|case| pattern.regex.get().is_match(case))
            .collect();
        assert!(
            cpu.iter().any(|&matched| matched),
            "production covered phase-2 pattern {phase2_index} has no positive fixture"
        );
        assert!(
            cpu.iter().any(|&matched| !matched),
            "production covered phase-2 pattern {phase2_index} has no negative fixture"
        );
        let chunks: Vec<keyhog_core::Chunk> =
            cases.into_iter().map(keyhog_core::Chunk::from).collect();
        let single = Phase2GpuDfaCatalog::build_from_selected_candidates(
            &scanner.phase2_patterns,
            1,
            0,
            &[phase2_index],
            Phase2GpuDfaProgramKind::CudaCompatible,
        )
        .unwrap_or_else(|| panic!("single production pattern {phase2_index} must lower"));
        assert_eq!(
            replay_catalog_admission(&single, &chunks),
            cpu,
            "VYRE language differs from CPU regex for production phase-2 pattern {phase2_index}"
        );
    }
}

#[test]
fn coverage_artifact_rejects_corrupt_stale_partial_and_detector_changed_evidence() {
    let patterns = vec![
        (test_pattern("alpha[0-9]{4}", false), Vec::new()),
        (test_pattern("beta[A-Z]{4}", false), Vec::new()),
    ];
    let catalog = Phase2GpuDfaCatalog::build_from_selected_candidates(
        &patterns,
        patterns.len(),
        0,
        &[0, 1],
        Phase2GpuDfaProgramKind::CudaCompatible,
    )
    .expect("artifact fixture catalog");
    let bytes = catalog
        .coverage_artifact_bytes_for_test()
        .expect("artifact bytes");

    let mut corrupt = bytes.clone();
    let middle = corrupt.len() / 2;
    corrupt[middle] ^= 0x5a;
    assert!(catalog
        .validate_coverage_artifact_for_test(&corrupt)
        .is_err());

    let json = String::from_utf8(bytes.clone()).expect("JSON artifact");
    let unknown = format!("{{\"unexpected\":0,{}", &json[1..]);
    let unknown_error = catalog
        .validate_coverage_artifact_for_test(unknown.as_bytes())
        .expect_err("unknown artifact fields must fail");
    assert!(unknown_error.contains("unknown field"), "{unknown_error}");

    let stale = String::from_utf8(bytes.clone())
        .expect("JSON artifact")
        .replacen("\"version\":1", "\"version\":0", 1);
    let stale_error = catalog
        .validate_coverage_artifact_for_test(stale.as_bytes())
        .expect_err("stale artifact must fail");
    assert!(stale_error.contains("stale"), "{stale_error}");

    let partial = Phase2GpuDfaArtifact::build(catalog.detector_digest, Vec::new(), Vec::new())
        .expect("syntactically valid partial artifact")
        .encode()
        .expect("partial artifact bytes");
    assert!(catalog
        .validate_coverage_artifact_for_test(&partial)
        .is_err());

    let artifact = catalog.coverage_artifact().expect("coverage artifact");
    let mut duplicate_shards = artifact.shards.clone();
    let duplicate_index = duplicate_shards[0][0];
    duplicate_shards[0].push(duplicate_index);
    let duplicate = Phase2GpuDfaArtifact::build(
        catalog.detector_digest,
        artifact.entries.clone(),
        duplicate_shards,
    )
    .expect("digest-valid duplicate artifact")
    .encode()
    .expect("duplicate artifact bytes");
    let duplicate_error = catalog
        .validate_coverage_artifact_for_test(&duplicate)
        .expect_err("duplicate shard indices must fail");
    assert!(duplicate_error.contains("duplicate"), "{duplicate_error}");

    let mut changed_patterns = patterns.clone();
    changed_patterns.push((test_pattern("gamma[0-9]{4}", false), Vec::new()));
    let changed = Phase2GpuDfaCatalog::build_from_selected_candidates(
        &changed_patterns,
        changed_patterns.len(),
        0,
        &[0, 1, 2],
        Phase2GpuDfaProgramKind::CudaCompatible,
    )
    .expect("changed registry catalog");
    let changed_error = changed
        .validate_coverage_artifact_for_test(&bytes)
        .expect_err("new registry member must invalidate old evidence");
    assert!(changed_error.contains("detector digest"), "{changed_error}");
}
#[test]
fn generated_coverage_keeps_keyword_gated_patterns_cpu_owned() {
    let patterns = vec![
        (test_pattern("[a-z]{4}[0-9]{4}", false), Vec::new()),
        (
            test_pattern("credential[0-9]{4}", false),
            vec!["credential".to_string()],
        ),
    ];
    let catalog =
        Phase2GpuDfaCatalog::build(&patterns, &[0], Phase2GpuDfaProgramKind::CudaCompatible)
            .expect("mixed coverage catalog");

    assert!(matches!(
        catalog.evidence[0].disposition,
        PatternCoverageDisposition::GpuCovered { .. }
    ));
    assert_eq!(
        catalog.evidence[1].disposition,
        PatternCoverageDisposition::CpuRequired(CpuRequiredReason::KeywordGated)
    );
    assert_eq!(catalog.coverage().covered_ascii_patterns, 1);
    assert_eq!(catalog.coverage().cpu_required_patterns, 1);
}

#[test]
fn catalog_totals_accept_exact_ceilings_and_reject_each_one_over_boundary() {
    use lowering::{
        validate_catalog_totals, PHASE2_GPU_DFA_MAX_AGGREGATE_STATES,
        PHASE2_GPU_DFA_MAX_OUTPUT_RECORDS, PHASE2_GPU_DFA_MAX_RESIDENT_BYTES,
        PHASE2_GPU_DFA_MAX_SHARDS,
    };

    validate_catalog_totals(
        PHASE2_GPU_DFA_MAX_SHARDS,
        PHASE2_GPU_DFA_MAX_AGGREGATE_STATES,
        PHASE2_GPU_DFA_MAX_OUTPUT_RECORDS,
        PHASE2_GPU_DFA_MAX_RESIDENT_BYTES,
    )
    .expect("exact catalog ceilings are valid");
    for error in [
        validate_catalog_totals(PHASE2_GPU_DFA_MAX_SHARDS + 1, 0, 0, 0),
        validate_catalog_totals(0, PHASE2_GPU_DFA_MAX_AGGREGATE_STATES + 1, 0, 0),
        validate_catalog_totals(0, 0, PHASE2_GPU_DFA_MAX_OUTPUT_RECORDS + 1, 0),
        validate_catalog_totals(0, 0, 0, PHASE2_GPU_DFA_MAX_RESIDENT_BYTES + 1),
    ] {
        assert!(error.is_err(), "one-over ceiling must be rejected");
    }
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

    let ceiling = vyre::scan::dispatch_io::DEFAULT_MAX_SCAN_BYTES as usize;
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
#[ignore = "requires real CUDA, Metal, or WGPU hardware for full detector-corpus parity"]
fn production_gpu_routes_preserve_exact_full_detector_fixture_findings() {
    const MAX_FIXTURE_BYTES: usize = 64 * 1024 * 1024;
    const MAX_FIXTURES: usize = 100_000;

    let detectors =
        keyhog_core::load_embedded_detectors_or_fail().expect("embedded detector corpus");
    let mut fixture_count = 0usize;
    let mut fixture_bytes = 0usize;
    for detector in &detectors {
        for fixture in &detector.tests {
            for text in [
                fixture.test_positive.as_deref(),
                fixture.test_negative.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                fixture_count = fixture_count
                    .checked_add(1)
                    .expect("detector fixture count overflow");
                fixture_bytes = fixture_bytes
                    .checked_add(text.len())
                    .expect("detector fixture byte count overflow");
            }
        }
    }
    assert!(fixture_count <= MAX_FIXTURES);
    assert!(fixture_bytes <= MAX_FIXTURE_BYTES);

    let mut chunks = Vec::new();
    chunks
        .try_reserve(fixture_count)
        .expect("bounded detector fixture reserve");
    for detector in &detectors {
        for fixture in &detector.tests {
            for text in [
                fixture.test_positive.as_deref(),
                fixture.test_negative.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                chunks.push(keyhog_core::Chunk::from(text.to_owned()));
            }
        }
    }
    let scanner = CompiledScanner::compile_with_gpu_policy(detectors, GpuInitPolicy::ForceEnabled)
        .expect("scanner with GPU peers");
    let reference = scanner
        .scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback)
        .expect("CPU reference scan");
    let mut exercised = 0usize;
    for route in [
        ScanBackend::GpuCuda,
        ScanBackend::GpuMetal,
        ScanBackend::GpuWgpu,
    ] {
        if scanner.gpu_backend(route).is_none() {
            continue;
        }
        let actual = scanner
            .scan_chunks_with_backend(&chunks, route)
            .expect("selected GPU corpus scan");
        assert_eq!(actual, reference, "{} finding parity", route.label());
        exercised += 1;
    }
    assert!(
        exercised > 0,
        "hardware parity requires an acquired GPU peer"
    );
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
        .gpu_backend(route)
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

/// Two-sided control for the incomplete-catalog refusal, one variable apart.
///
/// A refusal is invisible in a trace: on the shipped corpus it fires and
/// produces no dispatches, which looks exactly like the guard not being wired
/// at all. So both arms use the SAME lowerable pattern set and the SAME
/// candidate list, and differ only in how many patterns the CPU prefilter
/// would mark. Covering all of them must build pipelines; leaving one
/// uncovered must yield no catalog, because a GPU miss that does not cover
/// every marked pattern cannot prove absence, and dispatching anyway is pure
/// cost the CPU gate has to repeat.
#[test]
fn catalog_is_refused_when_one_required_pattern_is_uncovered() {
    let patterns = forced_multi_shard_patterns();
    let candidates: Vec<usize> = (0..patterns.len()).collect();

    let covered = Phase2GpuDfaCatalog::build_from_selected_candidates(
        &patterns,
        candidates.len(),
        0,
        &candidates,
        Phase2GpuDfaProgramKind::CudaCompatible,
    )
    .expect("every required pattern is a candidate and lowers, so the proof is complete");
    assert_eq!(covered.uncovered_ascii_patterns, 0);
    assert!(
        !covered.shards.is_empty(),
        "the covered arm must actually build dispatch pipelines, otherwise the \
         refused arm below proves nothing"
    );
    assert_eq!(
        covered
            .shards
            .iter()
            .map(|shard| shard.phase2_indices.len())
            .sum::<usize>(),
        candidates.len()
    );

    // The single variable: one more pattern the CPU would mark than the GPU
    // was given to cover, the shape a gate-prefixed always-active pattern
    // produces. Nothing else changes.
    let refused = Phase2GpuDfaCatalog::build_from_selected_candidates(
        &patterns,
        candidates.len() + 1,
        0,
        &candidates,
        Phase2GpuDfaProgramKind::CudaCompatible,
    );
    assert!(
        refused.is_none(),
        "one uncovered required pattern must refuse the catalog outright; \
         returning it would let a GPU miss claim absence for a pattern the GPU \
         never scanned"
    );
}
