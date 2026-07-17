use super::*;
use crate::GpuInitPolicy;

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
    let mut state = 0u32;
    for (pos, &byte) in scratch.haystack.iter().enumerate() {
        state = dfa.transitions[(state as usize) * 256 + byte as usize];
        let begin = dfa.output_offsets[state as usize] as usize;
        let end = dfa.output_offsets[state as usize + 1] as usize;
        for &pattern_id in &dfa.output_records[begin..end] {
            let pattern_len = match shard.pipeline.pattern_lengths.get(pattern_id as usize) {
                Some(&value) => value,
                None => {
                    panic!(
                        "replayed GPU DFA emitted pattern id {} outside pattern_lengths len {}",
                        pattern_id,
                        shard.pipeline.pattern_lengths.len()
                    )
                }
            };
            let end_offset = (pos as u32).saturating_add(1);
            let start_offset = end_offset.saturating_sub(pattern_len);
            if let Some(region) = match_region(
                &scratch.region_starts,
                scratch.haystack.len(),
                start_offset,
                end_offset,
            ) {
                if let Some(slot) = admitted.get_mut(region) {
                    *slot = true;
                }
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
