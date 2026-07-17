use super::super::gpu_region_batch::{
    build_region_presence_batch, validate_region_presence_batch_len, validation_window_range,
    with_region_presence_batch, RegionPresenceBatchMode, RegionPresenceScratch,
    ZeroRegionPresenceScratch, REGION_PRESENCE_BATCH_BYTE_LIMIT,
};
use super::*;

#[test]
fn region_presence_batch_lowercases_separates_and_clears_scratch() {
    let chunks = [
        keyhog_core::Chunk::from("GhP_TOKEN"),
        keyhog_core::Chunk::from("Zz9"),
    ];
    let mut scratch = RegionPresenceScratch::default();

    {
        let mut guard = ZeroRegionPresenceScratch::new(&mut scratch);
        build_region_presence_batch(&chunks, guard.as_mut()).expect("batch");
        assert_eq!(guard.haystack(), b"ghp_token\0zz9");
        assert_eq!(guard.region_starts(), &[0, 10]);
    }

    assert!(scratch.is_empty());
}

#[test]
fn region_presence_batch_borrows_single_chunk_when_folded_source_is_identical() {
    let chunks = [keyhog_core::Chunk::from("ghp_lowercase_token_123")];
    let source_ptr = chunks[0].data.as_bytes().as_ptr();

    with_region_presence_batch(&chunks, |haystack, region_starts, mode| {
        assert_eq!(mode, RegionPresenceBatchMode::BorrowedSingleChunk);
        assert_eq!(haystack, chunks[0].data.as_bytes());
        assert_eq!(haystack.as_ptr(), source_ptr);
        assert_eq!(region_starts, &[0]);
        Ok(())
    })
    .expect("borrowed single-chunk batch");
}

#[test]
fn region_presence_batch_uses_folded_scratch_when_case_fold_changes_bytes() {
    let chunks = [keyhog_core::Chunk::from("GhP_TOKEN")];
    let source_ptr = chunks[0].data.as_bytes().as_ptr();

    with_region_presence_batch(&chunks, |haystack, region_starts, mode| {
        assert_eq!(mode, RegionPresenceBatchMode::FoldedScratch);
        assert_eq!(haystack, b"ghp_token");
        assert_ne!(haystack.as_ptr(), source_ptr);
        assert_eq!(region_starts, &[0]);
        Ok(())
    })
    .expect("folded single-chunk batch");
}

#[test]
fn region_presence_batch_enforces_the_real_vyre_scan_ceiling() {
    assert_eq!(
        REGION_PRESENCE_BATCH_BYTE_LIMIT,
        vyre_libs::scan::dispatch_io::DEFAULT_MAX_SCAN_BYTES as usize
    );
    assert!(validate_region_presence_batch_len(REGION_PRESENCE_BATCH_BYTE_LIMIT).is_ok());
    let error = validate_region_presence_batch_len(REGION_PRESENCE_BATCH_BYTE_LIMIT + 1)
        .expect_err("ceiling plus one must fail before allocation");
    assert!(error.contains("VYRE") && error.contains("Fix:"), "{error}");
}

#[test]
fn validation_window_range_preserves_utf8_boundaries() {
    let text = "αβghp_secretδ";
    let (start, end) = validation_window_range(text, 6, 5).expect("window");

    assert!(text.is_char_boundary(start));
    assert!(text.is_char_boundary(end));
    assert!(text[start..end].contains("ghp"));
}

#[test]
fn bounded_gpu_firing_rejects_window_miss_without_full_chunk_scan() {
    let rx = regex::Regex::new(r"SECRET-[0-9]{4}").expect("regex");
    let text = "prefix bait hit here\n\nlots of filler\n\nSECRET-1234";
    let distant_match_offset = text.find("SECRET-1234").expect("match");

    assert!(
        validate_detector_match(
            text,
            &rx,
            Some(distant_match_offset),
            Some("SECRET-1234".len())
        ),
        "bounded validator must accept a real local match"
    );
    assert!(
        !validate_detector_match(text, &rx, Some(0), Some("SECRET-1234".len())),
        "bounded GPU over-fire validation must not fall back to a full-chunk \
             regex scan after the local window misses"
    );
}

#[test]
fn unbounded_and_cpu_floor_validation_keep_full_chunk_oracle() {
    let rx = regex::Regex::new(r"SECRET=.*END").expect("regex");
    let text = "prefix bait hit here\nSECRET=abc123END";

    assert!(
        validate_detector_match(text, &rx, Some(0), None),
        "unbounded detector validation keeps the full prepared-chunk oracle"
    );
    assert!(
        validate_detector_match(text, &rx, None, Some(8)),
        "CPU recall-floor validation has no GPU offset, so it keeps the full \
             prepared-chunk oracle"
    );
}

#[test]
fn bounded_validation_source_has_no_old_full_chunk_regex_scan() {
    let src = include_str!("../../src/engine/gpu_region_dispatch.rs");
    let old_full_chunk_regex_scan = ["rx.is_match", "(text.as_str())"].concat();
    assert!(
        !src.contains(&old_full_chunk_regex_scan),
        "bounded GPU firing validation must not run a full prepared-chunk regex \
             scan after its local proof window misses"
    );
}

#[test]
fn coalesce_rate_reports_zero_for_zero_duration() {
    assert_eq!(
        mib_per_second(8 * 1024 * 1024, std::time::Duration::ZERO),
        0.0
    );
    assert_eq!(mib_per_second(0, std::time::Duration::from_secs(1)), 0.0);
}

#[test]
fn phase2_gpu_admission_workload_uses_original_slice_when_every_row_is_eligible() {
    let chunks = [
        keyhog_core::Chunk::from("phase-one-triggered"),
        keyhog_core::Chunk::from("no-phase-one-trigger"),
    ];

    let workload = build_phase2_gpu_admission_workload(&chunks);

    let Phase2GpuAdmissionWorkload::Full {
        chunks: selected_chunks,
    } = workload
    else {
        panic!("an all-eligible batch must retain the original chunk slice");
    };
    assert_eq!(selected_chunks.as_ptr(), chunks.as_ptr());
    assert_eq!(selected_chunks.len(), chunks.len());
}

#[test]
fn phase2_gpu_admission_workload_filter_keeps_eligible_triggered_and_untriggered_rows() {
    let chunks = [
        keyhog_core::Chunk::from("oversized-or-non-ascii"),
        keyhog_core::Chunk::from("eligible-triggered"),
        keyhog_core::Chunk::from("eligible-untriggered"),
        keyhog_core::Chunk::from("decode-only"),
    ];

    let workload =
        build_phase2_gpu_admission_workload_filtered(&chunks, |idx, _| matches!(idx, 1 | 2));

    let Phase2GpuAdmissionWorkload::Subset {
        indices,
        chunks: selected_chunks,
        full_len,
    } = workload
    else {
        panic!("mixed eligibility must build a mapped subset workload");
    };
    assert_eq!(full_len, 4);
    assert_eq!(indices, vec![1, 2]);
    assert_eq!(selected_chunks[0].data.as_ref(), "eligible-triggered");
    assert_eq!(selected_chunks[1].data.as_ref(), "eligible-untriggered");
}

#[test]
fn phase2_gpu_admission_workload_preserves_eligible_prefix_before_exclusion() {
    let chunks = [
        keyhog_core::Chunk::from("eligible-before"),
        keyhog_core::Chunk::from("excluded-after"),
    ];

    let workload = build_phase2_gpu_admission_workload_filtered(&chunks, |idx, _| idx == 0);

    let Phase2GpuAdmissionWorkload::Subset {
        indices,
        chunks: selected_chunks,
        full_len,
    } = workload
    else {
        panic!("an eligible prefix before an exclusion must remain in the mapped subset");
    };
    assert_eq!(full_len, chunks.len());
    assert_eq!(indices, vec![0]);
    assert_eq!(selected_chunks.len(), 1);
    assert_eq!(selected_chunks[0].data.as_ref(), "eligible-before");
}

#[test]
fn phase2_gpu_admission_workload_filter_is_empty_when_every_row_is_excluded() {
    let chunks = [
        keyhog_core::Chunk::from("decode-only-a"),
        keyhog_core::Chunk::from("decode-only-b"),
    ];
    let workload = build_phase2_gpu_admission_workload_filtered(&chunks, |_, _| false);

    let Phase2GpuAdmissionWorkload::Empty = workload else {
        panic!("an all-excluded batch must not dispatch phase-2 GPU admission");
    };
}

#[test]
fn phase2_gpu_trigger_row_mismatch_is_rejected() {
    let error = validate_phase2_gpu_trigger_rows(4, 3).expect_err("mismatched rows rejected");

    assert!(
        error
            .to_string()
            .contains("refusing to run mismatched phase-2 admission"),
        "trigger/chunk cardinality drift must be a loud GPU route failure"
    );
}

#[test]
fn phase2_gpu_admission_expands_subset_bits_to_original_batch() {
    let subset = Phase2GpuDfaAdmission {
        admitted: vec![true, false, true],
        complete: vec![true, true, true],
        matches_seen: 7,
    };

    let full = expand_phase2_gpu_admission(subset, &[1, 3, 4], 5);

    assert_eq!(full.admitted, vec![false, true, false, false, true]);
    assert_eq!(full.complete, vec![false, true, false, true, true]);
    assert_eq!(full.matches_seen, 7);
}

#[test]
fn phase2_gpu_admission_length_mismatch_marks_evidence_incomplete() {
    let subset = Phase2GpuDfaAdmission {
        admitted: vec![true],
        complete: vec![true],
        matches_seen: 1,
    };

    let full = expand_phase2_gpu_admission(subset, &[0, 2], 3);

    assert_eq!(full.admitted, vec![true, false, false]);
    assert!(
        full.complete.iter().all(|&complete| !complete),
        "mismatched subset evidence must not claim complete GPU admission coverage"
    );
}

#[cfg(feature = "simd")]
#[test]
fn complete_always_active_negative_preserves_triggered_row_keyword_phase2_findings() {
    let detector = keyhog_core::DetectorSpec {
        id: "triggered-row-phase2-keyword".into(),
        name: "Triggered Row Phase Two Keyword".into(),
        service: "fixture".into(),
        severity: keyhog_core::Severity::High,
        keywords: vec!["credential".into()],
        patterns: vec![keyhog_core::PatternSpec {
            regex: r"(?:^|[^A-Za-z0-9])([A-Za-z0-9]{32})(?:$|[^A-Za-z0-9])".into(),
            group: Some(1),
            ..Default::default()
        }],
        ..Default::default()
    };
    let scanner = CompiledScanner::compile(vec![detector]).expect("compile fixture detector");
    let chunk = keyhog_core::Chunk::from("credential = aB3dE5gH7jK9mN2pQ4sT6vW8xY1zC0fR");
    let keyword_idx = scanner
        .phase2_keyword_ac
        .as_ref()
        .expect("phase-two keyword index")
        .find_iter("credential")
        .next()
        .expect("fixture keyword")
        .pattern()
        .as_u32();
    let keyword_hints = [vec![keyword_idx]];
    let admitted = [false];
    let complete = [true];
    let anchors_present = [false];

    let results = scanner.scan_coalesced_phase2_with_admission(
        std::slice::from_ref(&chunk),
        vec![Some(vec![1])],
        Some(&admitted),
        Some(&complete),
        Some(&keyword_hints),
        Some(&anchors_present),
        None,
        None,
    );

    let found = results[0]
        .iter()
        .find(|finding| finding.detector_id.as_ref() == "triggered-row-phase2-keyword")
        .expect("complete always-active absence must not suppress keyword-triggered phase two");
    assert_eq!(
        found.credential.as_ref(),
        "aB3dE5gH7jK9mN2pQ4sT6vW8xY1zC0fR"
    );
}

#[cfg(feature = "simd")]
#[test]
fn normalized_triggered_rows_discard_raw_gpu_evidence_and_recompute_admission() {
    let detectors = vec![
        keyhog_core::DetectorSpec {
            id: "raw-trigger-fixture".into(),
            name: "Raw trigger fixture".into(),
            service: "fixture".into(),
            severity: keyhog_core::Severity::High,
            patterns: vec![keyhog_core::PatternSpec {
                regex: r"(rawhit_[A-Z]{4})".into(),
                group: Some(1),
                ..Default::default()
            }],
            ..Default::default()
        },
        keyhog_core::DetectorSpec {
            id: "normalized-required-fixture".into(),
            name: "Normalized required fixture".into(),
            service: "fixture".into(),
            severity: keyhog_core::Severity::High,
            patterns: vec![keyhog_core::PatternSpec {
                regex: r"([a-f0-9]{8}:fx)".into(),
                group: Some(1),
                required_literals: vec![":fx".into()],
                ..Default::default()
            }],
            ..Default::default()
        },
        keyhog_core::DetectorSpec {
            id: "normalized-phase2-keyword-fixture".into(),
            name: "Normalized phase two keyword fixture".into(),
            service: "fixture".into(),
            severity: keyhog_core::Severity::High,
            keywords: vec!["credential".into()],
            patterns: vec![keyhog_core::PatternSpec {
                regex: r"(?:^|[^A-Za-z0-9])([A-Za-z0-9]{32})(?:$|[^A-Za-z0-9])".into(),
                group: Some(1),
                ..Default::default()
            }],
            ..Default::default()
        },
    ];
    let scanner = CompiledScanner::compile(detectors).expect("compile normalization fixtures");
    let chunk = keyhog_core::Chunk::from(concat!(
        "rawhit_ABCD\n",
        "required=0123abcd:\u{ff46}\u{ff58}\n",
        "\u{ff43}\u{ff52}\u{ff45}\u{ff44}\u{ff45}\u{ff4e}\u{ff54}\u{ff49}\u{ff41}\u{ff4c}",
        " = aB3dE5gH7jK9mN2pQ4sT6vW8xY1zC0fR\n"
    ));
    let raw_triggers = scanner
        .collect_triggered_patterns_for_backend(&chunk.data, crate::hw_probe::ScanBackend::SimdCpu);
    assert!(raw_triggers.iter().any(|&word| word != 0));
    let raw_keyword_hints = [Vec::<u32>::new()];
    let admitted = [false];
    let complete = [true];
    let anchors_present = [false];

    let results = scanner.scan_coalesced_phase2_with_admission(
        std::slice::from_ref(&chunk),
        vec![Some(raw_triggers)],
        Some(&admitted),
        Some(&complete),
        Some(&raw_keyword_hints),
        Some(&anchors_present),
        None,
        None,
    );
    let by_detector = |detector: &str| {
        results[0]
            .iter()
            .find(|finding| finding.detector_id.as_ref() == detector)
            .unwrap_or_else(|| panic!("missing normalized finding for {detector}"))
    };

    assert_eq!(
        by_detector("normalized-required-fixture")
            .credential
            .as_ref(),
        "0123abcd:fx"
    );
    assert_eq!(
        by_detector("normalized-phase2-keyword-fixture")
            .credential
            .as_ref(),
        "aB3dE5gH7jK9mN2pQ4sT6vW8xY1zC0fR"
    );
}
