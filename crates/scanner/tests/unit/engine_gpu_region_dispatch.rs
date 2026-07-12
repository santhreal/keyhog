use super::super::gpu_region_batch::{
    build_region_presence_batch, validation_window_range, with_region_presence_batch,
    RegionPresenceBatchMode, RegionPresenceScratch, ZeroRegionPresenceScratch,
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
fn phase2_gpu_admission_workload_keeps_only_no_trigger_chunks() {
    let chunks = [
        keyhog_core::Chunk::from("already-triggered"),
        keyhog_core::Chunk::from("no-trigger-none"),
        keyhog_core::Chunk::from("no-trigger-zero-row"),
        keyhog_core::Chunk::from("also-triggered"),
    ];
    let triggers = vec![Some(vec![1]), None, Some(vec![0]), Some(vec![0, 8])];

    let workload = build_phase2_gpu_admission_workload(&chunks, &triggers);

    let Phase2GpuAdmissionWorkload::Subset {
        indices,
        chunks: selected_chunks,
        full_len,
    } = workload
    else {
        panic!("mixed triggered/no-trigger batch must build subset workload");
    };
    assert_eq!(full_len, 4);
    assert_eq!(indices, vec![1, 2]);
    assert_eq!(selected_chunks.len(), 2);
    assert_eq!(selected_chunks[0].data.as_ref(), "no-trigger-none");
    assert_eq!(selected_chunks[1].data.as_ref(), "no-trigger-zero-row");
}

#[test]
fn phase2_gpu_admission_workload_uses_original_slice_for_all_no_trigger_chunks() {
    let chunks = [
        keyhog_core::Chunk::from("no-trigger-none"),
        keyhog_core::Chunk::from("no-trigger-zero-row"),
    ];
    let triggers = vec![None, Some(vec![0])];

    let workload = build_phase2_gpu_admission_workload(&chunks, &triggers);

    let Phase2GpuAdmissionWorkload::Full {
        chunks: selected_chunks,
    } = workload
    else {
        panic!("all no-trigger batch must use full-slice workload");
    };
    assert_eq!(selected_chunks.as_ptr(), chunks.as_ptr());
    assert_eq!(selected_chunks.len(), chunks.len());
}

#[test]
fn phase2_gpu_admission_workload_preserves_prefix_no_trigger_chunks() {
    let chunks = [
        keyhog_core::Chunk::from("no-trigger-before"),
        keyhog_core::Chunk::from("triggered"),
    ];
    let triggers = vec![None, Some(vec![1])];

    let workload = build_phase2_gpu_admission_workload(&chunks, &triggers);

    let Phase2GpuAdmissionWorkload::Subset {
        indices,
        chunks: selected_chunks,
        full_len,
    } = workload
    else {
        panic!("no-trigger prefix before a triggered chunk must remain in subset workload");
    };
    assert_eq!(full_len, chunks.len());
    assert_eq!(indices, vec![0]);
    assert_eq!(selected_chunks.len(), 1);
    assert_eq!(selected_chunks[0].data.as_ref(), "no-trigger-before");
}

#[test]
fn phase2_gpu_admission_workload_filter_skips_decode_only_rows() {
    let chunks = [
        keyhog_core::Chunk::from("decode-only-unicode-escape"),
        keyhog_core::Chunk::from("ordinary-no-trigger"),
        keyhog_core::Chunk::from("already-triggered"),
    ];
    let triggers = vec![None, None, Some(vec![1])];

    let workload =
        build_phase2_gpu_admission_workload_filtered(&chunks, &triggers, |idx, _| idx != 0);

    let Phase2GpuAdmissionWorkload::Subset {
        indices,
        chunks: selected_chunks,
        full_len,
    } = workload
    else {
        panic!("filtered no-trigger batch must build subset workload");
    };
    assert_eq!(full_len, chunks.len());
    assert_eq!(indices, vec![1]);
    assert_eq!(selected_chunks.len(), 1);
    assert_eq!(selected_chunks[0].data.as_ref(), "ordinary-no-trigger");
}

#[test]
fn phase2_gpu_admission_workload_filter_empty_when_all_no_trigger_rows_skipped() {
    let chunks = [
        keyhog_core::Chunk::from("decode-only-a"),
        keyhog_core::Chunk::from("decode-only-b"),
    ];
    let triggers = vec![None, Some(vec![0])];

    let workload = build_phase2_gpu_admission_workload_filtered(&chunks, &triggers, |_, _| false);

    let Phase2GpuAdmissionWorkload::Empty = workload else {
        panic!("all filtered no-trigger rows must skip phase-2 GPU DFA dispatch");
    };
}

#[test]
fn phase2_gpu_admission_workload_skips_gpu_dfa_when_every_chunk_already_triggered() {
    let chunks = [
        keyhog_core::Chunk::from("triggered"),
        keyhog_core::Chunk::from("also-triggered"),
    ];
    let triggers = vec![Some(vec![1]), Some(vec![0, 8])];

    let workload = build_phase2_gpu_admission_workload(&chunks, &triggers);

    let Phase2GpuAdmissionWorkload::Empty = workload else {
        panic!("all-triggered batch must skip phase-2 GPU DFA dispatch");
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
        complete: true,
        matches_seen: 7,
        marked: Vec::new(),
    };

    let full = expand_phase2_gpu_admission(subset, &[1, 3, 4], 5);

    assert_eq!(full.admitted, vec![false, true, false, false, true]);
    assert!(full.complete);
    assert_eq!(full.matches_seen, 7);
}

#[test]
fn phase2_gpu_admission_length_mismatch_marks_evidence_incomplete() {
    let subset = Phase2GpuDfaAdmission {
        admitted: vec![true],
        complete: true,
        matches_seen: 1,
        marked: Vec::new(),
    };

    let full = expand_phase2_gpu_admission(subset, &[0, 2], 3);

    assert_eq!(full.admitted, vec![true, false, false]);
    assert!(
        !full.complete,
        "mismatched subset evidence must not claim complete GPU admission coverage"
    );
}
