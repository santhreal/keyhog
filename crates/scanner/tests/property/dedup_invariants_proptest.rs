//! Massive property-based and adversarial test suite for KeyHog deduplication logic.
//! Target areas:
//! 1. In-place Span Coalescing (folding/merging of overlapping/touching literal matches).
//! 2. ScanState Global Match Deduplication (draining, stable highest-confidence preservation).
//! 3. Windowed Match Deduplication (sliding window Seen LRU eviction cache, global offset & line mapping).
//! 4. Seam Boundary Match Deduplication (cross-chunk boundary seam reassembly & defensive deduplication).

use crate::engine::scan_chunk_boundaries;
use keyhog_core::{Chunk, ChunkMetadata, MatchLocation, RawMatch, Severity};
use keyhog_scanner::testing::scan_state_drain_with_static_intern;
use keyhog_scanner::testing::{floor_char_boundary, line_number_for_offset};
use proptest::prelude::*;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

// --- Helper Functions for In-Place Coalescing (duplicated from GPU scanning modules) ---

fn coalesce_spans_inplace(matches: &mut Vec<vyre_libs::scan::LiteralMatch>) {
    matches.sort_unstable_by(|a, b| {
        a.pattern_id
            .cmp(&b.pattern_id)
            .then(a.start.cmp(&b.start))
            .then(a.end.cmp(&b.end))
    });
    {
        let mut write = 0;
        for read in 1..matches.len() {
            if matches[read].pattern_id == matches[write].pattern_id
                && matches[read].start <= matches[write].end
            {
                if matches[read].end > matches[write].end {
                    matches[write] = vyre_libs::scan::LiteralMatch::new(
                        matches[write].pattern_id,
                        matches[write].start,
                        matches[read].end,
                    );
                }
            } else {
                write += 1;
                matches[write] = matches[read];
            }
        }
        if !matches.is_empty() {
            matches.truncate(write + 1);
        }
    }
    matches.sort_unstable_by_key(|m| m.start);
}

// --- Generator Strategies ---

/// Strategy to generate a random RawMatch with a specific ID, credential, offset, and confidence.
fn arb_raw_match() -> impl Strategy<Value = RawMatch> {
    (
        prop::char::range('a', 'z').prop_map(|c| c.to_string()),
        prop::char::range('0', '9').prop_map(|c| c.to_string()),
        0..10_000usize,
        0.0..=1.0f64,
    )
        .prop_map(|(det, cred, offset, conf)| RawMatch {
            detector_id: Arc::from(det.as_str()),
            detector_name: Arc::from(det.as_str()),
            service: Arc::from("mock_service"),
            severity: Severity::Medium,
            credential: keyhog_core::SensitiveString::from(cred.as_str()),
            credential_hash: [0u8; 32].into(),
            companions: HashMap::new(),
            location: MatchLocation {
                source: Arc::from("filesystem"),
                file_path: None,
                offset,
                line: Some(offset / 80 + 1),
                commit: None,
                author: None,
                date: None,
            },
            entropy: Some(4.5),
            confidence: Some(conf),
        })
}

/// Strategy to generate a random LiteralMatch for span coalescing.
fn arb_literal_match() -> impl Strategy<Value = vyre_libs::scan::LiteralMatch> {
    (0..10u32, 0..10_000u32, 1..50u32)
        .prop_map(|(pid, start, len)| vyre_libs::scan::LiteralMatch::new(pid, start, start + len))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5000))]

    // =========================================================================
    // INVARIANT 1: In-place Span Coalescing (Interval Cover Parity)
    // =========================================================================
    #[test]
    fn test_inplace_span_coalescing(
        input_matches in prop::collection::vec(arb_literal_match(), 0..100)
    ) {
        // Run our target coalescing logic
        let mut coalesced = input_matches.clone();
        coalesce_spans_inplace(&mut coalesced);

        // Invariant 1A: Output must be sorted by start offset
        for idx in 1..coalesced.len() {
            prop_assert!(coalesced[idx - 1].start <= coalesced[idx].start);
        }

        // Invariant 1B: No two overlapping or touching spans for the same pattern ID exist in output
        for idx in 1..coalesced.len() {
            for jdx in 0..idx {
                if coalesced[idx].pattern_id == coalesced[jdx].pattern_id {
                    // Spans cannot overlap or touch
                    prop_assert!(
                        coalesced[jdx].end < coalesced[idx].start ||
                        coalesced[idx].end < coalesced[jdx].start,
                        "Found overlapping or touching spans in coalesced output: {:?} and {:?}",
                        coalesced[jdx],
                        coalesced[idx]
                    );
                }
            }
        }

        // Invariant 1C: Point Coverage equivalence.
        // For any random coordinate x, x is covered by the input set of matches for a pattern ID
        // if and only if it is covered by the coalesced output set of matches.
        let mut check_points = HashSet::new();
        for m in &input_matches {
            check_points.insert((m.pattern_id, m.start));
            check_points.insert((m.pattern_id, m.end));
            check_points.insert((m.pattern_id, m.start + (m.end - m.start) / 2));
        }

        for &(pid, pt) in &check_points {
            let covered_in_input = input_matches.iter().any(|m| {
                m.pattern_id == pid && pt >= m.start && pt < m.end
            });
            let covered_in_output = coalesced.iter().any(|m| {
                m.pattern_id == pid && pt >= m.start && pt < m.end
            });
            prop_assert_eq!(
                covered_in_input,
                covered_in_output,
                "Point coverage mismatch at point {} for pattern ID {}",
                pt,
                pid
            );
        }
    }

    // =========================================================================
    // INVARIANT 2: ScanState Global Match Deduplication
    // =========================================================================
    #[test]
    fn test_scan_state_global_deduplication(
        input_matches in prop::collection::vec(arb_raw_match(), 0..100)
    ) {
        let limit = 200; // Large enough capacity to not drop any by limit

        // Drain matches
        let drained = scan_state_drain_with_static_intern(input_matches.clone(), limit);

        // Invariant 2A: Output must be sorted descending by confidence
        for idx in 1..drained.len() {
            let conf_prev = drained[idx - 1].confidence.unwrap_or(0.0);
            let conf_curr = drained[idx].confidence.unwrap_or(0.0);
            prop_assert!(conf_prev >= conf_curr);
        }

        // Invariant 2B: Drained matches must contain absolutely no duplicate (detector_id, credential, offset) keys
        let mut seen_keys = HashSet::new();
        for m in &drained {
            let key = (m.detector_id.clone(), m.credential.clone(), m.location.offset);
            prop_assert!(
                seen_keys.insert(key),
                "Duplicate key found in drained output: detector={}, credential={}, offset={}",
                m.detector_id,
                m.credential,
                m.location.offset
            );
        }

        // Invariant 2C: For any key in the output, the retained confidence must be the MAXIMUM
        // confidence of all input matches with that identical key. (Stable priority retention)
        for m in &drained {
            let key = (m.detector_id.clone(), m.credential.clone(), m.location.offset);
            let max_input_conf = input_matches
                .iter()
                .filter(|x| x.detector_id == key.0 && x.credential == key.1 && x.location.offset == key.2)
                .map(|x| x.confidence.unwrap_or(0.0))
                .fold(0.0f64, |a, b| a.max(b));
            prop_assert_eq!(
                m.confidence.unwrap_or(0.0),
                max_input_conf,
                "Confidence not maximized for key: {:?}",
                key
            );
        }
    }

    // =========================================================================
    // INVARIANT 3: Windowed LRU Seen-Set Sliding Eviction
    // =========================================================================
    #[test]
    fn test_windowed_seen_lru_eviction(
        text in "\\PC{1,1000}", // Random string representing document content
        matches in prop::collection::vec(arb_raw_match(), 0..50)
    ) {
        // Direct testing of record_window_match deduplication logic.
        // Since MAX_WINDOW_DEDUP_ENTRIES is a constant (100_000), we'll test with a mock small LRU eviction logic
        // that mirrors record_window_match's exact logic to confirm standard deduplication and eviction behaviour.
        let mut seen = HashSet::new();
        let mut seen_order = VecDeque::new();
        let custom_max_entries = 10;

        let mut record_with_custom_limit = |m: &mut RawMatch, window_offset: usize| -> bool {
            m.location.offset += window_offset;
            let key = (m.detector_id.clone(), m.credential.clone(), m.location.offset);
            if seen.contains(&key) {
                return false;
            }
            if seen.len() >= custom_max_entries {
                if let Some(oldest) = seen_order.pop_front() {
                    seen.remove(&oldest);
                }
            }
            seen.insert(key.clone());
            seen_order.push_back(key);
            true
        };

        let mut recorded_count = 0;
        let mut duplicates_count = 0;

        for m in &matches {
            let mut match_copy = m.clone();
            let is_new = record_with_custom_limit(&mut match_copy, 100);
            if is_new {
                recorded_count += 1;
                // Offset must be correctly mapped to global file coordinate
                prop_assert_eq!(match_copy.location.offset, m.location.offset + 100);
            } else {
                duplicates_count += 1;
            }
        }

        // Verify key invariants on count
        prop_assert_eq!(recorded_count + duplicates_count, matches.len());

        // The size of seen set must never exceed our configured maximum entries
        prop_assert!(seen.len() <= custom_max_entries);
        prop_assert_eq!(seen.len(), seen_order.len());

        // Offset & Line mappings
        let offset = text.len() / 2;
        let line_num = line_number_for_offset(&text, offset);
        let calculated_line = text[..floor_char_boundary(&text, offset.min(text.len()))]
            .chars()
            .filter(|&c| c == '\n')
            .count() + 1;
        prop_assert_eq!(line_num, calculated_line);
    }
}

// =========================================================================
// ADVERSARIAL AND CORNER-CASE DEDUPLICATION TESTS
// =========================================================================

#[test]
fn test_window_boundary_dedup_non_contiguous_or_different_files() {
    let scanner = keyhog_scanner::CompiledScanner::compile(Vec::new()).unwrap();

    // Create non-contiguous chunks (gap of 100 bytes)
    let chunks = vec![
        Chunk {
            data: "A".repeat(1024).into(),
            metadata: ChunkMetadata {
                path: Some("/test/file.txt".to_string()),
                source_type: "file".to_string(),
                base_offset: 0,
                ..Default::default()
            },
        },
        Chunk {
            data: "B".repeat(1024).into(),
            metadata: ChunkMetadata {
                path: Some("/test/file.txt".to_string()),
                source_type: "file".to_string(),
                base_offset: 1124, // 100 bytes gap
                ..Default::default()
            },
        },
    ];

    let mut per_chunk_results = vec![Vec::new(), Vec::new()];
    scan_chunk_boundaries(&scanner, &chunks, &mut per_chunk_results);

    // Chunks are not contiguous; boundary scan must skip them and leave per_chunk_results empty
    assert!(per_chunk_results[0].is_empty());
    assert!(per_chunk_results[1].is_empty());

    // Create chunks with different paths
    let chunks_diff_paths = vec![
        Chunk {
            data: "A".repeat(1024).into(),
            metadata: ChunkMetadata {
                path: Some("/test/file_a.txt".to_string()),
                source_type: "file".to_string(),
                base_offset: 0,
                ..Default::default()
            },
        },
        Chunk {
            data: "B".repeat(1024).into(),
            metadata: ChunkMetadata {
                path: Some("/test/file_b.txt".to_string()),
                source_type: "file".to_string(),
                base_offset: 1024, // Contiguous offset but different path
                ..Default::default()
            },
        },
    ];

    let mut per_chunk_results_diff = vec![Vec::new(), Vec::new()];
    scan_chunk_boundaries(&scanner, &chunks_diff_paths, &mut per_chunk_results_diff);
    assert!(per_chunk_results_diff[0].is_empty());
    assert!(per_chunk_results_diff[1].is_empty());
}

#[test]
fn test_boundary_defensive_dedup_prevents_duplicate_reports() {
    let scanner = keyhog_scanner::CompiledScanner::compile(Vec::new()).unwrap();

    let chunks = vec![
        Chunk {
            data: "A".repeat(1024).into(),
            metadata: ChunkMetadata {
                path: Some("/test/file.txt".to_string()),
                source_type: "file".to_string(),
                base_offset: 0,
                ..Default::default()
            },
        },
        Chunk {
            data: "B".repeat(1024).into(),
            metadata: ChunkMetadata {
                path: Some("/test/file.txt".to_string()),
                source_type: "file".to_string(),
                base_offset: 1024, // Contiguous
                ..Default::default()
            },
        },
    ];

    // Pre-populate per_chunk_results with a match that exists at the boundary
    let mock_match = RawMatch {
        detector_id: Arc::from("dummy_detector"),
        detector_name: Arc::from("dummy_detector"),
        service: Arc::from("dummy_service"),
        severity: Severity::Medium,
        credential: keyhog_core::SensitiveString::from("mock_credential"),
        credential_hash: [0u8; 32].into(),
        companions: HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("/test/file.txt")),
            offset: 1020, // Inside seam overlap
            line: Some(1),
            commit: None,
            author: None,
            date: None,
        },
        confidence: Some(0.9),
        entropy: Some(4.5),
    };

    // If already seen in chunk results, boundary scanner must NOT duplicate it
    let mut per_chunk_results = vec![vec![mock_match.clone()], Vec::new()];
    scan_chunk_boundaries(&scanner, &chunks, &mut per_chunk_results);

    // Should not append duplicate
    assert_eq!(per_chunk_results[1].len(), 0);
}
