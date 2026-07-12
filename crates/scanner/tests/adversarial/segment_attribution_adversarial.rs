//! Adversarial tests for segment attribution.
//!
//! Exercises edge cases in the segment attribution logic: empty inputs,
//! overlapping segments, boundary matches, overflow conditions, and
//! ordering violations.

use keyhog_scanner::testing::segment_attribution::{
    map_offsets_to_segments, AttributedMatch, GlobalMatch, Segment, SegmentAttributionError,
};

// ────────────────────────────────────────────────────────────
// Empty inputs
// ────────────────────────────────────────────────────────────

#[test]
fn empty_segments_empty_matches() {
    let result = map_offsets_to_segments(&[], &[]);
    assert!(result.is_ok());
    let attributed = result.unwrap();
    assert!(attributed.is_empty());
}

#[test]
fn empty_segments_with_matches() {
    let matches = [GlobalMatch {
        start: 0,
        end: 5,
        pattern_id: 0,
    }];
    let result = map_offsets_to_segments(&[], &matches);
    // Should return Ok with no attributions (no segments to map to).
    assert!(result.is_ok());
    let attributed = result.unwrap();
    assert!(attributed.is_empty());
}

#[test]
fn segments_with_empty_matches() {
    let segments = [Segment::new(0, 0, 100)];
    let result = map_offsets_to_segments(&segments, &[]);
    assert!(result.is_ok());
    let attributed = result.unwrap();
    assert!(attributed.is_empty());
}

// ────────────────────────────────────────────────────────────
// Single segment, single match
// ────────────────────────────────────────────────────────────

#[test]
fn match_fully_inside_segment() {
    let segments = [Segment::new(0, 0, 100)];
    let matches = [GlobalMatch {
        start: 10,
        end: 20,
        pattern_id: 0,
    }];
    let result = map_offsets_to_segments(&segments, &matches);
    assert!(result.is_ok());
    let attributed = result.unwrap();
    assert_eq!(attributed.len(), 1);
    assert_eq!(attributed[0].segment_id, 0);
}

#[test]
fn match_at_segment_start() {
    let segments = [Segment::new(0, 0, 100)];
    let matches = [GlobalMatch {
        start: 0,
        end: 5,
        pattern_id: 0,
    }];
    let result = map_offsets_to_segments(&segments, &matches);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 1);
}

#[test]
fn match_at_segment_end() {
    let segments = [Segment::new(0, 0, 100)];
    let matches = [GlobalMatch {
        start: 95,
        end: 100,
        pattern_id: 0,
    }];
    let result = map_offsets_to_segments(&segments, &matches);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 1);
}

// ────────────────────────────────────────────────────────────
// Match spanning segment boundary
// ────────────────────────────────────────────────────────────

#[test]
fn match_spanning_two_segments() {
    let segments = [Segment::new(0, 0, 50), Segment::new(1, 50, 50)];
    let matches = [GlobalMatch {
        start: 45,
        end: 55,
        pattern_id: 0,
    }];
    let result = map_offsets_to_segments(&segments, &matches);
    // A match [45,55) that spills across the boundary is fully contained in
    // NEITHER segment ([0,50) nor [50,100)), so the attributor drops it — it only
    // rewrites matches that fit wholly inside a single segment. Assert that exact
    // behaviour: Ok, but no attributed match.
    let attributed = result.expect("valid segments must not error");
    assert!(
        attributed.is_empty(),
        "a boundary-spanning match must be attributed to neither segment; got {attributed:?}"
    );
}

// ────────────────────────────────────────────────────────────
// Overlapping segments
// ────────────────────────────────────────────────────────────

#[test]
fn overlapping_segments() {
    let segments = [
        Segment::new(0, 0, 60),
        Segment::new(1, 40, 60), // overlaps with segment 0
    ];
    let matches = [GlobalMatch {
        start: 50,
        end: 55,
        pattern_id: 0,
    }];
    let result = map_offsets_to_segments(&segments, &matches);
    // Overlapping segments are rejected at validation stage.
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        SegmentAttributionError::SegmentsOverlap {
            previous_index: 0,
            segment_index: 1,
            previous_end: 60,
            start: 40,
        }
    );
}

// ────────────────────────────────────────────────────────────
// Zero-length segments
// ────────────────────────────────────────────────────────────

#[test]
fn zero_length_segment() {
    let segments = [
        Segment::new(0, 50, 0), // zero length
        Segment::new(1, 50, 100),
    ];
    let matches = [GlobalMatch {
        start: 50,
        end: 55,
        pattern_id: 0,
    }];
    let result = map_offsets_to_segments(&segments, &matches);
    // The zero-length segment 0 ([50,50)) is skipped; the match [50,55) attributes
    // to the real segment 1 ([50,150)) as segment-local offsets [0,5). Assert the
    // exact attribution, not merely "did not panic".
    assert_eq!(
        result.expect("valid segments must not error"),
        vec![AttributedMatch::new(1, 0, 0, 5)],
        "match must attribute to the non-empty segment (id 1), skipping the zero-length one"
    );
}

// ────────────────────────────────────────────────────────────
// Overflow conditions
// ────────────────────────────────────────────────────────────

#[test]
fn segment_at_u32_max() {
    // Segment near u32::MAX — tests overflow safety.
    let segments = [Segment::new(0, u32::MAX - 10, 10)];
    let matches = [GlobalMatch {
        start: u32::MAX - 5,
        end: u32::MAX,
        pattern_id: 0,
    }];
    let result = map_offsets_to_segments(&segments, &matches);
    // Should handle without overflow panic.
    assert!(result.is_ok());
}

#[test]
fn segment_end_overflows_u32() {
    // start + len would overflow u32.
    let segments = [Segment::new(0, u32::MAX, 1)];
    let result = map_offsets_to_segments(&segments, &[]);
    // `start + len` = u32::MAX + 1 overflows. Segment validation runs UPFRONT
    // (`validate_segments` before any match is processed), so this ALWAYS errors
    // regardless of the empty match slice — the previous "Ok also acceptable" arm
    // was wrong. Assert the exact error, including its fields.
    assert_eq!(
        result.unwrap_err(),
        SegmentAttributionError::SegmentEndOverflow {
            segment_index: 0,
            start: u32::MAX,
            len: 1,
        }
    );
}

// ────────────────────────────────────────────────────────────
// Multiple segments, multiple matches
// ────────────────────────────────────────────────────────────

#[test]
fn many_segments_many_matches() {
    let segments: Vec<Segment> = (0..100).map(|i| Segment::new(i, i * 100, 100)).collect();
    let matches: Vec<GlobalMatch> = (0..100)
        .map(|i| GlobalMatch {
            start: i * 100 + 10,
            end: i * 100 + 20,
            pattern_id: i,
        })
        .collect();
    let result = map_offsets_to_segments(&segments, &matches);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 100);
}

// ────────────────────────────────────────────────────────────
// Duplicate segments
// ────────────────────────────────────────────────────────────

#[test]
fn duplicate_segments_same_range() {
    let segments = [
        Segment::new(0, 0, 100),
        Segment::new(1, 0, 100), // exact duplicate range
    ];
    let matches = [GlobalMatch {
        start: 50,
        end: 60,
        pattern_id: 0,
    }];
    let result = map_offsets_to_segments(&segments, &matches);
    // Exact duplicate ranges overlap and are rejected at validation stage.
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        SegmentAttributionError::SegmentsOverlap {
            previous_index: 0,
            segment_index: 1,
            previous_end: 100,
            start: 0,
        }
    );
}

// ────────────────────────────────────────────────────────────
// Match outside all segments
// ────────────────────────────────────────────────────────────

#[test]
fn match_outside_all_segments() {
    let segments = [Segment::new(0, 0, 50)];
    let matches = [GlobalMatch {
        start: 60,
        end: 70,
        pattern_id: 0,
    }];
    let result = map_offsets_to_segments(&segments, &matches);
    assert!(result.is_ok());
    // Match is outside the segment — should not be attributed.
    assert!(result.unwrap().is_empty());
}
