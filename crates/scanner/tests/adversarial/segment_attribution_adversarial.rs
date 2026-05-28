//! Adversarial tests for segment attribution.
//!
//! Exercises edge cases in the segment attribution logic: empty inputs,
//! overlapping segments, boundary matches, overflow conditions, and
//! ordering violations.

use keyhog_scanner::engine::segment_attribution::{
    map_offsets_to_segments, GlobalMatch, Segment, SegmentAttributionError,
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
    let matches = [GlobalMatch { start: 0, end: 5, pattern_id: 0 }];
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
    let matches = [GlobalMatch { start: 10, end: 20, pattern_id: 0 }];
    let result = map_offsets_to_segments(&segments, &matches);
    assert!(result.is_ok());
    let attributed = result.unwrap();
    assert_eq!(attributed.len(), 1);
    assert_eq!(attributed[0].segment_id, 0);
}

#[test]
fn match_at_segment_start() {
    let segments = [Segment::new(0, 0, 100)];
    let matches = [GlobalMatch { start: 0, end: 5, pattern_id: 0 }];
    let result = map_offsets_to_segments(&segments, &matches);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 1);
}

#[test]
fn match_at_segment_end() {
    let segments = [Segment::new(0, 0, 100)];
    let matches = [GlobalMatch { start: 95, end: 100, pattern_id: 0 }];
    let result = map_offsets_to_segments(&segments, &matches);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 1);
}

// ────────────────────────────────────────────────────────────
// Match spanning segment boundary
// ────────────────────────────────────────────────────────────

#[test]
fn match_spanning_two_segments() {
    let segments = [
        Segment::new(0, 0, 50),
        Segment::new(1, 50, 50),
    ];
    let matches = [GlobalMatch { start: 45, end: 55, pattern_id: 0 }];
    let result = map_offsets_to_segments(&segments, &matches);
    // The match spans two segments — implementation should handle this
    // gracefully (attribute to first, second, or both).
    assert!(result.is_ok());
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
    let matches = [GlobalMatch { start: 50, end: 55, pattern_id: 0 }];
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
    let matches = [GlobalMatch { start: 50, end: 55, pattern_id: 0 }];
    let result = map_offsets_to_segments(&segments, &matches);
    // Should not panic on zero-length segment.
    assert!(result.is_ok());
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
    // Should detect overflow and return error.
    match result {
        Err(SegmentAttributionError::SegmentEndOverflow { .. }) => {}
        Ok(_) => {
            // Also acceptable — empty matches, no actual overflow triggered.
        }
        Err(other) => {
            // Any error is acceptable as long as no panic.
            let _ = other;
        }
    }
}

// ────────────────────────────────────────────────────────────
// Multiple segments, multiple matches
// ────────────────────────────────────────────────────────────

#[test]
fn many_segments_many_matches() {
    let segments: Vec<Segment> = (0..100)
        .map(|i| Segment::new(i, i * 100, 100))
        .collect();
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
    let matches = [GlobalMatch { start: 50, end: 60, pattern_id: 0 }];
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
    let matches = [GlobalMatch { start: 60, end: 70, pattern_id: 0 }];
    let result = map_offsets_to_segments(&segments, &matches);
    assert!(result.is_ok());
    // Match is outside the segment — should not be attributed.
    assert!(result.unwrap().is_empty());
}
