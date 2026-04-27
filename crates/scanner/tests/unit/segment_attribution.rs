use keyhog_scanner::engine::segment_attribution::{
    map_offsets_to_segments, AttributedMatch, GlobalMatch, Segment, SegmentAttributionError,
};

#[test]
fn maps_global_matches_to_segment_local_offsets_preserving_match_order() {
    let segments = [
        Segment::new(10, 100, 16),
        Segment::new(20, 200, 32),
        Segment::new(30, 300, 8),
    ];
    let matches = [
        GlobalMatch::new(7, 205, 211),
        GlobalMatch::new(3, 101, 104),
        GlobalMatch::new(9, 300, 308),
    ];

    let mapped = map_offsets_to_segments(&segments, &matches).unwrap();

    assert_eq!(
        mapped,
        vec![
            AttributedMatch::new(20, 7, 5, 11),
            AttributedMatch::new(10, 3, 1, 4),
            AttributedMatch::new(30, 9, 0, 8),
        ]
    );
}

#[test]
fn omits_gap_matches_and_matches_that_cross_segment_boundaries() {
    let segments = [Segment::new(1, 0, 8), Segment::new(2, 16, 8)];
    let matches = [
        GlobalMatch::new(1, 2, 4),
        GlobalMatch::new(2, 8, 10),
        GlobalMatch::new(3, 6, 18),
        GlobalMatch::new(4, 18, 20),
    ];

    let mapped = map_offsets_to_segments(&segments, &matches).unwrap();

    assert_eq!(
        mapped,
        vec![
            AttributedMatch::new(1, 1, 2, 4),
            AttributedMatch::new(2, 4, 2, 4),
        ]
    );
}

#[test]
fn rejects_invalid_segments_and_match_ranges() {
    let unsorted =
        map_offsets_to_segments(&[Segment::new(1, 10, 2), Segment::new(2, 5, 2)], &[]).unwrap_err();
    assert_eq!(
        unsorted,
        SegmentAttributionError::SegmentsNotSorted {
            segment_index: 1,
            previous_start: 10,
            start: 5,
        }
    );

    let overlapping =
        map_offsets_to_segments(&[Segment::new(1, 10, 10), Segment::new(2, 15, 2)], &[])
            .unwrap_err();
    assert_eq!(
        overlapping,
        SegmentAttributionError::SegmentsOverlap {
            previous_index: 0,
            segment_index: 1,
            previous_end: 20,
            start: 15,
        }
    );

    let invalid_match =
        map_offsets_to_segments(&[Segment::new(1, 0, 8)], &[GlobalMatch::new(1, 3, 3)])
            .unwrap_err();
    assert_eq!(
        invalid_match,
        SegmentAttributionError::InvalidMatchRange {
            match_index: 0,
            start: 3,
            end: 3,
        }
    );
}
