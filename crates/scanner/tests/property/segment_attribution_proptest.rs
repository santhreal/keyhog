use keyhog_scanner::engine::segment_attribution::{
    map_offsets_to_segments, AttributedMatch, GlobalMatch, Segment, SegmentAttributionError,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]
    
    #[test]
    fn test_valid_and_invalid_matches(
        initial_start in 0..1000u32,
        segment_spec in prop::collection::vec((0..1000u32, 0..1000u32), 0..20),
        valid_match_spec in prop::collection::vec((0..1000u32, 0..1000u32), 0..20),
        invalid_match_spec in prop::collection::vec((0..1000u32, 0..1000u32, 0..4u8), 0..20),
    ) {
        // Construct segments from length and gap specification
        let mut segments = Vec::new();
        let mut current_offset = initial_start;
        for (i, &(len, gap)) in segment_spec.iter().enumerate() {
            if let Some(next) = current_offset.checked_add(gap) {
                let start = next;
                if let Some(end) = start.checked_add(len) {
                    segments.push(Segment::new(i as u32, start, len));
                    current_offset = end;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        // Generate valid matches and their expected attributed matches
        let mut global_matches = Vec::new();
        let mut expected_attributed = Vec::new();

        for (i, &segment) in segments.iter().enumerate() {
            if segment.len > 0 {
                if let Some(&(a, b)) = valid_match_spec.get(i) {
                    let a_mod = a % segment.len;
                    let b_mod = b % segment.len;
                    let mut min_val = std::cmp::min(a_mod, b_mod);
                    let mut max_val = std::cmp::max(a_mod, b_mod);
                    if min_val == max_val {
                        if max_val + 1 <= segment.len {
                            max_val += 1;
                        } else {
                            min_val = 0;
                            max_val = segment.len;
                        }
                    }
                    let m_start = segment.start + min_val;
                    let m_end = segment.start + max_val;
                    
                    let pattern_id = i as u32 * 10;
                    global_matches.push(GlobalMatch::new(pattern_id, m_start, m_end));
                    expected_attributed.push(AttributedMatch::new(segment.id, pattern_id, min_val, max_val));
                }
            }
        }

        // Generate invalid (spanning/gap) matches
        for (i, &segment) in segments.iter().enumerate() {
            if let Some(&(a, b, ty)) = invalid_match_spec.get(i) {
                let next_segment = segments.get(i + 1);
                let gap = if let Some(next_seg) = next_segment {
                    next_seg.start.saturating_sub(segment.start + segment.len)
                } else {
                    1000
                };
                let pattern_id = 9999 + i as u32;

                match ty {
                    0 => {
                        // Spans from segment to its gap
                        if segment.len > 0 && gap > 0 {
                            let m_start = segment.start + (a % segment.len);
                            let m_end = segment.start + segment.len + (b % gap) + 1;
                            global_matches.push(GlobalMatch::new(pattern_id, m_start, m_end));
                        }
                    }
                    1 => {
                        // Spans from gap to next segment
                        if gap > 0 && next_segment.is_some() {
                            let next_seg = next_segment.unwrap();
                            if next_seg.len > 0 {
                                let m_start = segment.start + segment.len + (a % gap);
                                let m_end = next_seg.start + (b % next_seg.len) + 1;
                                global_matches.push(GlobalMatch::new(pattern_id, m_start, m_end));
                            }
                        }
                    }
                    2 => {
                        // Spans from segment to next segment
                        if segment.len > 0 && next_segment.is_some() {
                            let next_seg = next_segment.unwrap();
                            if next_seg.len > 0 {
                                let m_start = segment.start + (a % segment.len);
                                let m_end = next_seg.start + (b % next_seg.len) + 1;
                                global_matches.push(GlobalMatch::new(pattern_id, m_start, m_end));
                            }
                        }
                    }
                    3 => {
                        // Purely within gap
                        if gap > 0 {
                            let gap_start = segment.start + segment.len;
                            let a_mod = a % gap;
                            let b_mod = b % gap;
                            let mut min_val = std::cmp::min(a_mod, b_mod);
                            let mut max_val = std::cmp::max(a_mod, b_mod);
                            if min_val == max_val {
                                if max_val + 1 <= gap {
                                    max_val += 1;
                                } else {
                                    min_val = 0;
                                    max_val = gap;
                                }
                            }
                            global_matches.push(GlobalMatch::new(pattern_id, gap_start + min_val, gap_start + max_val));
                        }
                    }
                    _ => {}
                }
            }
        }

        // Run the mapping and verify behavior
        let result = map_offsets_to_segments(&segments, &global_matches);
        
        let attributed = result.unwrap();

        // Verify that every expected match is in the output and correct
        for expected in &expected_attributed {
            let found = attributed.iter().any(|m| m == expected);
            prop_assert!(found, "Expected match {:?} was not found in attributed output: {:?}", expected, attributed);
        }

        // Verify that none of the invalid/spanning matches are attributed
        for m in &attributed {
            prop_assert!(m.pattern_id < 9999, "Invalid match with pattern_id {} was attributed: {:?}", m.pattern_id, m);
        }
        
        // Verify total length of attributed matches is exactly expected_attributed.len()
        prop_assert_eq!(attributed.len(), expected_attributed.len());
    }

    #[test]
    fn test_overflow_ranges_dont_panic(
        start in (u32::MAX - 1000)..=u32::MAX,
        len in 2..2000u32,
    ) {
        let segment = Segment::new(1, start, len);
        let segments = vec![segment];
        
        let result = map_offsets_to_segments(&segments, &[]);
        let end_overflows = start.checked_add(len).is_none();
        if end_overflows {
            prop_assert!(result.is_err());
            match result.unwrap_err() {
                SegmentAttributionError::SegmentEndOverflow { segment_index, start: s, len: l } => {
                    prop_assert_eq!(segment_index, 0);
                    prop_assert_eq!(s, start);
                    prop_assert_eq!(l, len);
                }
                other => {
                    prop_assert!(false, "Expected SegmentEndOverflow error, got {:?}", other);
                }
            }
        } else {
            prop_assert!(result.is_ok());
        }
    }

    #[test]
    fn test_multiple_segments_overflow_dont_panic(
        start1 in 0..1000u32,
        len1 in 0..1000u32,
        start2 in (u32::MAX - 1000)..=u32::MAX,
        len2 in 0..2000u32,
    ) {
        let segments = vec![
            Segment::new(1, start1, len1),
            Segment::new(2, start2, len2),
        ];
        
        let result = map_offsets_to_segments(&segments, &[]);
        if let Err(err) = result {
            match err {
                SegmentAttributionError::SegmentEndOverflow { .. } |
                SegmentAttributionError::SegmentsNotSorted { .. } |
                SegmentAttributionError::SegmentsOverlap { .. } => {}
                other => {
                    prop_assert!(false, "Unexpected error: {:?}", other);
                }
            }
        }
    }

    #[test]
    fn test_zero_width_segments(
        segment_spec in prop::collection::vec((0..10u32, 0..10u32), 0..20),
        matches in prop::collection::vec((0..100u32, 0..100u32), 0..20),
    ) {
        let mut segments = Vec::new();
        let mut current_offset = 0u32;
        for (i, &(len, gap)) in segment_spec.iter().enumerate() {
            let final_len = if len % 2 == 0 { 0 } else { len };
            if let Some(next) = current_offset.checked_add(gap) {
                let start = next;
                if let Some(end) = start.checked_add(final_len) {
                    segments.push(Segment::new(i as u32, start, final_len));
                    current_offset = end;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        let global_matches: Vec<GlobalMatch> = matches.iter().map(|&(start, len)| {
            GlobalMatch::new(1, start, start + len + 1)
        }).collect();

        let result = map_offsets_to_segments(&segments, &global_matches);
        
        if let Ok(attributed) = result {
            for m in attributed {
                let seg = segments.iter().find(|s| s.id == m.segment_id).unwrap();
                prop_assert!(seg.len > 0, "Match attributed to a zero-width segment! Match: {:?}, Segment: {:?}", m, seg);
            }
        }
    }
}
