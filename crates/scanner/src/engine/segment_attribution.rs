//! Attribute coalesced scanner matches back to logical input segments.
//!
//! This mirrors the general `match.map_offsets_to_segments` primitive in
//! Vyre while keeping Keyhog publishable until the matching primitive crate
//! version used by this repository is available on crates.io.

use thiserror::Error;

/// A logical input range inside one coalesced scanner buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Segment {
    /// Caller-defined stable identifier for the logical input.
    pub id: u32,
    /// Inclusive global byte offset where the segment starts.
    pub start: u32,
    /// Segment length in bytes.
    pub len: u32,
}

impl Segment {
    /// Create a segment descriptor.
    #[must_use]
    pub const fn new(id: u32, start: u32, len: u32) -> Self {
        Self { id, start, len }
    }

    fn checked_end(self, segment_index: usize) -> Result<u32, SegmentAttributionError> {
        self.start
            .checked_add(self.len)
            .ok_or(SegmentAttributionError::SegmentEndOverflow {
                segment_index,
                start: self.start,
                len: self.len,
            })
    }
}

/// A scanner match using global byte offsets in the coalesced buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GlobalMatch {
    /// Pattern identifier emitted by the scanner.
    pub pattern_id: u32,
    /// Inclusive global match start.
    pub start: u32,
    /// Exclusive global match end.
    pub end: u32,
}

impl GlobalMatch {
    /// Create a global scanner match.
    #[must_use]
    pub const fn new(pattern_id: u32, start: u32, end: u32) -> Self {
        Self {
            pattern_id,
            start,
            end,
        }
    }
}

/// A match rewritten into segment-local byte offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttributedMatch {
    /// Identifier copied from the containing segment.
    pub segment_id: u32,
    /// Identifier copied from the original match.
    pub pattern_id: u32,
    /// Inclusive byte offset inside the containing segment.
    pub local_start: u32,
    /// Exclusive byte offset inside the containing segment.
    pub local_end: u32,
}

impl AttributedMatch {
    /// Create a segment-local match.
    #[must_use]
    pub const fn new(segment_id: u32, pattern_id: u32, local_start: u32, local_end: u32) -> Self {
        Self {
            segment_id,
            pattern_id,
            local_start,
            local_end,
        }
    }
}

/// Validation error returned while attributing matches to segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SegmentAttributionError {
    /// A segment's `start + len` exceeded `u32::MAX`.
    #[error("segment {segment_index} overflows: start {start} + len {len}")]
    SegmentEndOverflow {
        /// Index of the overflowing segment.
        segment_index: usize,
        /// Segment start offset.
        start: u32,
        /// Segment length in bytes.
        len: u32,
    },
    /// Segments must be sorted by start offset.
    #[error("segment {segment_index} starts at {start} before previous start {previous_start}")]
    SegmentsNotSorted {
        /// Index of the segment that breaks ordering.
        segment_index: usize,
        /// Previous segment start offset.
        previous_start: u32,
        /// Current segment start offset.
        start: u32,
    },
    /// Segment byte ranges may touch but must not overlap.
    #[error(
        "segment {segment_index} starts at {start} before previous segment {previous_index} ends at {previous_end}"
    )]
    SegmentsOverlap {
        /// Index of the previous segment.
        previous_index: usize,
        /// Index of the overlapping segment.
        segment_index: usize,
        /// Exclusive end offset of the previous segment.
        previous_end: u32,
        /// Start offset of the current segment.
        start: u32,
    },
    /// Match ranges must be non-empty half-open byte ranges.
    #[error("match {match_index} has invalid range [{start}, {end})")]
    InvalidMatchRange {
        /// Index of the invalid match.
        match_index: usize,
        /// Inclusive match start offset.
        start: u32,
        /// Exclusive match end offset.
        end: u32,
    },
}

#[derive(Debug, Clone, Copy)]
struct NormalizedSegment {
    id: u32,
    start: u32,
    end: u32,
}

/// Map global byte-range matches back to their containing segments.
///
/// Matches that land in gaps or cross a segment boundary are omitted. Output
/// order follows the caller-provided match order.
pub fn map_offsets_to_segments(
    segments: &[Segment],
    matches: &[GlobalMatch],
) -> Result<Vec<AttributedMatch>, SegmentAttributionError> {
    let normalized = validate_segments(segments)?;
    let mut ordered_match_indices: Vec<usize> = (0..matches.len()).collect();
    ordered_match_indices.sort_by_key(|&index| {
        let item = matches[index];
        (item.start, item.end, item.pattern_id, index)
    });

    let mut segment_cursor = 0usize;
    let mut mapped_by_input_order = vec![None; matches.len()];

    for match_index in ordered_match_indices {
        let item = matches[match_index];
        if item.end <= item.start {
            return Err(SegmentAttributionError::InvalidMatchRange {
                match_index,
                start: item.start,
                end: item.end,
            });
        }

        while segment_cursor < normalized.len() && normalized[segment_cursor].end <= item.start {
            segment_cursor += 1;
        }

        let Some(segment) = normalized.get(segment_cursor).copied() else {
            continue;
        };

        if segment.start <= item.start && item.end <= segment.end {
            mapped_by_input_order[match_index] = Some(AttributedMatch::new(
                segment.id,
                item.pattern_id,
                item.start - segment.start,
                item.end - segment.start,
            ));
        }
    }

    Ok(mapped_by_input_order.into_iter().flatten().collect())
}

fn validate_segments(
    segments: &[Segment],
) -> Result<Vec<NormalizedSegment>, SegmentAttributionError> {
    let mut normalized = Vec::with_capacity(segments.len());
    let mut previous: Option<(usize, u32, u32)> = None;

    for (segment_index, segment) in segments.iter().copied().enumerate() {
        let end = segment.checked_end(segment_index)?;

        if let Some((previous_index, previous_start, previous_end)) = previous {
            if segment.start < previous_start {
                return Err(SegmentAttributionError::SegmentsNotSorted {
                    segment_index,
                    previous_start,
                    start: segment.start,
                });
            }
            if segment.start < previous_end {
                return Err(SegmentAttributionError::SegmentsOverlap {
                    previous_index,
                    segment_index,
                    previous_end,
                    start: segment.start,
                });
            }
        }

        normalized.push(NormalizedSegment {
            id: segment.id,
            start: segment.start,
            end,
        });
        previous = Some((segment_index, segment.start, end));
    }

    Ok(normalized)
}
