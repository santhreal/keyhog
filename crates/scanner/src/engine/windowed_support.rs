//! Window slicing and `(detector, credential, source_offset)` raw-hit dedup.

use super::*;
use keyhog_core::SensitiveString;
use std::collections::{HashSet, VecDeque};

pub fn window_end_offset(text: &str, start: usize, max_len: usize) -> usize {
    ceil_char_boundary(text, start.saturating_add(max_len).min(text.len()))
}

pub fn next_window_offset(text: &str, current_end: usize, overlap: usize) -> usize {
    ceil_char_boundary(text, current_end.saturating_sub(overlap))
}

pub fn window_ranges(text: &str, max_len: usize, overlap: usize) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut offset = 0usize;
    while offset < text.len() {
        let end = window_end_offset(text, offset, max_len);
        ranges.push((offset, end));
        if end >= text.len() {
            break;
        }
        let next = next_window_offset(text, end, overlap);
        offset = if next > offset { next } else { end };
    }
    ranges
}

pub fn window_chunk(chunk: &Chunk, start: usize, end: usize) -> Chunk {
    Chunk {
        data: chunk.data.as_ref()[start..end].to_string().into(),
        metadata: chunk.metadata.clone(),
    }
}

pub fn record_window_match(
    line_offsets: &[usize],
    source_base_offset: usize,
    source_base_line: usize,
    window_offset: usize,
    window_len: usize,
    m: &mut RawMatch,
    seen: &mut HashSet<(Arc<str>, SensitiveString, usize)>,
    seen_order: &mut VecDeque<(Arc<str>, SensitiveString, usize)>,
) -> bool {
    let Some(window_local_offset) = m.location.offset.checked_sub(source_base_offset) else {
        return false;
    };
    if window_local_offset >= window_len {
        return false;
    }
    m.location.offset = source_base_offset
        .saturating_add(window_offset)
        .saturating_add(window_local_offset);
    if m.location.line.is_some() {
        // `line_offsets` holds each line-start byte offset in ascending order
        // (offset 0 first). The count of starts `<= offset` IS the 1-based line
        // number - identical to counting newlines before `offset` and adding 1
        // (what `line_number_for_offset` does the slow way), but O(log L) per
        // match instead of O(offset).
        let chunk_local_offset = window_offset.saturating_add(window_local_offset);
        m.location.line = Some(
            source_base_line
                .saturating_add(line_offsets.partition_point(|&lo| lo <= chunk_local_offset)),
        );
    }

    let key = (
        m.detector_id.clone(),
        m.credential.clone(),
        m.location.offset,
    );
    if seen.contains(&key) {
        return false;
    }

    if seen.len() >= MAX_WINDOW_DEDUP_ENTRIES {
        if let Some(oldest) = seen_order.pop_front() {
            seen.remove(&oldest);
        }
    }
    seen.insert(key.clone());
    seen_order.push_back(key);
    true
}

pub fn line_number_for_offset(text: &str, offset: usize) -> usize {
    let safe_offset = floor_char_boundary(text, offset.min(text.len()));
    text[..safe_offset].chars().filter(|&ch| ch == '\n').count() + 1
}

pub fn floor_char_boundary(text: &str, index: usize) -> usize {
    if index >= text.len() {
        return text.len();
    }
    let mut i = index;
    while i > 0 && !text.is_char_boundary(i) {
        i -= 1;
    }
    i
}

pub(crate) fn ceil_char_boundary(text: &str, index: usize) -> usize {
    if index >= text.len() {
        return text.len();
    }
    let mut i = index;
    while i < text.len() && !text.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// Compose an absolute file offset from a chunk `base_offset` and a chunk-local
/// offset. Returns `None` on overflow so callers skip the unit instead of
/// emitting a wrapped (release) or debug-panicking bogus offset; overflow needs
/// a multi-exabyte `base_offset` a malformed source could report. This is the
/// single owner of that guard for every emit and cross-seam reassembly path.
pub(crate) fn absolute_offset(base_offset: usize, local: usize) -> Option<usize> {
    base_offset.checked_add(local)
}

/// Compose an absolute line number from a chunk `base_line` and a chunk-local
/// line index. Line counts cannot realistically overflow, so saturating keeps
/// the value monotone without a skip path, colocated with the offset owner.
pub(crate) fn absolute_line(base_line: usize, local_line: usize) -> usize {
    base_line.saturating_add(local_line)
}

#[cfg(test)]
mod absolute_composition_tests {
    use super::{absolute_line, absolute_offset};

    #[test]
    fn absolute_offset_composes_in_range() {
        assert_eq!(absolute_offset(64 * 1024 * 1024, 845), Some(67_109_709));
        assert_eq!(absolute_offset(0, 0), Some(0));
    }

    #[test]
    fn absolute_offset_returns_none_on_overflow() {
        assert_eq!(absolute_offset(usize::MAX, 1), None);
        assert_eq!(absolute_offset(usize::MAX - 3, 10), None);
    }

    #[test]
    fn absolute_line_composes_and_saturates() {
        assert_eq!(absolute_line(100, 44), 144);
        assert_eq!(absolute_line(usize::MAX, 1), usize::MAX);
    }
}
