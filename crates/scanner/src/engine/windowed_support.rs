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
        m.location.line = Some(line_offsets.partition_point(|&lo| lo <= m.location.offset));
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
