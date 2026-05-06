use super::*;
use std::collections::VecDeque;

impl CompiledScanner {
    pub(super) fn scan_windowed(
        &self,
        chunk: &Chunk,
        deadline: Option<std::time::Instant>,
    ) -> Vec<RawMatch> {
        let chunk_text = &chunk.data;
        if chunk_text.len() > 512 * 1024 * 1024 {
            tracing::warn!(
                "Chunk from {} exceeds 512MB limit ({} bytes), skipping to prevent OOM.",
                chunk.metadata.path.as_deref().unwrap_or("unknown"),
                chunk_text.len()
            );
            return Vec::new();
        }
        let mut all_matches = Vec::with_capacity((chunk_text.len() / 4096).max(16));
        let mut seen = HashSet::new();
        let mut seen_order = VecDeque::new();
        let mut offset = 0usize;

        while offset < chunk_text.len() {
            if let Some(deadline) = deadline {
                if std::time::Instant::now() > deadline {
                    break;
                }
            }
            let end = window_end_offset(chunk_text, offset, MAX_SCAN_CHUNK_BYTES);
            let window_chunk = window_chunk(chunk, offset, end);
            let backend = self.select_backend_for_file(window_chunk.data.len() as u64);
            for mut raw_match in self.scan_inner(&window_chunk, backend, deadline) {
                if record_window_match(
                    chunk_text,
                    offset,
                    &mut raw_match,
                    &mut seen,
                    &mut seen_order,
                ) {
                    all_matches.push(raw_match);
                }
            }
            if end >= chunk_text.len() {
                break;
            }
            offset = next_window_offset(chunk_text, end, WINDOW_OVERLAP_BYTES);
        }

        all_matches
    }
}

pub fn window_end_offset(text: &str, start: usize, max_len: usize) -> usize {
    let mut end = (start + max_len).min(text.len());
    while end < text.len() && !text.is_char_boundary(end) {
        end += 1;
    }
    end
}

pub fn next_window_offset(text: &str, current_end: usize, overlap: usize) -> usize {
    let mut next = current_end.saturating_sub(overlap);
    while next < text.len() && !text.is_char_boundary(next) {
        next += 1;
    }
    next
}

pub fn window_chunk(chunk: &Chunk, start: usize, end: usize) -> Chunk {
    Chunk {
        data: chunk.data.as_str()[start..end].to_string().into(),
        metadata: chunk.metadata.clone(),
    }
}

pub fn record_window_match(
    text: &str,
    window_offset: usize,
    m: &mut RawMatch,
    seen: &mut HashSet<(Arc<str>, Arc<str>, usize)>,
    seen_order: &mut VecDeque<(Arc<str>, Arc<str>, usize)>,
) -> bool {
    m.location.offset += window_offset;
    if m.location.line.is_some() {
        m.location.line = Some(line_number_for_offset(text, m.location.offset));
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
