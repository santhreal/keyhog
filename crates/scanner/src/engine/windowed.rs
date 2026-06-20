use super::windowed_support::{
    next_window_offset, record_window_match, window_chunk, window_end_offset,
};
use super::*;
use std::collections::{HashSet, VecDeque};

impl CompiledScanner {
    pub(super) fn scan_windowed(
        &self,
        chunk: &Chunk,
        deadline: Option<std::time::Instant>,
    ) -> Vec<RawMatch> {
        let chunk_text = &chunk.data;
        if reject_oversized_window_chunk(chunk, chunk_text) {
            return Vec::new();
        }
        let mut all_matches = Vec::with_capacity((chunk_text.len() / 4096).max(16));
        let mut seen = HashSet::new();
        let mut seen_order = VecDeque::new();
        let mut offset = 0usize;

        // Compute the chunk's line-start offsets ONCE up front. Per-match line
        // attribution then binary-searches this table (O(log L)) instead of
        // re-counting newlines from the buffer start for every match
        // (O(offset)/match → O(n²) over a match-dense chunk). On a windowed
        // multi-MiB buffer the old path made line attribution the dominant
        // cost; see `record_window_match`.
        let line_offsets = crate::compute_line_offsets(chunk_text);

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
                    &line_offsets,
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

    #[cfg(any(feature = "simd", feature = "gpu"))]
    pub(crate) fn scan_windowed_with_triggered(
        &self,
        chunk: &Chunk,
        triggered_patterns: &[u64],
        deadline: Option<std::time::Instant>,
        phase2_keyword_hints: Option<&[u32]>,
        phase2_always_anchor_present: Option<bool>,
        confirmed_anchor_literal_matches: Option<&[(u32, u32)]>,
    ) -> Vec<RawMatch> {
        let chunk_text = &chunk.data;
        if reject_oversized_window_chunk(chunk, chunk_text) {
            return Vec::new();
        }
        let mut all_matches = Vec::with_capacity((chunk_text.len() / 4096).max(16));
        let mut seen = HashSet::new();
        let mut seen_order = VecDeque::new();
        let mut offset = 0usize;
        let line_offsets = crate::compute_line_offsets(chunk_text);

        while offset < chunk_text.len() {
            if let Some(deadline) = deadline {
                if std::time::Instant::now() > deadline {
                    break;
                }
            }
            let end = window_end_offset(chunk_text, offset, MAX_SCAN_CHUNK_BYTES);
            let window_chunk = window_chunk(chunk, offset, end);
            let prepared = self.prepare_chunk(&window_chunk);
            let window_confirmed_anchor_matches;
            let confirmed_anchor_matches = if let Some(matches) = confirmed_anchor_literal_matches {
                window_confirmed_anchor_matches = matches
                    .iter()
                    .filter_map(|&(literal_idx, pos)| {
                        let pos = pos as usize;
                        (pos >= offset && pos < end).then_some((literal_idx, (pos - offset) as u32))
                    })
                    .collect::<Vec<_>>();
                Some(window_confirmed_anchor_matches.as_slice())
            } else {
                None
            };
            for mut raw_match in self.scan_prepared_with_triggered(
                prepared,
                crate::hw_probe::ScanBackend::SimdCpu,
                triggered_patterns.to_vec(),
                deadline,
                phase2_keyword_hints,
                phase2_always_anchor_present,
                confirmed_anchor_matches,
            ) {
                if record_window_match(
                    &line_offsets,
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

fn reject_oversized_window_chunk(chunk: &Chunk, chunk_text: &str) -> bool {
    if chunk_text.len() <= 512 * 1024 * 1024 {
        return false;
    }
    tracing::warn!(
        "Chunk from {} exceeds 512MB limit ({} bytes), skipping to prevent OOM.",
        chunk.metadata.path.as_deref().unwrap_or("unknown"), // LAW10: absent path/field => display placeholder; reporting-only, recall-safe
        chunk_text.len()
    );
    true
}
