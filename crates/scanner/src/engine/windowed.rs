use super::*;
use std::collections::{HashSet, VecDeque};

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

    /// THE single windowing contract for per-chunk phase-2 extraction.
    ///
    /// A chunk larger than [`MAX_SCAN_CHUNK_BYTES`] is WINDOWED (each ≤1 MiB
    /// window scanned independently with its own `max_matches_per_chunk` budget
    /// and a bounded, linear phase-2); every smaller chunk runs `extract` whole.
    ///
    /// Every phase-2 caller — the per-file `scan`, the coalesced SIMD path, and
    /// the GPU phase-2 path — MUST route a chunk through this. Each path used to
    /// make its own windowing decision and they DRIFTED: the GPU/coalesced paths
    /// scanned large chunks whole, so a >1 MiB file dense in matches silently
    /// truncated against the per-chunk cap (dropped 1/3 of secrets on a 16 MiB
    /// file) while the per-file path windowed and found them all. Funnelling the
    /// decision here makes that class of divergence unrepresentable.
    ///
    /// `extract` is only invoked for the small-chunk case; it owns preparing the
    /// chunk and running whichever seeded extractor (triggered bitmap, GPU pid
    /// hits, …) the caller has. Post-processing (decode recursion, cross-chunk
    /// reassembly) stays at the caller, applied uniformly to either branch.
    //
    // `any(simd, gpu)`: the only caller is `scan_coalesced_phase2`, the shared
    // tail of the coalesced (`simd`) and megakernel (`gpu`) producers. The
    // per-file and decode paths call `scan_windowed` directly, so the wrapper
    // itself is unused in a no-`simd`-no-`gpu` build — gated to match (Law 11).
    #[cfg(any(feature = "simd", feature = "gpu"))]
    pub(crate) fn scan_chunk_or_window<F>(
        &self,
        chunk: &Chunk,
        deadline: Option<std::time::Instant>,
        extract: F,
    ) -> Vec<RawMatch>
    where
        F: FnOnce() -> Vec<RawMatch>,
    {
        if chunk.data.len() > MAX_SCAN_CHUNK_BYTES {
            self.scan_windowed(chunk, deadline)
        } else {
            extract()
        }
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
    line_offsets: &[usize],
    window_offset: usize,
    m: &mut RawMatch,
    seen: &mut HashSet<(Arc<str>, Arc<str>, usize)>,
    seen_order: &mut VecDeque<(Arc<str>, Arc<str>, usize)>,
) -> bool {
    m.location.offset += window_offset;
    if m.location.line.is_some() {
        // `line_offsets` holds each line-start byte offset in ascending order
        // (offset 0 first). The count of starts `<= offset` IS the 1-based line
        // number — identical to counting newlines before `offset` and adding 1
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
