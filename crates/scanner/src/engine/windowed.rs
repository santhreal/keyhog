#[cfg(any(feature = "simd", feature = "gpu", test))]
use super::phase2::Phase2AlwaysActiveGpuEvidence;
#[cfg(any(feature = "simd", feature = "gpu", test))]
use super::windowed_support::window_ranges;
use super::windowed_support::{
    next_window_offset, record_window_match, window_chunk, window_end_offset,
};
use super::*;
use std::collections::{HashSet, VecDeque};

impl CompiledScanner {
    pub(crate) fn scan_windowed(
        &self,
        chunk: &Chunk,
        backend: crate::hw_probe::ScanBackend,
        deadline: Option<std::time::Instant>,
    ) -> Vec<RawMatch> {
        let chunk_text = &chunk.data;
        if reject_oversized_window_chunk(chunk, chunk_text) {
            return Vec::new();
        }
        let mut all_matches = Vec::with_capacity(estimate_window_match_capacity(chunk_text.len()));
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
            for mut raw_match in self.scan_inner(&window_chunk, backend, deadline) {
                if record_window_match(
                    &line_offsets,
                    chunk.metadata.base_offset,
                    chunk.metadata.base_line,
                    offset,
                    end - offset,
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

    #[cfg(any(feature = "simd", feature = "gpu", test))]
    pub(crate) fn scan_windowed_with_triggered(
        &self,
        chunk: &Chunk,
        triggered_patterns: &[u64],
        deadline: Option<std::time::Instant>,
        phase2_keyword_hints: Option<&[u32]>,
        phase2_always_active_gpu_evidence: Option<Phase2AlwaysActiveGpuEvidence>,
        confirmed_anchor_literal_matches: Option<&[(u32, u32)]>,
        generic_keyword_positions: Option<&[u32]>,
    ) -> Vec<RawMatch> {
        use rayon::prelude::*;

        let chunk_text = &chunk.data;
        if reject_oversized_window_chunk(chunk, chunk_text) {
            return Vec::new();
        }
        let mut all_matches = Vec::with_capacity(estimate_window_match_capacity(chunk_text.len()));
        let mut seen = HashSet::new();
        let mut seen_order = VecDeque::new();
        let line_offsets = crate::compute_line_offsets(chunk_text);
        let ranges = window_ranges(chunk_text, MAX_SCAN_CHUNK_BYTES, WINDOW_OVERLAP_BYTES);
        let telemetry = crate::telemetry::capture_scan_telemetry();

        let window_matches: Vec<(usize, usize, Vec<RawMatch>)> = ranges
            .par_iter()
            .map(|&(offset, end)| {
                crate::telemetry::with_captured_scan_telemetry(telemetry.as_ref(), || {
                    let window_len = end - offset;
                    if let Some(deadline) = deadline {
                        if std::time::Instant::now() > deadline {
                            return (offset, window_len, Vec::new());
                        }
                    }
                    let window_chunk = window_chunk(chunk, offset, end);
                    let prepared = self.prepare_chunk(&window_chunk);
                    let window_confirmed_anchor_matches;
                    let confirmed_anchor_matches =
                        if let Some(matches) = confirmed_anchor_literal_matches {
                            window_confirmed_anchor_matches = matches
                                .iter()
                                .filter_map(|&(literal_idx, pos)| {
                                    let pos = pos as usize;
                                    (pos >= offset && pos < end)
                                        .then(|| (literal_idx, (pos - offset) as u32))
                                })
                                .collect::<Vec<_>>();
                            Some(window_confirmed_anchor_matches.as_slice())
                        } else {
                            None
                        };
                    let window_generic_keyword_positions;
                    let generic_positions = if let Some(positions) = generic_keyword_positions {
                        window_generic_keyword_positions = positions
                            .iter()
                            .filter_map(|&pos| {
                                let pos = pos as usize;
                                (pos >= offset && pos < end).then(|| (pos - offset) as u32)
                            })
                            .collect::<Vec<_>>();
                        Some(window_generic_keyword_positions.as_slice())
                    } else {
                        None
                    };
                    let matches = self.scan_prepared_with_triggered(
                        prepared,
                        crate::hw_probe::ScanBackend::SimdCpu,
                        triggered_patterns,
                        deadline,
                        phase2_keyword_hints,
                        phase2_always_active_gpu_evidence,
                        confirmed_anchor_matches,
                        generic_positions,
                    );
                    (offset, window_len, matches)
                })
            })
            .collect();

        for (offset, window_len, matches) in window_matches {
            for mut raw_match in matches {
                if record_window_match(
                    &line_offsets,
                    chunk.metadata.base_offset,
                    chunk.metadata.base_line,
                    offset,
                    window_len,
                    &mut raw_match,
                    &mut seen,
                    &mut seen_order,
                ) {
                    all_matches.push(raw_match);
                }
            }
        }

        all_matches
    }
}

/// Rough starting capacity for a chunk's match vec: ~1 per 4 KiB, floor 16.
fn estimate_window_match_capacity(chunk_len: usize) -> usize {
    (chunk_len / 4096).max(16)
}

/// Absolute OOM backstop for windowed scanning. `scan_windowed` already scans a
/// chunk in bounded `MAX_SCAN_CHUNK_BYTES` slices, so a chunk below this ceiling
/// is fully covered (windowed), NOT dropped, per-window memory stays bounded
/// regardless of total chunk size. This hard skip therefore fires only for a
/// pathological multi-GiB single chunk, where the resident buffer plus the line
/// -offset table would themselves threaten OOM. Set far above any real input so
/// the previous 512 MiB recall cliff no longer silently drops scannable data.
pub(crate) const MAX_WINDOW_CHUNK_BYTES: usize = 4 * 1024 * 1024 * 1024;

pub(crate) fn reject_oversized_window_chunk(chunk: &Chunk, chunk_text: &str) -> bool {
    if chunk_text.len() <= MAX_WINDOW_CHUNK_BYTES {
        return false;
    }
    tracing::warn!(
        "Chunk from {} exceeds {}MiB windowed-scan ceiling ({} bytes); skipping this chunk to prevent OOM. COVERAGE LOSS for this input.",
        chunk.metadata.path.as_deref().unwrap_or("unknown"), // LAW10: absent path/field => display placeholder; reporting-only, recall-safe
        MAX_WINDOW_CHUNK_BYTES / (1024 * 1024),
        chunk_text.len()
    );
    true
}
