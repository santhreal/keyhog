#[cfg(any(feature = "simd", feature = "gpu", test))]
use super::phase2::Phase2AlwaysActiveGpuEvidence;
use super::windowed_support::{record_window_match, window_chunk, window_ranges};
use super::*;
use std::collections::{HashSet, VecDeque};

impl CompiledScanner {
    pub(crate) fn scan_windowed(
        &self,
        chunk: &Chunk,
        backend: crate::hw_probe::ScanBackend,
        deadline: Option<std::time::Instant>,
        route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<Vec<RawMatch>> {
        use rayon::prelude::*;

        let chunk_text = &chunk.data;
        if reject_oversized_window_chunk(chunk, chunk_text) {
            return Ok(Vec::new());
        }
        let line_offsets = crate::compute_line_offsets(chunk_text);
        let ranges = window_ranges(chunk_text, MAX_SCAN_CHUNK_BYTES, WINDOW_OVERLAP_BYTES);
        let telemetry = crate::telemetry::capture_scan_telemetry();
        let recovery_receipts = crate::gpu::capture_recovery_receipts();
        let profile_runtime = keyhog_profile::current_runtime();
        let window_matches: crate::error::Result<Vec<(usize, usize, Vec<RawMatch>)>> = ranges
            .par_iter()
            .map(|&(offset, end)| {
                let _profile_context = profile_runtime.as_ref().map(keyhog_profile::Runtime::enter);
                crate::gpu::with_captured_recovery_receipts(recovery_receipts.as_ref(), || {
                    crate::telemetry::with_captured_scan_telemetry(telemetry.as_ref(), || {
                        let window_len = end - offset;
                        if crate::deadline::expired(deadline) {
                            return Ok((offset, window_len, Vec::new()));
                        }
                        let window_chunk = window_chunk(chunk, offset, end);
                        self.scan_inner(&window_chunk, backend, deadline, route)
                            .map(|matches| (offset, window_len, matches))
                    })
                })
            })
            .collect();

        let mut all_matches = Vec::with_capacity(estimate_window_match_capacity(chunk_text.len()));
        let mut seen = HashSet::new();
        let mut seen_order = VecDeque::new();
        for (offset, window_len, matches) in window_matches? {
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
        Ok(all_matches)
    }

    /// Reached only from the coalesced phase-2 tail, which a portable build
    /// does not compile.
    #[cfg(any(feature = "simd", feature = "gpu", test))]
    pub(crate) fn scan_windowed_with_triggered(
        &self,
        chunk: &Chunk,
        triggered_patterns: &[u64],
        deadline: Option<std::time::Instant>,
        phase2_keyword_hints: Option<&[u32]>,
        phase2_always_active_gpu_evidence: Option<Phase2AlwaysActiveGpuEvidence<'_>>,
        confirmed_anchor_literal_matches: Option<&[(u32, u32)]>,
        generic_keyword_positions: Option<&[u32]>,
        backend: crate::hw_probe::ScanBackend,
        route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<Vec<RawMatch>> {
        use rayon::prelude::*;

        let chunk_text = &chunk.data;
        if reject_oversized_window_chunk(chunk, chunk_text) {
            return Ok(Vec::new());
        }
        let mut all_matches = Vec::with_capacity(estimate_window_match_capacity(chunk_text.len()));
        let mut seen = HashSet::new();
        let mut seen_order = VecDeque::new();
        let line_offsets = crate::compute_line_offsets(chunk_text);
        let ranges = window_ranges(chunk_text, MAX_SCAN_CHUNK_BYTES, WINDOW_OVERLAP_BYTES);
        let telemetry = crate::telemetry::capture_scan_telemetry();
        let recovery_receipts = crate::gpu::capture_recovery_receipts();
        let profile_runtime = keyhog_profile::current_runtime();

        let window_matches: crate::error::Result<Vec<(usize, usize, Vec<RawMatch>)>> = ranges
            .par_iter()
            .map(|&(offset, end)| {
                let _profile_context = profile_runtime.as_ref().map(keyhog_profile::Runtime::enter);
                crate::gpu::with_captured_recovery_receipts(recovery_receipts.as_ref(), || {
                    crate::telemetry::with_captured_scan_telemetry(telemetry.as_ref(), || {
                        let window_len = end - offset;
                        if crate::deadline::expired(deadline) {
                            return Ok((offset, window_len, Vec::new()));
                        }
                        let window_chunk = window_chunk(chunk, offset, end);
                        let prepared = self.prepare_chunk(&window_chunk);
                        let window_phase2_always_anchor_matches;
                        let phase2_always_evidence =
                            if let Some(evidence) = phase2_always_active_gpu_evidence {
                                if let Some(matches) = evidence.anchor_literal_matches {
                                    window_phase2_always_anchor_matches = matches
                                        .iter()
                                        .filter_map(|&(literal_idx, pos)| {
                                            let pos = pos as usize;
                                            (pos >= offset && pos < end)
                                                .then(|| (literal_idx, (pos - offset) as u32))
                                        })
                                        .collect::<Vec<_>>();
                                    Some(Phase2AlwaysActiveGpuEvidence {
                                        anchor_literal_matches: Some(
                                            window_phase2_always_anchor_matches.as_slice(),
                                        ),
                                        ..evidence
                                    })
                                } else {
                                    Some(evidence)
                                }
                            } else {
                                None
                            };
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
                            triggered_patterns,
                            deadline,
                            false,
                            false,
                            phase2_keyword_hints,
                            phase2_always_evidence,
                            confirmed_anchor_matches,
                            generic_positions,
                            backend,
                            route,
                        )?;
                        Ok((offset, window_len, matches))
                    })
                })
            })
            .collect();
        let window_matches = window_matches?;

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

        Ok(all_matches)
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
