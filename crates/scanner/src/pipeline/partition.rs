//! Chunk partitioning and subdivision for concurrent pipeline execution.
//!
//! Provides deterministic sub-chunk partitioning with overlap for single large
//! files, preserving UTF-8 character boundaries, exact base offsets, base line
//! numbers, and seam safety across chunk boundaries.

use crate::engine::{ceil_char_boundary, floor_char_boundary};
use crate::hw_probe::ScanBackend;
use crate::pipeline::compute_line_offsets;
use crate::CompiledScanner;
use keyhog_core::{Chunk, RawMatch};
use std::collections::HashSet;

/// Minimum chunk size (64 KiB) below which subdivision does not yield parallel gains.
pub const DEFAULT_MIN_PARTITION_CHUNK_BYTES: usize = 64 * 1024;

/// Default window overlap (128 KiB) matching `WINDOW_OVERLAP_BYTES` to ensure
/// seam-straddling credentials are fully contained in at least one window.
pub const DEFAULT_PARTITION_OVERLAP_BYTES: usize = crate::types::WINDOW_OVERLAP_BYTES;

/// Subdivide a `Chunk` into overlapping sub-chunks of approximately `target_window_bytes`
/// with `overlap_bytes` shared between consecutive windows.
///
/// Every sub-chunk maintains UTF-8 character boundary alignment, accurate
/// `base_offset`, accurate `base_line` derived from preceding newlines, and
/// preserves all parent chunk metadata.
pub fn partition_chunk(
    chunk: &Chunk,
    target_window_bytes: usize,
    overlap_bytes: usize,
) -> Vec<Chunk> {
    let text = chunk.data.as_ref();
    if text.is_empty() || text.len() <= target_window_bytes {
        return vec![chunk.clone()];
    }

    let line_offsets = compute_line_offsets(text);
    let mut sub_chunks = Vec::new();
    let mut offset = 0usize;

    while offset < text.len() {
        let start = floor_char_boundary(text, offset);
        let uncapped_end = start.saturating_add(target_window_bytes).min(text.len());
        let end = if uncapped_end >= text.len() {
            text.len()
        } else {
            floor_char_boundary(text, uncapped_end)
        };

        let end = if end <= start {
            ceil_char_boundary(text, (start + 1).min(text.len()))
        } else {
            end
        };

        let sub_text = &text[start..end];
        // Calculate newlines preceding `start` in O(log L) via line_offsets.
        let newlines_before = line_offsets
            .partition_point(|&lo| lo <= start)
            .saturating_sub(1);

        let mut sub_metadata = chunk.metadata.clone();
        sub_metadata.base_offset = chunk.metadata.base_offset.saturating_add(start);
        sub_metadata.base_line = chunk.metadata.base_line.saturating_add(newlines_before);
        sub_chunks.push(Chunk {
            data: sub_text.to_string().into(),
            metadata: sub_metadata,
        });

        if end >= text.len() {
            break;
        }

        let next_offset = ceil_char_boundary(text, end.saturating_sub(overlap_bytes));
        offset = if next_offset > start {
            next_offset
        } else {
            end
        };
    }

    sub_chunks
}

/// Partition a `Chunk` across `worker_count` workers, sizing windows so that each
/// worker receives an equal share above `min_window_bytes` with `overlap_bytes` overlap.
pub fn partition_chunk_for_workers(
    chunk: &Chunk,
    worker_count: usize,
    min_window_bytes: usize,
    overlap_bytes: usize,
) -> Vec<Chunk> {
    let worker_count = worker_count.max(1);
    let total_len = chunk.data.len();
    if worker_count <= 1 || total_len <= min_window_bytes {
        return vec![chunk.clone()];
    }

    let target_window_bytes = (total_len / worker_count)
        .max(min_window_bytes)
        .saturating_add(overlap_bytes);

    partition_chunk(chunk, target_window_bytes, overlap_bytes)
}

/// Deduplicate matches collected across overlapping sub-chunk partitions.
///
/// Findings are sorted by canonical location key `(offset, line, detector_id, credential)`
/// to guarantee deterministic ordering regardless of worker thread completion order.
pub fn deduplicate_partition_matches(matches: impl IntoIterator<Item = RawMatch>) -> Vec<RawMatch> {
    let mut all_matches: Vec<RawMatch> = matches.into_iter().collect();
    all_matches.sort_by(|a, b| {
        a.location
            .offset
            .cmp(&b.location.offset)
            .then_with(|| a.location.line.cmp(&b.location.line))
            .then_with(|| a.detector_id.cmp(&b.detector_id))
            .then_with(|| a.credential.as_bytes().cmp(b.credential.as_bytes()))
    });

    let mut deduped = Vec::with_capacity(all_matches.len());
    let mut seen = HashSet::new();
    for m in all_matches {
        let key = (
            m.location.offset,
            m.location.line,
            m.detector_id.clone(),
            m.credential.clone(),
        );
        if seen.insert(key) {
            deduped.push(m);
        }
    }
    deduped
}

/// Scan a single chunk with concurrent pipeline partitioning across `worker_count` workers.
///
/// Subdivides the chunk into overlapping windows, executes scans in parallel across
/// scoped threads, and deduplicates findings deterministically.
pub fn scan_chunk_partitioned(
    scanner: &CompiledScanner,
    chunk: &Chunk,
    backend: ScanBackend,
    worker_count: usize,
) -> crate::error::Result<Vec<RawMatch>> {
    let worker_count = worker_count.max(1);
    if worker_count <= 1 || chunk.data.len() <= DEFAULT_MIN_PARTITION_CHUNK_BYTES {
        return scanner.scan_with_backend(chunk, backend);
    }

    let sub_chunks = partition_chunk_for_workers(
        chunk,
        worker_count,
        DEFAULT_MIN_PARTITION_CHUNK_BYTES,
        DEFAULT_PARTITION_OVERLAP_BYTES,
    );
    if sub_chunks.len() <= 1 {
        return scanner.scan_with_backend(chunk, backend);
    }

    let telemetry = crate::telemetry::capture_scan_telemetry();
    let recovery_receipts = crate::gpu::capture_recovery_receipts();
    let profile_runtime = keyhog_profile::current_runtime();

    let results = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(sub_chunks.len());
        for sub_chunk in &sub_chunks {
            let telemetry = telemetry.clone();
            let recovery_receipts = recovery_receipts.clone();
            let profile_runtime = profile_runtime.clone();
            let handle = scope.spawn(move || {
                let _profile_context = profile_runtime.as_ref().map(keyhog_profile::Runtime::enter);
                crate::gpu::with_captured_recovery_receipts(recovery_receipts.as_ref(), || {
                    crate::telemetry::with_captured_scan_telemetry(telemetry.as_ref(), || {
                        scanner.scan_with_backend(sub_chunk, backend)
                    })
                })
            });
            handles.push(handle);
        }
        let mut all_results = Vec::with_capacity(handles.len());
        for handle in handles {
            all_results.push(handle.join().map_err(|_| {
                crate::error::ScanError::Config(
                    "worker thread panicked during partitioned scan".to_string(),
                )
            })?);
        }
        Ok::<_, crate::error::ScanError>(all_results)
    })?;

    let mut flattened = Vec::new();
    for sub_res in results {
        flattened.extend(sub_res?);
    }
    Ok(deduplicate_partition_matches(flattened))
}
