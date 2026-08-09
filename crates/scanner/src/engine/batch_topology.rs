use keyhog_core::Chunk;

pub(crate) const SMALL_CHUNK_MAX_BYTES: usize = 64 * 1024;

/// Calculates coalesced worker lane width given a configurable chunk size threshold.
/// Enables sweeping small file performance thresholds across varied workload distributions.
pub(super) fn coalesced_lane_width_with_threshold(
    chunks: &[Chunk],
    threshold_bytes: usize,
) -> usize {
    let workers = rayon::current_num_threads().max(1);
    if chunks.len() <= workers {
        return 1;
    }
    let small_chunk_count = chunks
        .iter()
        .filter(|chunk| chunk.data.len() <= threshold_bytes)
        .count();
    if small_chunk_count == 0 {
        1
    } else if small_chunk_count == chunks.len() {
        chunks.len().div_ceil(workers)
    } else {
        // Mixed batch: if small chunks exist, coalesce based on small chunk proportion
        small_chunk_count.div_ceil(workers).max(1)
    }
}
