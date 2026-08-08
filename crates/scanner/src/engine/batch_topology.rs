use keyhog_core::Chunk;

pub(crate) const SMALL_CHUNK_MAX_BYTES: usize = 64 * 1024;
pub(super) const CANDIDATE_LANE_THRESHOLDS: &[usize] = &[
    16 * 1024,
    32 * 1024,
    64 * 1024,
    128 * 1024,
    256 * 1024,
];

/// Groups tiny chunks into one sequential lane per worker while preserving
/// per-chunk result order. Large chunks remain independently scheduled so a
/// slow file cannot strand otherwise-idle workers.
#[allow(dead_code)]
pub(super) fn coalesced_lane_width(chunks: &[Chunk]) -> usize {
    coalesced_lane_width_with_threshold(chunks, SMALL_CHUNK_MAX_BYTES)
}

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

/// Sweeps candidate chunk lane thresholds for performance analysis.
#[must_use]
pub(super) fn sweep_chunk_lane_thresholds(chunks: &[Chunk]) -> Vec<(usize, usize)> {
    CANDIDATE_LANE_THRESHOLDS
        .iter()
        .map(|&thresh| (thresh, coalesced_lane_width_with_threshold(chunks, thresh)))
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coalesced_lane_width_threshold_sweep() {
        let chunk1 = Chunk::from("small chunk data");
        let chunk2 = Chunk::from("another small chunk data");
        let chunks = vec![chunk1, chunk2];
        let sweep = sweep_chunk_lane_thresholds(&chunks);
        assert_eq!(sweep.len(), CANDIDATE_LANE_THRESHOLDS.len());
        for &(thresh, width) in &sweep {
            assert!(thresh > 0);
            assert!(width >= 1);
        }
    }
}
