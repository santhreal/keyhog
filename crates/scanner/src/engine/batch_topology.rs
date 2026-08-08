use keyhog_core::Chunk;

pub(crate) const SMALL_CHUNK_MAX_BYTES: usize = 64 * 1024;
const MAX_LANE_BYTES_TARGET: usize = 512 * 1024;
#[allow(dead_code)]
pub(super) const CANDIDATE_LANE_THRESHOLDS: &[usize] = &[
    16 * 1024,
    32 * 1024,
    64 * 1024,
    128 * 1024,
    256 * 1024,
];

/// Batch evidence collected to select a deterministic topology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BatchEvidence {
    pub total_chunks: usize,
    pub small_chunks: usize,
    pub large_chunks: usize,
    pub total_bytes: usize,
    pub max_chunk_bytes: usize,
}

impl BatchEvidence {
    pub(crate) fn measure(chunks: &[Chunk]) -> Self {
        let mut small_chunks = 0;
        let mut large_chunks = 0;
        let mut total_bytes: usize = 0;
        let mut max_chunk_bytes = 0;
        for chunk in chunks {
            let len = chunk.data.len();
            total_bytes = total_bytes.saturating_add(len);
            if len > max_chunk_bytes {
                max_chunk_bytes = len;
            }
            if len <= SMALL_CHUNK_MAX_BYTES {
                small_chunks += 1;
            } else {
                large_chunks += 1;
            }
        }
        Self {
            total_chunks: chunks.len(),
            small_chunks,
            large_chunks,
            total_bytes,
            max_chunk_bytes,
        }
    }
}

/// Deterministic topology configuration for batch execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BatchTopology {
    pub lane_width: usize,
    pub fused_waves: usize,
    pub max_memory_per_lane_bytes: usize,
}

impl BatchTopology {
    pub(crate) fn select(evidence: &BatchEvidence, workers: usize) -> Self {
        let workers = workers.max(1);
        if evidence.total_chunks == 0 {
            return Self {
                lane_width: 1,
                fused_waves: 1,
                max_memory_per_lane_bytes: 0,
            };
        }
        if evidence.total_chunks <= workers {
            return Self {
                lane_width: 1,
                fused_waves: 1,
                max_memory_per_lane_bytes: evidence.max_chunk_bytes,
            };
        }

        let raw_lane_width = evidence.total_chunks.div_ceil(workers);
        let avg_bytes = evidence.total_bytes / evidence.total_chunks;
        let bytes_bounded_width = if avg_bytes > 0 {
            (MAX_LANE_BYTES_TARGET / avg_bytes).max(1)
        } else {
            raw_lane_width
        };

        let lane_width = if evidence.large_chunks > 0 && evidence.small_chunks > 0 {
            raw_lane_width.min(bytes_bounded_width).max(1)
        } else if evidence.large_chunks == evidence.total_chunks {
            1
        } else {
            raw_lane_width.min(bytes_bounded_width).max(1)
        };

        let max_lane_bytes = lane_width.saturating_mul(evidence.max_chunk_bytes);
        let total_lanes = evidence.total_chunks.div_ceil(lane_width);
        let fused_waves = total_lanes.div_ceil(workers).max(1);
        Self {
            lane_width,
            fused_waves,
            max_memory_per_lane_bytes: max_lane_bytes,
        }
    }
}

/// Groups tiny chunks into one sequential lane per worker while preserving
/// per-chunk result order. Large chunks remain independently scheduled so a
/// slow file cannot strand otherwise-idle workers.
pub(crate) fn coalesced_lane_width(chunks: &[Chunk]) -> usize {
    coalesced_lane_width_with_threshold(chunks, SMALL_CHUNK_MAX_BYTES)
}

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
        small_chunk_count.div_ceil(workers).max(1)
    }
}

#[allow(dead_code)]
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

    #[test]
    fn test_coalesced_lane_width_with_threshold_mixed_batches() {
        let small_data = "x".repeat(1024);
        let large_data = "y".repeat(128 * 1024);
        let mut chunks = Vec::new();
        for i in 0..20 {
            if i % 2 == 0 {
                chunks.push(Chunk::from(small_data.as_str()));
            } else {
                chunks.push(Chunk::from(large_data.as_str()));
            }
        }
        let w_16k = coalesced_lane_width_with_threshold(&chunks, 16 * 1024);
        let w_256k = coalesced_lane_width_with_threshold(&chunks, 256 * 1024);
        assert!(w_16k >= 1);
        assert!(w_256k >= w_16k);
    }
}

