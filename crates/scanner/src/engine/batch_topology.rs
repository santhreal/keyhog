use keyhog_core::Chunk;

const SMALL_CHUNK_MAX_BYTES: usize = 64 * 1024;
const MAX_LANE_BYTES_TARGET: usize = 512 * 1024;

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

        // Scheduling groups contiguous chunks in one sequential lane. Bound
        // every possible lane by the largest admitted chunk, not the average:
        // averages let one skewed small-chunk batch exceed the lane ceiling.
        let raw_lane_width = evidence.total_chunks.div_ceil(workers);
        let bytes_bounded_width = if evidence.max_chunk_bytes > 0 {
            (MAX_LANE_BYTES_TARGET / evidence.max_chunk_bytes).max(1)
        } else {
            raw_lane_width
        };

        let lane_width = if evidence.large_chunks > 0 {
            // Any oversized chunk keeps per-chunk scheduling so a slow file
            // cannot strand otherwise-idle workers and memory remains bounded.
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
    let workers = rayon::current_num_threads().max(1);
    let evidence = BatchEvidence::measure(chunks);
    BatchTopology::select(&evidence, workers).lane_width
}
