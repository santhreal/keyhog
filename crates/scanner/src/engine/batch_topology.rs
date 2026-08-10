use keyhog_core::Chunk;

pub(crate) const SMALL_CHUNK_MAX_BYTES: usize = 64 * 1024;
const MAX_SMALL_LANE_BYTES_TARGET: usize = 512 * 1024;

/// One independently scheduled work item in a chunk batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CoalescedLane {
    /// Small chunks scanned sequentially to amortize scheduler overhead.
    Small(Vec<usize>),
    /// A large chunk that must never wait behind another chunk in its lane.
    Large(usize),
}

/// Builds the scheduler topology used by every parallel chunk dispatch path.
pub(super) fn coalesced_work_lanes(chunks: &[Chunk], threshold_bytes: usize) -> Vec<CoalescedLane> {
    coalesced_work_lanes_for_workers(chunks, threshold_bytes, rayon::current_num_threads().max(1))
}

pub(crate) fn coalesced_work_lanes_for_workers(
    chunks: &[Chunk],
    threshold_bytes: usize,
    workers: usize,
) -> Vec<CoalescedLane> {
    let workers = workers.max(1);
    if chunks.len() <= workers {
        return chunks
            .iter()
            .enumerate()
            .map(|(index, chunk)| {
                if chunk.data.len() <= threshold_bytes {
                    CoalescedLane::Small(vec![index])
                } else {
                    CoalescedLane::Large(index)
                }
            })
            .collect();
    }

    let small_indices: Vec<usize> = chunks
        .iter()
        .enumerate()
        .filter_map(|(index, chunk)| (chunk.data.len() <= threshold_bytes).then_some(index))
        .collect();
    let worker_lane_width = small_indices.len().div_ceil(workers).max(1);
    let max_small_chunk_bytes = small_indices
        .iter()
        .map(|&index| chunks[index].data.len())
        .max()
        .unwrap_or(0);
    let byte_bounded_width = if max_small_chunk_bytes == 0 {
        worker_lane_width
    } else {
        (MAX_SMALL_LANE_BYTES_TARGET / max_small_chunk_bytes).max(1)
    };
    let lane_width = worker_lane_width.min(byte_bounded_width).max(1);
    let large_count = chunks.len() - small_indices.len();
    let mut lanes = Vec::with_capacity(small_indices.len().div_ceil(lane_width) + large_count);
    lanes.extend(
        small_indices
            .chunks(lane_width)
            .map(|indices| CoalescedLane::Small(indices.to_vec())),
    );
    lanes.extend(
        chunks
            .iter()
            .enumerate()
            .filter(|(_, chunk)| chunk.data.len() > threshold_bytes)
            .map(|(index, _)| CoalescedLane::Large(index)),
    );
    lanes
}
