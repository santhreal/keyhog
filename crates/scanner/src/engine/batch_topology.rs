use keyhog_core::Chunk;

pub(crate) const SMALL_CHUNK_MAX_BYTES: usize = 64 * 1024;
const MAX_SMALL_LANE_BYTES_TARGET: usize = 512 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CoalescedLane {
    Small(std::ops::Range<usize>),
    Large(usize),
}
type CoalescedWorkLanes = (Vec<usize>, Vec<CoalescedLane>);

/// Builds the scheduler topology used by every parallel chunk dispatch path.
pub(super) fn coalesced_work_lanes(chunks: &[Chunk], threshold_bytes: usize) -> CoalescedWorkLanes {
    coalesced_work_lanes_for_workers(chunks, threshold_bytes, rayon::current_num_threads().max(1))
}

pub(crate) fn coalesced_work_lanes_for_workers(
    chunks: &[Chunk],
    threshold_bytes: usize,
    workers: usize,
) -> CoalescedWorkLanes {
    let workers = workers.max(1);
    if chunks.len() <= workers {
        let mut small_indices = Vec::with_capacity(chunks.len());
        let mut lanes = Vec::with_capacity(chunks.len());
        for (index, chunk) in chunks.iter().enumerate() {
            if chunk.data.len() <= threshold_bytes {
                let start = small_indices.len();
                small_indices.push(index);
                lanes.push(CoalescedLane::Small(start..start + 1));
            } else {
                lanes.push(CoalescedLane::Large(index));
            }
        }
        return (small_indices, lanes);
    }

    let is_small = |chunk: &Chunk| chunk.data.len() <= threshold_bytes;
    let small_count = chunks.iter().filter(|chunk| is_small(chunk)).count();
    let mut small_indices = Vec::with_capacity(small_count);
    small_indices.extend(
        chunks
            .iter()
            .enumerate()
            .filter_map(|(index, chunk)| is_small(chunk).then_some(index)),
    );
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
    let lane_count = small_indices.len().div_ceil(lane_width) + chunks.len() - small_indices.len();
    let mut lanes = Vec::with_capacity(lane_count);
    for start in (0..small_indices.len()).step_by(lane_width) {
        let end = (start + lane_width).min(small_indices.len());
        lanes.push(CoalescedLane::Small(start..end));
    }
    for (index, chunk) in chunks.iter().enumerate() {
        if !is_small(chunk) {
            lanes.push(CoalescedLane::Large(index));
        }
    }
    (small_indices, lanes)
}
