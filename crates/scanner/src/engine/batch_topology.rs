use keyhog_core::Chunk;

pub(crate) const SMALL_CHUNK_MAX_BYTES: usize = 64 * 1024;
const MAX_SMALL_LANE_BYTES_TARGET: usize = 512 * 1024;

/// One independently scheduled work item in a chunk batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CoalescedLane {
    /// A range into the topology's flat small-chunk index buffer.
    Small(std::ops::Range<usize>),
    /// A large chunk that must never wait behind another chunk in its lane.
    Large(usize),
}

pub(crate) struct CoalescedWorkLanes {
    small_indices: Vec<usize>,
    lanes: Vec<CoalescedLane>,
}

impl CoalescedWorkLanes {
    pub(crate) fn lanes(&self) -> &[CoalescedLane] {
        &self.lanes
    }

    pub(crate) fn indices<'a>(&'a self, lane: &'a CoalescedLane) -> &'a [usize] {
        match lane {
            CoalescedLane::Small(range) => self
                .small_indices
                .get(range.clone())
                .expect("small-lane range must remain inside the flat index buffer"),
            CoalescedLane::Large(index) => std::slice::from_ref(index),
        }
    }

    pub(crate) fn storage_shape(&self) -> (usize, usize, usize) {
        let small_lanes = self
            .lanes
            .iter()
            .filter(|lane| matches!(lane, CoalescedLane::Small(_)))
            .count();
        (
            small_lanes,
            self.small_indices.len(),
            usize::from(!self.small_indices.is_empty()),
        )
    }
}

/// Builds the scheduler topology used by every parallel chunk dispatch path.
pub(super) fn coalesced_work_lanes(
    chunks: &[Chunk],
    threshold_bytes: usize,
) -> CoalescedWorkLanes {
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
                lanes.push(CoalescedLane::Small(start..small_indices.len()));
            } else {
                lanes.push(CoalescedLane::Large(index));
            }
        }
        return CoalescedWorkLanes {
            small_indices,
            lanes,
        };
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
    let large_count = chunks.len() - small_indices.len();
    let small_lane_count = small_indices.len().div_ceil(lane_width);
    let lane_count = small_lane_count
        .checked_add(large_count)
        .expect("coalesced lane count cannot exceed the chunk count");
    let mut lanes = Vec::with_capacity(lane_count);
    let mut start: usize = 0;
    for indices in small_indices.chunks(lane_width) {
        let end = start
            .checked_add(indices.len())
            .expect("small-lane range cannot exceed the flat index buffer");
        lanes.push(CoalescedLane::Small(start..end));
        start = end;
    }
    for (index, chunk) in chunks.iter().enumerate() {
        if !is_small(chunk) {
            lanes.push(CoalescedLane::Large(index));
        }
    }
    CoalescedWorkLanes {
        small_indices,
        lanes,
    }
}
