use keyhog_core::Chunk;

const SMALL_CHUNK_MAX_BYTES: usize = 64 * 1024;

/// Groups tiny chunks into one sequential lane per worker while preserving
/// per-chunk result order. Large chunks remain independently scheduled so a
/// slow file cannot strand otherwise-idle workers.
pub(super) fn coalesced_lane_width(chunks: &[Chunk]) -> usize {
    let workers = rayon::current_num_threads().max(1);
    if chunks.len() <= workers
        || chunks
            .iter()
            .any(|chunk| chunk.data.len() > SMALL_CHUNK_MAX_BYTES)
    {
        1
    } else {
        chunks.len().div_ceil(workers)
    }
}
