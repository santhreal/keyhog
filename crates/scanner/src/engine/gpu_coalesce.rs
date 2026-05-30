// The function signature below references `keyhog_core::Chunk` via the
// full path; no top-level `use` is needed.
const COALESCE_SEPARATOR_LEN: usize = 8;
const COALESCE_SEPARATOR_BYTE: u8 = 0xFF;

/// Build the contiguous GPU input buffer from `chunks`.
///
/// The returned `Vec<u8>` is a full second copy of the batch corpus (up to
/// the documented 256 MiB-1 GiB), so peak RSS is 2x the batch while both it
/// and the original `chunks` slice are live. Ownership is handed to the
/// caller precisely so the caller can `drop(buffer)` the instant the GPU
/// dispatch returns its matches (`pipeline.scan` yields owned
/// pattern_id/start/end), collapsing the 2x window back to 1x before the
/// per-chunk extraction phase. Callers (gpu_megascan / gpu_literal_phase1 /
/// gpu_ac_phase1) MUST drop the buffer immediately after dispatch; holding
/// it to end-of-scope straddles the peak-memory extraction window.
pub fn coalesce_chunks(chunks: &[keyhog_core::Chunk]) -> (Vec<(usize, usize, usize)>, Vec<u8>) {
    // Reserve once: data + (n-1) separators. Empirically this single big
    // allocation is the main cost of `coalesce_chunks` on a typical
    // 256 MiB batch (and even more on 1 GiB batches on big-VRAM hosts);
    // pre-sizing avoids the geometric `Vec::push` regrowth path entirely.
    let total_bytes: usize = chunks.iter().map(|chunk| chunk.data.len()).sum();
    let separators_total = chunks.len().saturating_sub(1) * COALESCE_SEPARATOR_LEN;
    let mut entries = Vec::with_capacity(chunks.len());
    let mut buffer = Vec::with_capacity(total_bytes + separators_total);

    for (index, chunk) in chunks.iter().enumerate() {
        if index > 0 {
            // Sentinel between chunks. Without this a literal that spans
            // chunk-N's tail and chunk-N+1's head would phantom-match on
            // GPU and have to be filtered out post-hoc. The 0xFF bytes
            // are guaranteed-non-text (>0x7F, not valid UTF-8 lead) so
            // they cannot produce spurious matches against any of the
            // detector literals (all ASCII).
            buffer.resize(
                buffer.len() + COALESCE_SEPARATOR_LEN,
                COALESCE_SEPARATOR_BYTE,
            );
        }
        let start = buffer.len();
        buffer.extend_from_slice(chunk.data.as_bytes());
        entries.push((index, start, chunk.data.len()));
    }

    (entries, buffer)
}
