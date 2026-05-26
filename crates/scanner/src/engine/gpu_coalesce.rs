use keyhog_core::Chunk;

const COALESCE_SEPARATOR_LEN: usize = 8;
const COALESCE_SEPARATOR_BYTE: u8 = 0xFF;

pub(crate) fn coalesce_chunks(
    chunks: &[keyhog_core::Chunk],
) -> (Vec<(usize, usize, usize)>, Vec<u8>) {
    // Reserve once: data + (n-1) separators. Empirically this single big
    // allocation is the main cost of `coalesce_chunks` on a 256 MiB batch;
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
