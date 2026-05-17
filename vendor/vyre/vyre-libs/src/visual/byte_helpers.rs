//! Shared visual inventory helpers.

/// Convert packed `u32` pixels/words into little-endian bytes for harness IO.
#[must_use]
pub(crate) fn u32_words_to_le_bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}
