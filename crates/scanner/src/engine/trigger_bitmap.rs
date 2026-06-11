//! Shared dense trigger-bitmap primitives.
//!
//! A *trigger bitmap* is a `Vec<u64>` with one bit per pattern index (AC literal
//! + fallback regex): bit `i` set means "pattern `i` may match this chunk, run
//! its extraction". The same three operations — allocate `n_patterns.div_ceil(64)`
//! zeroed words, set bit `i`, and walk every set bit — were open-coded across
//! `backend_triggered` and `scan_postprocess`. Funneling
//! them through one module means the word width and `div_ceil(64)` sizing live in
//! exactly one place (so a future width change can't update only some sites) and
//! the hot bit-walk has a single, audited implementation.
//!
//! Everything here is `#[inline(always)]` on the hot paths so the helpers compile
//! to the same code the open-coded loops did — this is a deduplication, not an
//! abstraction that costs cycles.

/// Allocate a zeroed trigger bitmap with one bit per pattern index.
#[inline]
pub(crate) fn new_trigger_bitmap(n_patterns: usize) -> Vec<u64> {
    vec![0u64; n_patterns.div_ceil(64)]
}

/// Invoke `f` with the pattern index of every set bit, ascending.
///
/// The index is `word_idx * 64 + bit`. Trailing padding bits in the final word
/// are always zero (the bitmap is sized to the exact pattern count and only valid
/// indices are ever set), so `f` is never called for an out-of-range index — but
/// callers that index fallibly should still guard, as the open-coded loops did.
#[inline(always)]
pub(crate) fn for_each_set_bit(words: &[u64], mut f: impl FnMut(usize)) {
    for (word_idx, &word) in words.iter().enumerate() {
        let mut bits = word;
        while bits != 0 {
            f(word_idx * 64 + bits.trailing_zeros() as usize);
            bits &= bits - 1; // clear the lowest set bit
        }
    }
}
