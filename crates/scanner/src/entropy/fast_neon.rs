//! Neon optimized Shannon entropy for aarch64.

/// AArch64 entropy: shared multi-stream histogram + shared exact reduction.
///
/// Counting (the memory-bound part) and the null-byte contract live in the
/// shared [`crate::entropy::fast::histogram_8way`]; the 256-bin reduction is the
/// shared exact [`crate::entropy::fast::entropy_from_histogram`]. Funnelling both
/// through the one definition keeps this path bit-identical to scalar/AVX2/SSE2
/// (KH-25, KH-28, KH-34).
#[cfg(target_arch = "aarch64")]
pub(crate) fn shannon_entropy_neon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let (counts, active_len) = crate::entropy::fast::histogram_8way(data);
    crate::entropy::fast::entropy_from_histogram(&counts, active_len)
}
