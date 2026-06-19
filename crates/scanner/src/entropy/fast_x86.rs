//! AVX2 and SSE2 optimized Shannon entropy and high-entropy heuristic checks for x86_64.

#[cfg(test)]
use crate::entropy::fast::distinct_byte_count;
#[cfg(test)]
use crate::entropy::fast::shannon_entropy_scalar;
use crate::entropy::fast::{entropy_from_histogram, histogram_8way};

/// AVX2 path: the 8-way ILP histogram (the memory-bound part) shared via
/// [`histogram_8way`], then the shared exact [`entropy_from_histogram`] reduction.
///
/// The `#[target_feature(enable = "avx2,fma")]` attribute is retained so this
/// stays a distinct dispatch slot, but the reduction is no longer a vectorized
/// polynomial-log2 (which diverged from the scalar reference by ~5e-3 bits/byte —
/// see [`entropy_from_histogram`]); the 256-bin reduction is negligible and now
/// bit-identical to every other path.
///
/// # Safety
/// The CPU executing this call must support both `avx2` and `fma` (the
/// `#[target_feature]` set). The caller is responsible for gating dispatch on a
/// runtime feature probe (see `shannon_entropy_simd`, which checks
/// `is_x86_feature_detected!("avx2")` + `..("fma")`); invoking on a CPU lacking
/// either is undefined behaviour / SIGILL.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,fma")]
#[allow(unsafe_op_in_unsafe_fn)]
pub(crate) unsafe fn shannon_entropy_avx2(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let (counts, active_len) = histogram_8way(data);
    entropy_from_histogram(&counts, active_len)
}

/// SSE2 path: shared 8-way ILP histogram + shared exact reduction.
///
/// # Safety
/// The CPU must support `sse2`. SSE2 is mandatory on every x86_64 target per the
/// SysV ABI, so the obligation is trivially met on any host the `#[cfg]` permits;
/// the `#[target_feature(enable = "sse2")]` attribute formalizes it.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
#[allow(unsafe_op_in_unsafe_fn)]
pub(crate) unsafe fn shannon_entropy_sse2(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let (counts, active_len) = histogram_8way(data);
    entropy_from_histogram(&counts, active_len)
}

/// High-entropy fast check (x86_64).
///
/// The early-exit decision is shared with the scalar/neon paths via
/// [`distinct_byte_count`] so all three implementations return identical
/// answers for the same input: count the distinct byte values over the FULL
/// buffer and skip the float-heavy reduction only when their log2 ceiling is
/// strictly below the threshold (a buffer of `u` distinct symbols carries at
/// most log2(u) bits/byte). The previous 16-byte middle-only sample was both
/// non-representative (a constant run hiding a high-entropy remainder produced
/// a false negative) and divergent from the scalar 12-byte 3-region sample.
///
/// # Safety
/// The CPU must support `sse2` (mandatory on x86_64 per the SysV ABI). The
/// `#[target_feature(enable = "sse2")]` attribute makes feature presence a caller
/// obligation; the dispatcher (`shannon_entropy_simd` / `has_high_entropy_fast`)
/// gates on `is_x86_feature_detected!("sse2")`. The body takes no raw pointer
/// loads beyond safe slice ops, so soundness reduces to the feature gate.
#[cfg(target_arch = "x86_64")]
#[cfg(test)]
#[target_feature(enable = "sse2")]
#[allow(unsafe_op_in_unsafe_fn)]
pub(crate) unsafe fn has_high_entropy_fast_x86(data: &[u8], threshold: f64) -> bool {
    if data.is_empty() {
        return shannon_entropy_scalar(data) >= threshold;
    }

    let unique = distinct_byte_count(data);
    if (unique as f64).log2() < threshold {
        return false;
    }

    crate::entropy::fast::shannon_entropy_simd(data) >= threshold
}
