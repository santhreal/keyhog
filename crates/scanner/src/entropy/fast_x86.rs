//! AVX2 optimized Shannon entropy for x86_64.

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
