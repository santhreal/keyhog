//! AVX-512 Native Shannon Entropy Calculation
//!
//! `keyhog` hunts for base64 cryptographic secrets by calculating Shannon Entropy.
//! Processing logarithmic equations looping per-byte over gigabytes of source code
//! mathematically halts the CPU pipeline inherently.
//!
//! The byte-tally pass is a multi-stream scalar histogram (manual ILP, not a
//! vector gather), shared with every other path via
//! [`crate::entropy::fast::histogram_8way`]. The 256-bin entropy reduction is
//! the shared exact [`crate::entropy::fast::entropy_from_histogram`], counting
//! is the memory-bound part, so the reduction is negligible work and is kept
//! bit-identical across all ISA paths rather than re-derived with a vectorized
//! polynomial `log2` (which diverged from the scalar reference by ~5e-3
//! bits/byte and could flip an entropy gate near a threshold).
//!
//! ## Histogram strategy
//!
//! Building a 256-bin histogram is intrinsically scatter-gather: every byte
//! indexes a different counter, which AVX-512 cannot express without
//! `VPCONFLICTD`-style conflict detection. Rather than pay that cost, the
//! counting pass uses independent scalar streams:
//!
//! 1. **Scalar unrolled (baseline):** single-array unrolled scalar loop.
//!    Cache-friendly because `counts[256]` fits in a few L1 lines, but
//!    throughput is limited to ~1 byte/cycle by the load-add-store
//!    dependency chain.
//!
//! 2. **Multi-stream scalar histograms (this impl):** Maintain 8 independent
//!    `[u32; 256]` arrays, each processing every 8th byte. The streams have
//!    no address conflicts (different indices in different arrays), so the
//!    out-of-order engine can issue all 8 load-add-stores in parallel,
//!    saturating more execution ports than the 4-stream variant. Measured
//!    several x faster than single-array on Zen 4 / Sapphire Rapids for inputs
//!    > 256 bytes; the dominant counting loop remains scalar with manual ILP,
//!    not a true vector histogram. This lives in the shared
//!    [`crate::entropy::fast::histogram_8way`] so the count is bit-identical
//!    across every ISA path.

/// Hardware-native Shannon Entropy evaluation via AVX-512.
///
/// The histogram (the memory-bound part) is the shared multi-stream scalar
/// [`crate::entropy::fast::histogram_8way`]; the 256-bin reduction is the shared
/// exact [`crate::entropy::fast::entropy_from_histogram`]. This path is kept as a
/// distinct dispatch slot (gated on `avx512f`+`avx512bw`+`avx512dq`) for ABI and
/// future-vectorization reasons, but it is now bit-identical to the scalar path:
/// the previous vectorized polynomial-`log2` reduction diverged from the exact
/// reference by ~5e-3 bits/byte for no measurable speedup (the 256-bin loop is a
/// negligible fraction of the work), so soundness wins.
///
/// # Safety
///
/// The CPU executing this call must support both `avx512f` and
/// `avx512bw`. The function is annotated with `#[target_feature]`
/// covering those instruction sets, so the caller is responsible for
/// gating dispatch on a runtime feature probe (see
/// `is_x86_feature_detected!("avx512f")`). Calling on unsupported
/// hardware is undefined behaviour.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512bw")]
#[allow(unsafe_op_in_unsafe_fn)]
pub(crate) unsafe fn calculate_shannon_entropy(chunk: &[u8]) -> f64 {
    if chunk.is_empty() {
        return 0.0;
    }

    // The byte tally and the null-byte contract live in the shared
    // `histogram_8way` (8 independent scalar accumulators, counting is
    // memory-bound, so there is no AVX-512 histogram to win here); the 256-bin
    // entropy reduction is the shared exact `entropy_from_histogram`.
    let (counts, active_len) = crate::entropy::fast::histogram_8way(chunk);
    crate::entropy::fast::entropy_from_histogram(&counts, active_len)
}
