//! Fast vectorized entropy calculation with architecture-specific implementations.
//!
//! This module uses SIMD instructions (AVX-512, AVX2, SSE2, Neon) to accelerate Shannon
//! entropy calculation. It includes optimized paths for character frequency
//! counting and parallel logarithmic summation.

use std::sync::OnceLock;

static LOG2_TABLE: OnceLock<[f64; 256]> = OnceLock::new();

#[inline]
pub(crate) fn get_log2_table() -> &'static [f64; 256] {
    LOG2_TABLE.get_or_init(|| {
        let mut table = [0.0f64; 256];
        for i in 1..256 {
            let val = i as f64;
            table[i] = val * val.log2();
        }
        table
    })
}

/// The x86_64 SIMD entropy tier, resolved ONCE from the runtime CPU features.
///
/// CPU feature availability is fixed for the life of the process, so the
/// `is_x86_feature_detected!` gates (each a branch plus an atomic load over a
/// std-internal cpuid cache) do NOT belong in the entropy hot loop, where
/// `shannon_entropy_simd` runs once per candidate. This enum records the single
/// winning tier so the loop dispatches on a plain `Copy` value instead.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum X86EntropyTier {
    Avx512,
    Avx2,
    /// The SSE2 baseline (guaranteed on every x86_64 target), whose
    /// histogram+reduction is bit- and codegen-identical to
    /// [`shannon_entropy_scalar`]. Reaching this tier is NOT a silent degrade
    /// (Law 10): it is the correct baseline path, and it is recorded loudly and
    /// exactly once by [`resolve_x86_entropy_tier`].
    Scalar,
}

#[cfg(target_arch = "x86_64")]
static X86_ENTROPY_TIER: OnceLock<X86EntropyTier> = OnceLock::new();

/// Detect the entropy SIMD tier once, record the choice loudly, and cache it.
///
/// SAFETY (dispatch soundness): the runtime probe for a tier MUST be a SUPERSET
/// of every feature the dispatched function's `#[target_feature]` enables
/// entering a `target_feature` fn on a CPU lacking those features is UB/SIGILL
/// (the compiler assumes them throughout the body):
///  - the AVX-512 reduction (`entropy::avx512::calculate_shannon_entropy`)
///    declares `avx512f,avx512bw`; soundness needs only those two. The gate ALSO
///    requires `avx512dq` as deliberate forward-headroom, so a future dq-using
///    re-vectorization of the reduction needs no gate change (entropy/avx512.rs)
///: a sound over-gate, not a current intrinsic need. KH C10/M9.
///  - the AVX2 reduction (`fast_x86::shannon_entropy_avx2`) declares `avx2,fma`,
///    which licenses the compiler to emit FMA3 (VFMADD231PD) in its body, so
///    `fma` is required in addition to `avx2` (else SIGILL on an AVX2-without-FMA
///    CPU/VM). Falling through lands on the SSE2/scalar baseline.
///
/// The feature gates are read here exactly once; the dispatch site consumes the
/// cached tier and performs no further probing.
#[cfg(target_arch = "x86_64")]
pub(crate) fn resolve_x86_entropy_tier() -> X86EntropyTier {
    *X86_ENTROPY_TIER.get_or_init(|| {
        let tier = if is_x86_feature_detected!("avx512f")
            && is_x86_feature_detected!("avx512bw")
            && is_x86_feature_detected!("avx512dq")
        {
            X86EntropyTier::Avx512
        } else if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("fma") {
            X86EntropyTier::Avx2
        } else {
            X86EntropyTier::Scalar
        };
        // Loud, one-time record of the selected path (Law 10: a SIMD→scalar
        // fall-through is surfaced, never silent). Emitted once at first use, so
        // it costs nothing on the per-candidate hot path.
        tracing::info!(
            tier = ?tier,
            "keyhog entropy: selected x86_64 SIMD tier for the Shannon-entropy reduction"
        );
        tier
    })
}

/// Fast entropy calculation dispatched on the once-resolved [`X86EntropyTier`].
#[cfg(target_arch = "x86_64")]
pub(crate) fn shannon_entropy_simd(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    match resolve_x86_entropy_tier() {
        // SAFETY: `resolve_x86_entropy_tier` proved the CPU carries every feature
        // each dispatched `#[target_feature]` fn requires (see its SAFETY note),
        // and CPU features do not change at runtime, so the cached tier stays
        // valid for the life of the process.
        X86EntropyTier::Avx512 => unsafe {
            crate::entropy::avx512::calculate_shannon_entropy(data)
        },
        X86EntropyTier::Avx2 => unsafe { crate::entropy::fast_x86::shannon_entropy_avx2(data) },
        X86EntropyTier::Scalar => shannon_entropy_scalar(data),
    }
}

/// AArch64 true Neon SIMD parallel histogram calculations.
#[cfg(target_arch = "aarch64")]
pub(crate) fn shannon_entropy_simd(data: &[u8]) -> f64 {
    crate::entropy::fast_neon::shannon_entropy_neon(data)
}

/// Generic fallback for all other architectures.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(crate) fn shannon_entropy_simd(data: &[u8]) -> f64 {
    shannon_entropy_scalar(data)
}

/// Canonical byte-frequency histogram carrying KeyHog's null-byte contract.
///
/// Bytes are grouped into 8-byte chunks from offset 0. A fully-null chunk is
/// skipped as binary padding (its 8 bytes leave `active_len`); every other
/// chunk, including one that merely *contains* nulls, is counted in full, as
/// is the sub-8 remainder (a lone trailing null drops out). Returns the merged
/// 256-bin histogram and `active_len` (input length minus the padding bytes).
///
/// This is the single definition of that contract. The scalar path and every
/// SIMD path (`avx2`/`avx512`/`neon`) count through here, so they agree
/// bit-for-bit regardless of pointer alignment or input length. Folding it into
/// one helper also removes the divergence an alignment-prologue histogram used
/// to introduce on short/unaligned inputs, where the byte-at-a-time prologue
/// dropped *every* null individually instead of honoring the 8-byte contract.
///
/// Counting is memory-bound: a single `counts[b] += 1` carries a load-add-store
/// dependency chain, so 8 independent accumulators (every 8th byte) let the
/// out-of-order engine issue 8 chains in parallel and saturate the load/store
/// ports (KH-27). Wider vectors win nothing in the count, they specialize only
/// the entropy summation over the 256 bins.
#[inline]
pub(crate) fn histogram_8way(data: &[u8]) -> ([u32; 256], usize) {
    let mut c0 = [0u32; 256];
    let mut c1 = [0u32; 256];
    let mut c2 = [0u32; 256];
    let mut c3 = [0u32; 256];
    let mut c4 = [0u32; 256];
    let mut c5 = [0u32; 256];
    let mut c6 = [0u32; 256];
    let mut c7 = [0u32; 256];

    let mut active_len = data.len();
    let mut chunks = data.chunks_exact(8);

    for chunk in &mut chunks {
        // Fast-path null check to skip binary padding (KH-27).
        if chunk[0] == 0
            && chunk[1] == 0
            && chunk[2] == 0
            && chunk[3] == 0
            && chunk[4] == 0
            && chunk[5] == 0
            && chunk[6] == 0
            && chunk[7] == 0
        {
            active_len -= 8;
            continue;
        }

        c0[chunk[0] as usize] += 1;
        c1[chunk[1] as usize] += 1;
        c2[chunk[2] as usize] += 1;
        c3[chunk[3] as usize] += 1;
        c4[chunk[4] as usize] += 1;
        c5[chunk[5] as usize] += 1;
        c6[chunk[6] as usize] += 1;
        c7[chunk[7] as usize] += 1;
    }

    for &byte in chunks.remainder() {
        if byte == 0 {
            active_len -= 1;
        } else {
            c0[byte as usize] += 1;
        }
    }

    let mut counts = [0u32; 256];
    for j in 0..256 {
        counts[j] = c0[j] + c1[j] + c2[j] + c3[j] + c4[j] + c5[j] + c6[j] + c7[j];
    }

    (counts, active_len)
}

/// Exact Shannon entropy (bits/byte) from a 256-bin byte histogram and its
/// `active_len` (non-padding byte count).
///
/// This is the single, exact reduction shared by the scalar path and every SIMD
/// path (`avx2`/`avx512`/`neon`). Counting is the memory-bound part and
/// lives in [`histogram_8way`]; the reduction over 256 bins is negligible work,
/// so all paths funnel through this one `f64::log2` reduction and therefore agree
/// to a few ULPs regardless of which ISA produced the histogram.
///
/// A vectorized *polynomial* log2 reduction used to live in the AVX2/AVX512
/// paths. It was removed: the 5-term minimax polynomial diverged from this exact
/// reference by ~5e-3 bits/byte on long inputs, enough to flip an entropy gate
/// near a threshold, while saving no measurable time over a 256-iteration loop
/// (the loop is ~0.0004% of the work on a 64 KiB window). Soundness over a
/// micro-optimization that was never on the hot path.
///
/// Two equivalent forms are used by `active_len`: a `count·log2(count)` table for
/// short inputs (`active_len <= 255`, where every count fits the 256-entry table,
/// KH-28) and the direct `-Σ p·log2 p` form for longer ones. Both branches are
/// keyed on the same `active_len` every path computes identically, so scalar and
/// SIMD always take the same branch.
#[inline]
pub(crate) fn entropy_from_histogram(counts: &[u32; 256], active_len: usize) -> f64 {
    if active_len == 0 {
        return 0.0;
    }

    // Log2 Table Lookup optimization for small active length (KH-28)
    if active_len <= 255 {
        let table = get_log2_table();
        let mut sum = 0.0;
        for &count in counts {
            if count > 0 {
                sum += table[count as usize];
            }
        }
        return (active_len as f64).log2() - sum / (active_len as f64);
    }

    let len_f = active_len as f64;
    let mut entropy = 0.0;
    for &count in counts {
        if count > 0 {
            let p = count as f64 / len_f;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Shannon entropy in bits/byte over the non-padding bytes of `data`.
///
/// Counts through [`histogram_8way`] (the shared null contract), then reduces
/// through the shared exact [`entropy_from_histogram`].
#[inline]
pub(crate) fn shannon_entropy_scalar(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let (counts, active_len) = histogram_8way(data);
    entropy_from_histogram(&counts, active_len)
}
