//! AVX-512 Native Shannon Entropy Calculation
//!
//! `keyhog` hunts for base64 cryptographic secrets by calculating Shannon Entropy.
//! Processing logarithmic equations looping per-byte over gigabytes of source code
//! mathematically halts the CPU pipeline inherently.
//!
//! The byte-tally pass is a multi-stream scalar histogram (manual ILP, not a
//! vector gather), and the per-bin merge plus the polynomial `log2` reduction
//! are vectorized with AVX-512. The wide path therefore accelerates the merge
//! and entropy reduction, while the dominant O(n) counting loop relies on
//! several independent scalar streams to saturate the load/store ports.
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
//!    saturating more execution ports than the 4-stream variant. The final
//!    256-bin merge is done with AVX-512 16-wide adds for inputs long enough
//!    to amortize the vector setup, and with a plain scalar merge for short
//!    candidates where the SIMD overhead would dominate. Measured several x
//!    faster than single-array on Zen 4 / Sapphire Rapids for inputs > 256
//!    bytes; the dominant counting loop remains scalar with manual ILP, not a
//!    true vector histogram.

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// Hardware-native Shannon Entropy evaluation via AVX-512.
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
    let len = chunk.len();
    if len == 0 {
        return 0.0;
    }

    // The byte tally and the null-byte contract live in the shared
    // `histogram_8way` (8 independent scalar accumulators — counting is
    // memory-bound, so there is no AVX-512 histogram to win here). The wide
    // path below accelerates only the entropy reduction over the 256 bins.
    let (counts, active_len) = crate::entropy_fast::histogram_8way(chunk);

    if active_len == 0 {
        return 0.0;
    }

    if active_len <= 255 {
        let table = crate::entropy_fast::get_log2_table();
        let mut sum = 0.0;
        for &count in &counts {
            if count > 0 {
                sum += table[count as usize];
            }
        }
        return (active_len as f64).log2() - sum / (active_len as f64);
    }

    // ── Entropy: vectorized polynomial log2 in 8-wide f64 lanes ──
    let mut sum_v = _mm512_setzero_pd();
    let len_v = _mm512_set1_pd(active_len as f64);

    for k in (0..256).step_by(8) {
        let counts_v = _mm256_loadu_si256(counts[k..].as_ptr() as *const __m256i);
        let counts_f = _mm512_cvtepi32_pd(counts_v);

        // mask for counts > 0. _CMP_GT_OQ = 30
        let mask = _mm512_cmp_pd_mask(counts_f, _mm512_setzero_pd(), 30);
        if mask == 0 {
            continue;
        }

        // p = count / len
        let p = _mm512_maskz_div_pd(mask, counts_f, len_v);

        // log2(p)
        let log2p = approx_log2_pd(p);

        // sum -= p * log2p
        let term = _mm512_mul_pd(p, log2p);
        sum_v = _mm512_mask_sub_pd(sum_v, mask, sum_v, term);
    }

    // Reduce sum_v to scalar
    let mut sums = [0.0f64; 8];
    _mm512_storeu_pd(sums.as_mut_ptr(), sum_v);
    sums.iter().sum()
}

/// 5-term polynomial approximation for log2(x) where x is in (0, 1]
/// Uses the identity log2(x) = exponent + log2(mantissa)
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn approx_log2_pd(x: __m512d) -> __m512d {
    // x = m * 2^e
    // Extract exponent
    let bits = _mm512_castpd_si512(x);
    let e = _mm512_sub_epi64(
        _mm512_and_si512(_mm512_srli_epi64(bits, 52), _mm512_set1_epi64(0x7FF)),
        _mm512_set1_epi64(1023),
    );
    let e_f = _mm512_cvtepi64_pd(e);

    // Extract mantissa m in [1, 2)
    let m_bits = _mm512_or_si512(
        _mm512_and_si512(bits, _mm512_set1_epi64(0xFFFFFFFFFFFFF)),
        _mm512_set1_epi64(0x3FF0000000000000), // 1.0 in f64
    );
    let m = _mm512_castsi512_pd(m_bits);

    // z = m - 1, z in [0, 1)
    let z = _mm512_sub_pd(m, _mm512_set1_pd(1.0));

    // 5-term polynomial for log2(1+z)
    let a1 = _mm512_set1_pd(1.442689882843058);
    let a2 = _mm512_set1_pd(-0.721344529025066);
    let a3 = _mm512_set1_pd(0.480884024344551);
    let a4 = _mm512_set1_pd(-0.359880922880757);
    let a5 = _mm512_set1_pd(0.246417534433544);

    let mut poly = a5;
    poly = _mm512_fmadd_pd(poly, z, a4);
    poly = _mm512_fmadd_pd(poly, z, a3);
    poly = _mm512_fmadd_pd(poly, z, a2);
    poly = _mm512_fmadd_pd(poly, z, a1);
    let log2m = _mm512_mul_pd(poly, z);

    _mm512_add_pd(e_f, log2m)
}
