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

    // ── Histogram: 8-way parallel to break the load-add-store dependency ──
    //
    // A single `counts[b] += 1` has a multi-cycle dependency chain on x86
    // (load → add → store, plus the index computation). By keeping 8
    // independent histogram arrays and assigning every 8th byte to each,
    // we give the out-of-order engine 8 independent chains to schedule,
    // saturating more load/store ports than a 4-stream split. This is a
    // scalar histogram with manual ILP, not an AVX-512 gather; the wide
    // instructions below only accelerate the per-bin merge and the entropy
    // reduction. The 256-element merge is negligible compared to the
    // per-byte cost on any input > 256 bytes.
    let mut c0 = [0u32; 256];
    let mut c1 = [0u32; 256];
    let mut c2 = [0u32; 256];
    let mut c3 = [0u32; 256];
    let mut c4 = [0u32; 256];
    let mut c5 = [0u32; 256];
    let mut c6 = [0u32; 256];
    let mut c7 = [0u32; 256];

    let ptr = chunk.as_ptr();
    let mut i = 0usize;

    // Process 16 bytes per iteration (2 bytes × 8 lanes)
    let end16 = len & !15;
    while i < end16 {
        c0[*ptr.add(i) as usize] += 1;
        c1[*ptr.add(i + 1) as usize] += 1;
        c2[*ptr.add(i + 2) as usize] += 1;
        c3[*ptr.add(i + 3) as usize] += 1;
        c4[*ptr.add(i + 4) as usize] += 1;
        c5[*ptr.add(i + 5) as usize] += 1;
        c6[*ptr.add(i + 6) as usize] += 1;
        c7[*ptr.add(i + 7) as usize] += 1;
        c0[*ptr.add(i + 8) as usize] += 1;
        c1[*ptr.add(i + 9) as usize] += 1;
        c2[*ptr.add(i + 10) as usize] += 1;
        c3[*ptr.add(i + 11) as usize] += 1;
        c4[*ptr.add(i + 12) as usize] += 1;
        c5[*ptr.add(i + 13) as usize] += 1;
        c6[*ptr.add(i + 14) as usize] += 1;
        c7[*ptr.add(i + 15) as usize] += 1;
        i += 16;
    }
    // Remainder
    while i < len {
        c0[*ptr.add(i) as usize] += 1;
        i += 1;
    }

    // ── Merge the 8 streams into a single histogram ──
    //
    // For inputs long enough to amortize the vector setup, merge with
    // AVX-512 16-wide adds. For short candidates (typical 20-64 byte
    // tokens) the SIMD setup can exceed a plain scalar count, so fall back
    // to a scalar merge below the crossover.
    let mut counts = [0u32; 256];
    if len >= 256 {
        let mut j = 0;
        while j < 256 {
            let v0 = _mm512_loadu_si512(c0[j..].as_ptr() as *const _);
            let v1 = _mm512_loadu_si512(c1[j..].as_ptr() as *const _);
            let v2 = _mm512_loadu_si512(c2[j..].as_ptr() as *const _);
            let v3 = _mm512_loadu_si512(c3[j..].as_ptr() as *const _);
            let v4 = _mm512_loadu_si512(c4[j..].as_ptr() as *const _);
            let v5 = _mm512_loadu_si512(c5[j..].as_ptr() as *const _);
            let v6 = _mm512_loadu_si512(c6[j..].as_ptr() as *const _);
            let v7 = _mm512_loadu_si512(c7[j..].as_ptr() as *const _);
            let sum01 = _mm512_add_epi32(v0, v1);
            let sum23 = _mm512_add_epi32(v2, v3);
            let sum45 = _mm512_add_epi32(v4, v5);
            let sum67 = _mm512_add_epi32(v6, v7);
            let sum0123 = _mm512_add_epi32(sum01, sum23);
            let sum4567 = _mm512_add_epi32(sum45, sum67);
            let sum = _mm512_add_epi32(sum0123, sum4567);
            _mm512_storeu_si512(counts[j..].as_mut_ptr() as *mut _, sum);
            j += 16;
        }
    } else {
        for b in 0..256 {
            counts[b] = c0[b] + c1[b] + c2[b] + c3[b] + c4[b] + c5[b] + c6[b] + c7[b];
        }
    }

    // ── Entropy: vectorized polynomial log2 in 8-wide f64 lanes ──
    let mut sum_v = _mm512_setzero_pd();
    let len_v = _mm512_set1_pd(len as f64);

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
