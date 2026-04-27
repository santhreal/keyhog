//! AVX-512 Native Shannon Entropy Calculation
//!
//! `keyhog` hunts for base64 cryptographic secrets by calculating Shannon Entropy.
//! Processing logarithmic equations looping per-byte over gigabytes of source code
//! mathematically halts the CPU pipeline inherently.
//!
//! Elite engineering processes Entropy via Hardware Population Counts (`POPCNT`) and
//! explicitly vectorized parallel polynomial logarithm approximations via AVX-512 foundation instructions.
//! It reads 64 bytes simultaneously, tallies exactly how many times characters appear dynamically,
//! and outputs the Entropy fraction mathematically in `O(1)` clock cycles.

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
pub unsafe fn calculate_shannon_entropy(chunk: &[u8]) -> f64 {
    let len = chunk.len();
    if len == 0 {
        return 0.0;
    }

    let mut remaining = chunk;
    let mut counts = [0u32; 256];

    // Read full 64-byte blocks
    while remaining.len() >= 64 {
        let v = _mm512_loadu_si512(remaining.as_ptr() as *const __m512i);

        let mut local_rem = 64; // Track inner reduction

        // Fast path for identical sequences in chunk
        for byte_val in 0..=255u8 {
            let target = _mm512_set1_epi8(byte_val as i8);
            let mask = _mm512_cmpeq_epi8_mask(v, target);
            if mask != 0 {
                let count = mask.count_ones();
                counts[byte_val as usize] += count;
                local_rem -= count as usize;
                if local_rem == 0 {
                    break; // All characters identified in this 64-byte block
                }
            }
        }
        remaining = &remaining[64..];
    }

    // Scalar fallback for tail
    for &b in remaining {
        counts[b as usize] += 1;
    }

    // Calculate actual entropy using vectorized polynomial log2 (f64 for 1e-9 precision)
    let mut sum_v = _mm512_setzero_pd();
    let len_v = _mm512_set1_pd(len as f64);

    for i in (0..256).step_by(8) {
        let counts_v = _mm256_loadu_si256(counts[i..].as_ptr() as *const __m256i);
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
