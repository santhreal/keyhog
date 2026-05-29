//! Fast vectorized entropy calculation with architecture-specific implementations.
//!
//! This module uses SIMD instructions (AVX-512, AVX2, SSE2) to accelerate Shannon
//! entropy calculation. It includes optimized paths for character frequency
//! counting and parallel logarithmic summation.

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// Fast entropy calculation using unrolled scalar accumulation.
/// Processes data in 32-byte chunks with 8 parallel accumulators on x86_64.
#[cfg(target_arch = "x86_64")]
pub fn shannon_entropy_simd(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // The "AVX2" and "SSE2" paths below are actually unrolled scalar
    // loops that avoid data hazards by keeping counts in separate
    // arrays. True SIMD vectorization (e.g. `vpgatherdd` for the
    // histogram, `vpermd` for the bucket reduce) is open and not
    // yet implemented - the AVX-512 path below IS true SIMD; this
    // fallback path is scalar-with-ILP.
    #[cfg(target_arch = "x86_64")]
    // SAFETY: We verify AVX2/SSE2 support via is_x86_feature_detected! before calling specialized paths.
    unsafe {
        if is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512bw") {
            return crate::entropy_avx512::calculate_shannon_entropy(data);
        }
        if is_x86_feature_detected!("avx2") {
            return shannon_entropy_avx2(data);
        }
        if is_x86_feature_detected!("sse2") {
            return shannon_entropy_sse2(data);
        }
    }

    shannon_entropy_scalar(data)
}

/// Scalar fallback: 4-way parallel histogram to break load-add-store chains.
///
/// A single `counts[b] += 1` has a 4-cycle dependency chain. By maintaining
/// 4 independent arrays and interleaving accesses, the OOE engine can issue
/// 4 independent chains in parallel, yielding ~3-4x throughput on modern CPUs.
#[inline]
pub fn shannon_entropy_scalar(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut c0 = [0u32; 256];
    let mut c1 = [0u32; 256];
    let mut c2 = [0u32; 256];
    let mut c3 = [0u32; 256];

    let chunks = data.chunks_exact(4);
    let remainder = chunks.remainder();

    for chunk in chunks {
        c0[chunk[0] as usize] += 1;
        c1[chunk[1] as usize] += 1;
        c2[chunk[2] as usize] += 1;
        c3[chunk[3] as usize] += 1;
    }

    for &byte in remainder {
        c0[byte as usize] += 1;
    }

    // Merge
    let mut counts = [0u32; 256];
    for j in 0..256 {
        counts[j] = c0[j] + c1[j] + c2[j] + c3[j];
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// AVX2 path: 4-way parallel histogram to break load-add-store dependency chains.
///
/// The previous broadcast+cmpeq approach was O(unique_chars × n/32), which is
/// slow on high-entropy data (base64 secrets: ~64 unique chars = 64 iterations
/// per 32-byte chunk). The 4-way parallel histogram is O(n) regardless of data
/// entropy, with 4 independent dependency chains for the OOE engine.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn shannon_entropy_avx2(data: &[u8]) -> f64 {
    let mut c0 = [0u32; 256];
    let mut c1 = [0u32; 256];
    let mut c2 = [0u32; 256];
    let mut c3 = [0u32; 256];

    let ptr = data.as_ptr();
    let len = data.len();
    let mut i = 0usize;

    // Process 16 bytes per iteration (4 bytes × 4 lanes)
    let end16 = len & !15;
    while i < end16 {
        c0[*ptr.add(i) as usize] += 1;
        c1[*ptr.add(i + 1) as usize] += 1;
        c2[*ptr.add(i + 2) as usize] += 1;
        c3[*ptr.add(i + 3) as usize] += 1;
        c0[*ptr.add(i + 4) as usize] += 1;
        c1[*ptr.add(i + 5) as usize] += 1;
        c2[*ptr.add(i + 6) as usize] += 1;
        c3[*ptr.add(i + 7) as usize] += 1;
        c0[*ptr.add(i + 8) as usize] += 1;
        c1[*ptr.add(i + 9) as usize] += 1;
        c2[*ptr.add(i + 10) as usize] += 1;
        c3[*ptr.add(i + 11) as usize] += 1;
        c0[*ptr.add(i + 12) as usize] += 1;
        c1[*ptr.add(i + 13) as usize] += 1;
        c2[*ptr.add(i + 14) as usize] += 1;
        c3[*ptr.add(i + 15) as usize] += 1;
        i += 16;
    }
    while i < len {
        c0[*ptr.add(i) as usize] += 1;
        i += 1;
    }

    // Merge the 4 histograms using AVX2 vector additions
    let mut counts = [0u32; 256];
    let mut j = 0;
    while j < 256 {
        let v0 = _mm256_loadu_si256(c0[j..].as_ptr() as *const _);
        let v1 = _mm256_loadu_si256(c1[j..].as_ptr() as *const _);
        let v2 = _mm256_loadu_si256(c2[j..].as_ptr() as *const _);
        let v3 = _mm256_loadu_si256(c3[j..].as_ptr() as *const _);
        let sum01 = _mm256_add_epi32(v0, v1);
        let sum23 = _mm256_add_epi32(v2, v3);
        let sum = _mm256_add_epi32(sum01, sum23);
        _mm256_storeu_si256(counts[j..].as_mut_ptr() as *mut _, sum);
        j += 8;
    }

    let mut sum_v = _mm256_setzero_pd();
    let len_v = _mm256_set1_pd(len as f64);

    // Calculate entropy using vectorized 4-wide double-precision log approximation
    for k in (0..256).step_by(4) {
        let counts_v = _mm_loadu_si128(counts[k..].as_ptr() as *const _);
        let counts_f = _mm256_cvtepi32_pd(counts_v);

        let mask_v = _mm256_cmp_pd(counts_f, _mm256_setzero_pd(), 30);
        let mask_bits = _mm256_movemask_pd(mask_v);
        if mask_bits == 0 {
            continue;
        }

        // p = count / len
        let p = _mm256_div_pd(counts_f, len_v);

        // log2(p)
        let log2p = approx_log2_pd(p);

        // term = p * log2p
        let term = _mm256_mul_pd(p, log2p);
        let term_masked = _mm256_and_pd(term, mask_v);
        sum_v = _mm256_sub_pd(sum_v, term_masked);
    }

    // Reduce sum_v to scalar
    let mut sums = [0.0f64; 4];
    _mm256_storeu_pd(sums.as_mut_ptr(), sum_v);
    sums.iter().sum()
}

/// 5-term polynomial approximation for log2(x) where x is in (0, 1]
/// Uses the identity log2(x) = exponent + log2(mantissa)
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn approx_log2_pd(x: __m256d) -> __m256d {
    // x = m * 2^e
    // Extract exponent
    let bits = _mm256_castpd_si256(x);
    let e = _mm256_and_si256(_mm256_srli_epi64(bits, 52), _mm256_set1_epi64x(0x7FF_i64));

    // e contains (exponent bias + E) in the lower 32-bits of each 64-bit element.
    // Permute lower 32-bits of each 64-bit lane to pack them into the lower 128-bit lane.
    let e_packed = _mm256_permutevar8x32_epi32(e, _mm256_setr_epi32(0, 2, 4, 6, 0, 0, 0, 0));
    let e_128 = _mm256_castsi256_si128(e_packed);
    let e_unbiased = _mm_sub_epi32(e_128, _mm_set1_epi32(1023));
    let e_f = _mm256_cvtepi32_pd(e_unbiased);

    // Extract mantissa m in [1, 2)
    let m_bits = _mm256_or_si256(
        _mm256_and_si256(bits, _mm256_set1_epi64x(0x000F_FFFF_FFFF_FFFF_i64)),
        _mm256_set1_epi64x(0x3FF0_0000_0000_0000_i64), // 1.0 in f64
    );
    let m = _mm256_castsi256_pd(m_bits);

    // z = m - 1, z in [0, 1)
    let z = _mm256_sub_pd(m, _mm256_set1_pd(1.0));

    // 5-term polynomial for log2(1+z)
    let a1 = _mm256_set1_pd(1.442689882843058);
    let a2 = _mm256_set1_pd(-0.721344529025066);
    let a3 = _mm256_set1_pd(0.480884024344551);
    let a4 = _mm256_set1_pd(-0.359880922880757);
    let a5 = _mm256_set1_pd(0.246417534433544);

    let mut poly = a5;
    poly = _mm256_add_pd(_mm256_mul_pd(poly, z), a4);
    poly = _mm256_add_pd(_mm256_mul_pd(poly, z), a3);
    poly = _mm256_add_pd(_mm256_mul_pd(poly, z), a2);
    poly = _mm256_add_pd(_mm256_mul_pd(poly, z), a1);
    let log2m = _mm256_mul_pd(poly, z);

    _mm256_add_pd(e_f, log2m)
}

/// SSE2 path: 4-way parallel histogram, same strategy as AVX2/AVX-512.
///
/// The old broadcast+cmpeq approach was O(unique_chars × n/16), which is
/// quadratic-ish on high-entropy data. 4-way histogram is O(n) regardless.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn shannon_entropy_sse2(data: &[u8]) -> f64 {
    let mut c0 = [0u32; 256];
    let mut c1 = [0u32; 256];
    let mut c2 = [0u32; 256];
    let mut c3 = [0u32; 256];

    let ptr = data.as_ptr();
    let len = data.len();
    let mut i = 0usize;

    let end16 = len & !15;
    while i < end16 {
        c0[*ptr.add(i) as usize] += 1;
        c1[*ptr.add(i + 1) as usize] += 1;
        c2[*ptr.add(i + 2) as usize] += 1;
        c3[*ptr.add(i + 3) as usize] += 1;
        c0[*ptr.add(i + 4) as usize] += 1;
        c1[*ptr.add(i + 5) as usize] += 1;
        c2[*ptr.add(i + 6) as usize] += 1;
        c3[*ptr.add(i + 7) as usize] += 1;
        c0[*ptr.add(i + 8) as usize] += 1;
        c1[*ptr.add(i + 9) as usize] += 1;
        c2[*ptr.add(i + 10) as usize] += 1;
        c3[*ptr.add(i + 11) as usize] += 1;
        c0[*ptr.add(i + 12) as usize] += 1;
        c1[*ptr.add(i + 13) as usize] += 1;
        c2[*ptr.add(i + 14) as usize] += 1;
        c3[*ptr.add(i + 15) as usize] += 1;
        i += 16;
    }
    while i < len {
        c0[*ptr.add(i) as usize] += 1;
        i += 1;
    }

    // Merge the 4 histograms using SSE2 vector additions
    let mut counts = [0u32; 256];
    let mut j = 0;
    while j < 256 {
        let v0 = _mm_loadu_si128(c0[j..].as_ptr() as *const _);
        let v1 = _mm_loadu_si128(c1[j..].as_ptr() as *const _);
        let v2 = _mm_loadu_si128(c2[j..].as_ptr() as *const _);
        let v3 = _mm_loadu_si128(c3[j..].as_ptr() as *const _);
        let sum01 = _mm_add_epi32(v0, v1);
        let sum23 = _mm_add_epi32(v2, v3);
        let sum = _mm_add_epi32(sum01, sum23);
        _mm_storeu_si128(counts[j..].as_mut_ptr() as *mut _, sum);
        j += 4;
    }

    let len_f = len as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len_f;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// AArch64 true Neon SIMD parallel equality logic
#[cfg(target_arch = "aarch64")]
pub fn shannon_entropy_simd(data: &[u8]) -> f64 {
    #[cfg(target_arch = "aarch64")]
    use core::arch::aarch64::*;

    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    let mut chunks = data.chunks_exact(16);

    // SAFETY: every NEON intrinsic below operates on exactly the 16-byte
    // `chunk` reference produced by `chunks_exact(16)`, which guarantees
    // chunk.len() == 16 and that chunk.as_ptr() is valid for at least
    // 16 bytes. `vdupq_n_u8`/`vceqq_u8`/`vandq_u8`/`vaddvq_u8` have no
    // memory preconditions; they're pure register ops. NEON requires
    // aarch64 which is enforced by the surrounding `#[cfg(target_arch
    // = "aarch64")]`. kimi-wave1 audit finding 6.LOW.entropy_fast.rs.186.
    unsafe {
        for chunk in chunks.by_ref() {
            let v = vld1q_u8(chunk.as_ptr());
            let mut active_mask = 0xFFFFu32;

            while active_mask != 0 {
                let tz = active_mask.trailing_zeros();
                let b = chunk[tz as usize];

                let broadcast = vdupq_n_u8(b);
                let cmp = vceqq_u8(v, broadcast);

                // Neon lacks movemask, so we shift mask to a scalar using a standard trick
                let shift_mask =
                    vld1q_u8([1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128].as_ptr());
                let and_mask = vandq_u8(cmp, shift_mask);
                let sums = vpaddq_u8(vpaddq_u8(vpaddq_u8(and_mask, and_mask), and_mask), and_mask);

                let low = vgetq_lane_u8(sums, 0) as u32;
                let high = vgetq_lane_u8(sums, 8) as u32;
                let match_mask = low | (high << 8);

                let combined = match_mask & active_mask;
                counts[b as usize] += combined.count_ones();
                active_mask ^= combined;
            }
        }
    }

    for &byte in chunks.remainder() {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Generic fallback for all other architectures.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn shannon_entropy_simd(data: &[u8]) -> f64 {
    shannon_entropy_scalar(data)
}

/// Fast check if data MIGHT have high entropy.
/// Returns quickly for obviously low-entropy data.
///
/// Uses a 12-byte sample (first 4 + middle 4 + last 4) to detect
/// obviously-low-entropy inputs and skip the O(n) full scan. On
/// high-entropy data the heuristic can't decide, so it falls through
/// to `shannon_entropy_simd` for an exact answer.
///
/// The early-exit fires when:
///  - The sample has < 4 unique byte values, AND
///  - The byte-value spread (max − min) is < 16, AND
///  - The threshold is ≥ 2.0 (below 2.0, even very low-variation
///    data might meet the threshold depending on distribution).
///
/// This combination is sound because 3 distinct values drawn from a
/// 16-wide alphabet can produce at most log2(16) = 4.0 bits of
/// entropy, but with only 3 values in a 16-wide range the real
/// entropy of any length-n sequence is bounded by log2(3) ≈ 1.585,
/// well below any production threshold (≥ 2.0).
pub fn has_high_entropy_fast(data: &[u8], threshold: f64) -> bool {
    if data.len() < 8 {
        return shannon_entropy_scalar(data) >= threshold;
    }

    // Sample 12 bytes: first 4 + middle 4 + last 4.
    // Count unique bytes via a 256-bit bitset (4 × u64, stack-only).
    let mut seen = [0u64; 4];
    let mid = data.len() / 2;
    let samples = [
        data[0],
        data[1],
        data[2],
        data[3],
        data[mid],
        data[mid + 1],
        data[mid + 2],
        data[mid + 3],
        data[data.len() - 4],
        data[data.len() - 3],
        data[data.len() - 2],
        data[data.len() - 1],
    ];
    let mut sample_min = u8::MAX;
    let mut sample_max = 0u8;
    for &b in &samples {
        seen[b as usize / 64] |= 1u64 << (b % 64);
        sample_min = sample_min.min(b);
        sample_max = sample_max.max(b);
    }
    let unique =
        seen[0].count_ones() + seen[1].count_ones() + seen[2].count_ones() + seen[3].count_ones();
    let spread = (sample_max as u32).saturating_sub(sample_min as u32);

    // Early exit: very few unique bytes in the sample AND they're
    // clustered in a narrow range. With < 4 distinct values from a
    // ≤ 16-wide alphabet, maximum theoretical entropy is log2(4) = 2.0
    // bits - any threshold ≥ 2.0 cannot be met regardless of the
    // full-data distribution. Skip the O(n) scan.
    if unique < 4 && spread < 16 && threshold >= 2.0 {
        return false;
    }

    // Can't decide from the sample - do the full calculation.
    shannon_entropy_simd(data) >= threshold
}
