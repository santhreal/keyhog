//! AVX2 and SSE2 optimized Shannon entropy and high-entropy heuristic checks for x86_64.

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use crate::entropy_fast::{get_log2_table, shannon_entropy_scalar, HIST_SCRATCH};

/// AVX2 path: 4-way parallel histogram to break load-add-store dependency chains.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,fma")]
#[allow(unsafe_op_in_unsafe_fn)]
pub(crate) unsafe fn shannon_entropy_avx2(data: &[u8]) -> f64 {
    let len = data.len();
    if len == 0 {
        return 0.0;
    }

    // Get the thread-local scratch buffer
    let scratch_ptr = HIST_SCRATCH.with(|s| s.get());
    let scratch = &mut *scratch_ptr;

    // Vectorized zeroing of scratch space before borrowing sub-slices
    let zero = _mm256_setzero_si256();
    for j in (0..1024).step_by(8) {
        _mm256_storeu_si256(scratch[j..].as_mut_ptr() as *mut _, zero);
    }

    let (c0, rest) = scratch.split_at_mut(256);
    let (c1, rest) = rest.split_at_mut(256);
    let (c2, c3) = rest.split_at_mut(256);

    let ptr = data.as_ptr();
    let mut i = 0usize;
    let mut active_len = len;

    // Align memory scans to 32-byte boundaries
    while i < len && (((ptr as usize) + i) & 31) != 0 {
        let val = *ptr.add(i);
        if val == 0 {
            active_len -= 1;
        } else {
            c0[val as usize] += 1;
        }
        i += 1;
    }

    // Process 32 bytes per iteration and filter contiguous null bytes.
    //
    // The alignment prologue above advances `i` so that `ptr + i` is 32-byte
    // aligned (required by `_mm256_load_si256`). The loop bound must therefore
    // be expressed as "a full 32-byte read still fits", i.e. `i + 32 <= len`,
    // NOT `len & !31`: the latter ignores the prologue's `pad` offset and, when
    // `pad > 0`, both reads past the end of `data` and loads from a
    // non-32-aligned address on the last iteration.
    while i + 32 <= len {
        let chunk_v = _mm256_load_si256(ptr.add(i) as *const _);
        if _mm256_testz_si256(chunk_v, chunk_v) == 1 {
            active_len -= 32;
            i += 32;
            continue;
        }

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

        c0[*ptr.add(i + 16) as usize] += 1;
        c1[*ptr.add(i + 17) as usize] += 1;
        c2[*ptr.add(i + 18) as usize] += 1;
        c3[*ptr.add(i + 19) as usize] += 1;
        c0[*ptr.add(i + 20) as usize] += 1;
        c1[*ptr.add(i + 21) as usize] += 1;
        c2[*ptr.add(i + 22) as usize] += 1;
        c3[*ptr.add(i + 23) as usize] += 1;
        c0[*ptr.add(i + 24) as usize] += 1;
        c1[*ptr.add(i + 25) as usize] += 1;
        c2[*ptr.add(i + 26) as usize] += 1;
        c3[*ptr.add(i + 27) as usize] += 1;
        c0[*ptr.add(i + 28) as usize] += 1;
        c1[*ptr.add(i + 29) as usize] += 1;
        c2[*ptr.add(i + 30) as usize] += 1;
        c3[*ptr.add(i + 31) as usize] += 1;
        i += 32;
    }

    while i < len {
        let val = *ptr.add(i);
        if val == 0 {
            active_len -= 1;
        } else {
            c0[val as usize] += 1;
        }
        i += 1;
    }

    if active_len == 0 {
        return 0.0;
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

    // Log2 Table Lookup optimization for small active length
    if active_len <= 255 {
        let table = get_log2_table();
        let mut sum = 0.0;
        for &count in &counts {
            if count > 0 {
                sum += table[count as usize];
            }
        }
        return (active_len as f64).log2() - sum / (active_len as f64);
    }

    let mut sum_v = _mm256_setzero_pd();
    let len_v = _mm256_set1_pd(active_len as f64);

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
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,fma")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn approx_log2_pd(x: __m256d) -> __m256d {
    // Clamp polynomial log2 outputs strictly to the domain (0, 1] using pure float SIMD
    let min_val = _mm256_set1_pd(f64::MIN_POSITIVE);
    let max_val = _mm256_set1_pd(1.0);
    let clamped_x = _mm256_max_pd(_mm256_min_pd(x, max_val), min_val);

    // clamped_x = m * 2^e
    // Extract exponent
    let bits = _mm256_castpd_si256(clamped_x);
    let e = _mm256_and_si256(_mm256_srli_epi64(bits, 52), _mm256_set1_epi64x(0x7FF_i64));

    let e_packed = _mm256_permutevar8x32_epi32(e, _mm256_setr_epi32(0, 2, 4, 6, 0, 0, 0, 0));
    let e_128 = _mm256_castsi256_si128(e_packed);
    let e_unbiased = _mm_sub_epi32(e_128, _mm_set1_epi32(1023));
    let e_f = _mm256_cvtepi32_pd(e_unbiased);

    // Extract mantissa m in [1, 2)
    let m_bits = _mm256_or_si256(
        _mm256_and_si256(bits, _mm256_set1_epi64x(0x000F_FFFF_FFFF_FFFF_i64)),
        _mm256_set1_epi64x(0x3FF0_0000_0000_0000_i64),
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
    poly = _mm256_fmadd_pd(poly, z, a4);
    poly = _mm256_fmadd_pd(poly, z, a3);
    poly = _mm256_fmadd_pd(poly, z, a2);
    poly = _mm256_fmadd_pd(poly, z, a1);
    let log2m = _mm256_mul_pd(poly, z);

    _mm256_add_pd(e_f, log2m)
}

/// SSE2 path: 4-way parallel histogram, unrolled to process 32 bytes per iteration
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
#[allow(unsafe_op_in_unsafe_fn)]
pub(crate) unsafe fn shannon_entropy_sse2(data: &[u8]) -> f64 {
    let len = data.len();
    if len == 0 {
        return 0.0;
    }

    let mut c0 = [0u32; 256];
    let mut c1 = [0u32; 256];
    let mut c2 = [0u32; 256];
    let mut c3 = [0u32; 256];

    let ptr = data.as_ptr();
    let mut i = 0usize;
    let mut active_len = len;

    // Align to 16-byte boundary
    while i < len && (((ptr as usize) + i) & 15) != 0 {
        let val = *ptr.add(i);
        if val == 0 {
            active_len -= 1;
        } else {
            c0[val as usize] += 1;
        }
        i += 1;
    }

    // As in the AVX2 path: the 16-byte alignment prologue offsets `i` by
    // `pad`, so the aligned-load loop must stop when a full 32-byte read
    // (two 16-byte `_mm_load_si128`s) would run past `len`. `len & !31`
    // ignores `pad` and over-reads / loads off-alignment when `pad > 0`.
    let zeros = _mm_setzero_si128();
    while i + 32 <= len {
        let v0 = _mm_load_si128(ptr.add(i) as *const _);
        let v1 = _mm_load_si128(ptr.add(i + 16) as *const _);

        let cmp0 = _mm_cmpeq_epi8(v0, zeros);
        let cmp1 = _mm_cmpeq_epi8(v1, zeros);
        let mask0 = _mm_movemask_epi8(cmp0) as u32;
        let mask1 = _mm_movemask_epi8(cmp1) as u32;
        if mask0 == 0xFFFF && mask1 == 0xFFFF {
            active_len -= 32;
            i += 32;
            continue;
        }

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

        c0[*ptr.add(i + 16) as usize] += 1;
        c1[*ptr.add(i + 17) as usize] += 1;
        c2[*ptr.add(i + 18) as usize] += 1;
        c3[*ptr.add(i + 19) as usize] += 1;
        c0[*ptr.add(i + 20) as usize] += 1;
        c1[*ptr.add(i + 21) as usize] += 1;
        c2[*ptr.add(i + 22) as usize] += 1;
        c3[*ptr.add(i + 23) as usize] += 1;
        c0[*ptr.add(i + 24) as usize] += 1;
        c1[*ptr.add(i + 25) as usize] += 1;
        c2[*ptr.add(i + 26) as usize] += 1;
        c3[*ptr.add(i + 27) as usize] += 1;
        c0[*ptr.add(i + 28) as usize] += 1;
        c1[*ptr.add(i + 29) as usize] += 1;
        c2[*ptr.add(i + 30) as usize] += 1;
        c3[*ptr.add(i + 31) as usize] += 1;
        i += 32;
    }

    while i < len {
        let val = *ptr.add(i);
        if val == 0 {
            active_len -= 1;
        } else {
            c0[val as usize] += 1;
        }
        i += 1;
    }

    if active_len == 0 {
        return 0.0;
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

    // Log2 Table Lookup optimization for small active length
    if active_len <= 255 {
        let table = get_log2_table();
        let mut sum = 0.0;
        for &count in &counts {
            if count > 0 {
                sum += table[count as usize];
            }
        }
        return (active_len as f64).log2() - sum / (active_len as f64);
    }

    let len_f = active_len as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len_f;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Vectorized unique character checks using SSE2
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
#[allow(unsafe_op_in_unsafe_fn)]
pub(crate) unsafe fn has_high_entropy_fast_x86(data: &[u8], threshold: f64) -> bool {
    let len = data.len();
    if len < 16 {
        return shannon_entropy_scalar(data) >= threshold;
    }

    let mid = len / 2;
    let ptr = data.as_ptr().add(mid.saturating_sub(8));
    let v = _mm_loadu_si128(ptr as *const _);

    let mut min_v = v;
    let mut max_v = v;

    let shuf1 = _mm_srli_si128(min_v, 8);
    min_v = _mm_min_epu8(min_v, shuf1);
    let shuf1_max = _mm_srli_si128(max_v, 8);
    max_v = _mm_max_epu8(max_v, shuf1_max);

    let shuf2 = _mm_srli_si128(min_v, 4);
    min_v = _mm_min_epu8(min_v, shuf2);
    let shuf2_max = _mm_srli_si128(max_v, 4);
    max_v = _mm_max_epu8(max_v, shuf2_max);

    let shuf3 = _mm_srli_si128(min_v, 2);
    min_v = _mm_min_epu8(min_v, shuf3);
    let shuf3_max = _mm_srli_si128(max_v, 2);
    max_v = _mm_max_epu8(max_v, shuf3_max);

    let shuf4 = _mm_srli_si128(min_v, 1);
    min_v = _mm_min_epu8(min_v, shuf4);
    let shuf4_max = _mm_srli_si128(max_v, 1);
    max_v = _mm_max_epu8(max_v, shuf4_max);

    let sample_min = _mm_cvtsi128_si32(min_v) as u8;
    let sample_max = _mm_cvtsi128_si32(max_v) as u8;
    let spread = sample_max.saturating_sub(sample_min);

    let mut dup_mask = 0u32;
    macro_rules! check_shift {
        ($shift:expr) => {
            let rotated = _mm_srli_si128(v, $shift);
            let cmp = _mm_cmpeq_epi8(v, rotated);
            let mask = _mm_movemask_epi8(cmp) as u32;
            let valid_mask = (1u32 << (16 - $shift)) - 1;
            dup_mask |= mask & valid_mask;
        };
    }
    check_shift!(1);
    check_shift!(2);
    check_shift!(3);
    check_shift!(4);
    check_shift!(5);
    check_shift!(6);
    check_shift!(7);
    check_shift!(8);
    check_shift!(9);
    check_shift!(10);
    check_shift!(11);
    check_shift!(12);
    check_shift!(13);
    check_shift!(14);
    check_shift!(15);

    let unique = 16 - dup_mask.count_ones();

    if (unique < 4 && threshold >= 1.585) || (unique < 4 && spread < 16 && threshold >= 2.0) {
        return false;
    }

    crate::entropy_fast::shannon_entropy_simd(data) >= threshold
}
