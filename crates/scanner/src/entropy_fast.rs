//! Fast vectorized entropy calculation with architecture-specific implementations.
//!
//! This module uses SIMD instructions (AVX-512, AVX2, SSE2, Neon) to accelerate Shannon
//! entropy calculation. It includes optimized paths for character frequency
//! counting and parallel logarithmic summation.

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use std::cell::UnsafeCell;
use std::sync::OnceLock;

static LOG2_TABLE: OnceLock<[f64; 256]> = OnceLock::new();

#[inline]
fn get_log2_table() -> &'static [f64; 256] {
    LOG2_TABLE.get_or_init(|| {
        let mut table = [0.0f64; 256];
        for i in 1..256 {
            let val = i as f64;
            table[i] = val * val.log2();
        }
        table
    })
}

thread_local! {
    static HIST_SCRATCH: UnsafeCell<[u32; 1024]> = UnsafeCell::new([0u32; 1024]);
}

/// Fast entropy calculation using unrolled scalar accumulation.
/// Processes data in 32-byte chunks with 8 parallel accumulators on x86_64.
#[cfg(target_arch = "x86_64")]
pub fn shannon_entropy_simd(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

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

/// Scalar fallback: 8-way parallel histogram to break load-add-store chains.
///
/// A single `counts[b] += 1` has a 4-cycle dependency chain. By maintaining
/// 8 independent arrays and interleaving accesses, the OOE engine can issue
/// 8 independent chains in parallel, yielding maximum throughput on modern CPUs (KH-27).
#[inline]
pub fn shannon_entropy_scalar(data: &[u8]) -> f64 {
    let len = data.len();
    if len == 0 {
        return 0.0;
    }

    let mut c0 = [0u32; 256];
    let mut c1 = [0u32; 256];
    let mut c2 = [0u32; 256];
    let mut c3 = [0u32; 256];
    let mut c4 = [0u32; 256];
    let mut c5 = [0u32; 256];
    let mut c6 = [0u32; 256];
    let mut c7 = [0u32; 256];

    let chunks = data.chunks_exact(8);
    let remainder = chunks.remainder();
    let mut active_len = len;

    for chunk in chunks {
        // Fast-path null check to speed up binary scanning
        if chunk[0] == 0 && chunk[1] == 0 && chunk[2] == 0 && chunk[3] == 0
            && chunk[4] == 0 && chunk[5] == 0 && chunk[6] == 0 && chunk[7] == 0
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

    for &byte in remainder {
        if byte == 0 {
            active_len -= 1;
        } else {
            c0[byte as usize] += 1;
        }
    }

    if active_len == 0 {
        return 0.0;
    }

    // Merge
    let mut counts = [0u32; 256];
    for j in 0..256 {
        counts[j] = c0[j] + c1[j] + c2[j] + c3[j] + c4[j] + c5[j] + c6[j] + c7[j];
    }

    // Log2 Table Lookup optimization for small active length (KH-28)
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

/// AVX2 path: 4-way parallel histogram to break load-add-store dependency chains.
///
/// Unrolled to process 32 bytes per iteration with thread-local scratch arrays and
/// fast vectorized zero-byte checks (KH-23, KH-29, KH-31, KH-32, KH-34).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,fma")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn shannon_entropy_avx2(data: &[u8]) -> f64 {
    let len = data.len();
    if len == 0 {
        return 0.0;
    }

    // Get the thread-local scratch buffer (KH-23)
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

    // Align memory scans to 32-byte boundaries to avoid unaligned load penalties (KH-29)
    while i < len && (((ptr as usize) + i) & 31) != 0 {
        let val = *ptr.add(i);
        if val == 0 {
            active_len -= 1;
        } else {
            c0[val as usize] += 1;
        }
        i += 1;
    }

    // Process 32 bytes per iteration and filter contiguous null bytes (KH-31, KH-32, KH-34)
    let end32 = len & !31;
    while i < end32 {
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

    // Log2 Table Lookup optimization for small active length (KH-28)
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
/// Uses the identity log2(x) = exponent + log2(mantissa)
///
/// Features FMA-based polynomial evaluation and domain clamping (KH-22, KH-35).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,fma")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn approx_log2_pd(x: __m256d) -> __m256d {
    // Clamp polynomial log2 outputs strictly to the domain (0, 1] using pure float SIMD (KH-35)
    let min_val = _mm256_set1_pd(f64::MIN_POSITIVE);
    let max_val = _mm256_set1_pd(1.0);
    let clamped_x = _mm256_max_pd(_mm256_min_pd(x, max_val), min_val);

    // clamped_x = m * 2^e
    // Extract exponent
    let bits = _mm256_castpd_si256(clamped_x);
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

    // FMA-based polynomial evaluation (KH-22)
    let mut poly = a5;
    poly = _mm256_fmadd_pd(poly, z, a4);
    poly = _mm256_fmadd_pd(poly, z, a3);
    poly = _mm256_fmadd_pd(poly, z, a2);
    poly = _mm256_fmadd_pd(poly, z, a1);
    let log2m = _mm256_mul_pd(poly, z);

    _mm256_add_pd(e_f, log2m)
}

/// SSE2 path: 4-way parallel histogram, unrolled to process 32 bytes per iteration
/// with vectorized zero-byte checks (KH-31, KH-34).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn shannon_entropy_sse2(data: &[u8]) -> f64 {
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

    // Align to 16-byte boundary (KH-29)
    while i < len && (((ptr as usize) + i) & 15) != 0 {
        let val = *ptr.add(i);
        if val == 0 {
            active_len -= 1;
        } else {
            c0[val as usize] += 1;
        }
        i += 1;
    }

    // Unrolled SSE2 to process 32 bytes per iteration with zero-byte checks (KH-31, KH-34)
    let end32 = len & !31;
    let zeros = _mm_setzero_si128();
    while i < end32 {
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

    // Log2 Table Lookup optimization for small active length (KH-28)
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

/// AArch64 true Neon SIMD parallel histogram calculations.
/// Unrolled to process 32 bytes per iteration with vector null filtering (KH-25, KH-34).
#[cfg(target_arch = "aarch64")]
pub fn shannon_entropy_simd(data: &[u8]) -> f64 {
    #[cfg(target_arch = "aarch64")]
    use core::arch::aarch64::*;

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

    // Process 32 bytes per iteration with vector null filtering (KH-34)
    let end32 = len & !31;
    unsafe {
        while i < end32 {
            let v0 = vld1q_u8(ptr.add(i));
            let v1 = vld1q_u8(ptr.add(i + 16));
            
            // Fast null check using Neon ORR and MAX reduction
            if vmaxvq_u8(vorrq_u8(v0, v1)) == 0 {
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
    }

    if active_len == 0 {
        return 0.0;
    }

    // Merge the 4 histograms using Neon vector additions (KH-25)
    let mut counts = [0u32; 256];
    let mut j = 0;
    unsafe {
        while j < 256 {
            let v0 = vld1q_u32(c0[j..].as_ptr());
            let v1 = vld1q_u32(c1[j..].as_ptr());
            let v2 = vld1q_u32(c2[j..].as_ptr());
            let v3 = vld1q_u32(c3[j..].as_ptr());
            let sum01 = vaddq_u32(v0, v1);
            let sum23 = vaddq_u32(v2, v3);
            let sum = vaddq_u32(sum01, sum23);
            vst1q_u32(counts[j..].as_mut_ptr(), sum);
            j += 4;
        }
    }

    // Log2 Table Lookup optimization for small active length (KH-28)
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

/// Generic fallback for all other architectures.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn shannon_entropy_simd(data: &[u8]) -> f64 {
    shannon_entropy_scalar(data)
}

/// Fast check if data MIGHT have high entropy.
/// Returns quickly for obviously low-entropy data.
///
/// Features vectorized unique checks and expanded sampling threshold optimizations
/// (KH-21, KH-26, KH-30).
pub fn has_high_entropy_fast(data: &[u8], threshold: f64) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("sse2") {
            unsafe {
                return has_high_entropy_fast_x86(data, threshold);
            }
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe {
            return has_high_entropy_fast_neon(data, threshold);
        }
    }

    has_high_entropy_fast_scalar(data, threshold)
}

/// Scalar fallback for has_high_entropy_fast
#[inline]
fn has_high_entropy_fast_scalar(data: &[u8], threshold: f64) -> bool {
    let len = data.len();
    if len < 8 {
        return shannon_entropy_scalar(data) >= threshold;
    }

    // Sample 12 bytes: first 4 + middle 4 + last 4.
    // Count unique bytes via a 256-bit bitset (4 × u64, stack-only).
    let mut seen = [0u64; 4];
    let mid = len / 2;
    let samples = [
        data[0],
        data[1],
        data[2],
        data[3],
        data[mid],
        data[mid + 1],
        data[mid + 2],
        data[mid + 3],
        data[len - 4],
        data[len - 3],
        data[len - 2],
        data[len - 1],
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

    // Early exit (KH-26): automatically bypass full scans for chunks with fewer than 4 unique bytes
    if (unique < 4 && threshold >= 1.585) || (unique < 4 && spread < 16 && threshold >= 2.0) {
        return false;
    }

    // Can't decide from the sample - do the full calculation.
    shannon_entropy_simd(data) >= threshold
}

/// Vectorized unique character checks using SSE2 (KH-21, KH-30)
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn has_high_entropy_fast_x86(data: &[u8], threshold: f64) -> bool {
    let len = data.len();
    if len < 16 {
        return shannon_entropy_scalar(data) >= threshold;
    }

    // Single 128-bit vector load to inspect 16 bytes (KH-30)
    let mid = len / 2;
    let ptr = data.as_ptr().add(mid.saturating_sub(8));
    let v = _mm_loadu_si128(ptr as *const _);

    // Vectorized min/max to compute spread
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

    // Vectorized unique character check: compare vector with its 15 byte-shifts (KH-21, KH-30)
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

    // Early exit (KH-26)
    if (unique < 4 && threshold >= 1.585) || (unique < 4 && spread < 16 && threshold >= 2.0) {
        return false;
    }

    shannon_entropy_simd(data) >= threshold
}

/// Vectorized unique character checks using Neon (KH-21, KH-30)
#[cfg(target_arch = "aarch64")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn has_high_entropy_fast_neon(data: &[u8], threshold: f64) -> bool {
    use core::arch::aarch64::*;
    let len = data.len();
    if len < 16 {
        return shannon_entropy_scalar(data) >= threshold;
    }

    let mid = len / 2;
    let ptr = data.as_ptr().add(mid.saturating_sub(8));
    let v = vld1q_u8(ptr);

    // Vectorized min/max to compute spread
    let mut min_v = v;
    let mut max_v = v;

    let shuf1 = vextq_u8(min_v, min_v, 8);
    min_v = vminq_u8(min_v, shuf1);
    let shuf1_max = vextq_u8(max_v, max_v, 8);
    max_v = vmaxq_u8(max_v, shuf1_max);

    let shuf2 = vextq_u8(min_v, min_v, 4);
    min_v = vminq_u8(min_v, shuf2);
    let shuf2_max = vextq_u8(max_v, max_v, 4);
    max_v = vmaxq_u8(max_v, shuf2_max);

    let shuf3 = vextq_u8(min_v, min_v, 2);
    min_v = vminq_u8(min_v, shuf3);
    let shuf3_max = vextq_u8(max_v, max_v, 2);
    max_v = vmaxq_u8(max_v, shuf3_max);

    let shuf4 = vextq_u8(min_v, min_v, 1);
    min_v = vminq_u8(min_v, shuf4);
    let shuf4_max = vextq_u8(max_v, max_v, 1);
    max_v = vmaxq_u8(max_v, shuf4_max);

    let sample_min = vgetq_lane_u8(min_v, 0);
    let sample_max = vgetq_lane_u8(max_v, 0);
    let spread = sample_max.saturating_sub(sample_min);

    // Vectorized unique character check using shifts and standard mask tricks
    let mut dup_mask = 0u32;
    let shift_mask = vld1q_u8([1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128].as_ptr());
    let zero = vdupq_n_u8(0);

    for shift in 1..16 {
        let rotated = match shift {
            1 => vextq_u8(v, zero, 1),
            2 => vextq_u8(v, zero, 2),
            3 => vextq_u8(v, zero, 3),
            4 => vextq_u8(v, zero, 4),
            5 => vextq_u8(v, zero, 5),
            6 => vextq_u8(v, zero, 6),
            7 => vextq_u8(v, zero, 7),
            8 => vextq_u8(v, zero, 8),
            9 => vextq_u8(v, zero, 9),
            10 => vextq_u8(v, zero, 10),
            11 => vextq_u8(v, zero, 11),
            12 => vextq_u8(v, zero, 12),
            13 => vextq_u8(v, zero, 13),
            14 => vextq_u8(v, zero, 14),
            15 => vextq_u8(v, zero, 15),
            _ => zero,
        };
        let cmp = vceqq_u8(v, rotated);
        let and_mask = vandq_u8(cmp, shift_mask);
        let sums = vpaddq_u8(vpaddq_u8(vpaddq_u8(and_mask, and_mask), and_mask), and_mask);
        let low = vgetq_lane_u8(sums, 0) as u32;
        let high = vgetq_lane_u8(sums, 8) as u32;
        let mask = low | (high << 8);

        let valid_mask = (1u32 << (16 - shift)) - 1;
        dup_mask |= mask & valid_mask;
    }
    let unique = 16 - dup_mask.count_ones();

    // Early exit (KH-26)
    if (unique < 4 && threshold >= 1.585) || (unique < 4 && spread < 16 && threshold >= 2.0) {
        return false;
    }

    shannon_entropy_simd(data) >= threshold
}
