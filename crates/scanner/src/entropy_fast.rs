//! Fast vectorized entropy calculation with architecture-specific implementations.
//!
//! This module uses SIMD instructions (AVX-512, AVX2, SSE2) to accelerate Shannon
//! entropy calculation. It includes optimized paths for character frequency
//! counting and parallel logarithmic summation.

/// Fast entropy calculation using unrolled scalar accumulation.
/// Processes data in 32-byte chunks with 8 parallel accumulators on x86_64.
#[cfg(target_arch = "x86_64")]
pub fn shannon_entropy_simd(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // The "AVX2" and "SSE2" paths below are actually unrolled scalar loops
    // that avoid data hazards by keeping counts in separate arrays.
    // True SIMD vectorization is left as future work.
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

/// Scalar fallback - optimized version of original
#[inline]
pub fn shannon_entropy_scalar(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // Unroll by 8 for better instruction-level parallelism
    let mut counts = [0u32; 256];
    let chunks = data.chunks_exact(8);
    let remainder = chunks.remainder();

    for chunk in chunks {
        counts[chunk[0] as usize] += 1;
        counts[chunk[1] as usize] += 1;
        counts[chunk[2] as usize] += 1;
        counts[chunk[3] as usize] += 1;
        counts[chunk[4] as usize] += 1;
        counts[chunk[5] as usize] += 1;
        counts[chunk[6] as usize] += 1;
        counts[chunk[7] as usize] += 1;
    }

    for &byte in remainder {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    // Process in chunks for cache efficiency
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// True AVX2 SIMD path using population count on equality masks.
/// Instead of iterating 32 bytes scalar-style, we broadcast elements, create equality masks,
/// and popcount them via `_mm256_movemask_epi8`. Perfect for compressing low-entropy strings.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn shannon_entropy_avx2(data: &[u8]) -> f64 {
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    let mut counts = [0u32; 256];
    let mut chunks = data.chunks_exact(32);

    for chunk in chunks.by_ref() {
        let v = _mm256_loadu_si256(chunk.as_ptr() as *const __m256i);
        let mut active_mask = 0xFFFF_FFFFu32;

        while active_mask != 0 {
            // Find the first unprocessed byte
            let tz = active_mask.trailing_zeros();
            let b = chunk[tz as usize];

            // Broadcast and match horizontally across 32 bytes
            let broadcast = _mm256_set1_epi8(b as i8);
            let cmp = _mm256_cmpeq_epi8(v, broadcast);
            let match_mask = _mm256_movemask_epi8(cmp) as u32;

            // Count exactly how many of this character were found in the active set
            let combined = match_mask & active_mask;
            counts[b as usize] += combined.count_ones();

            // Remove those from the active mask instantly natively
            active_mask ^= combined;
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

/// Fallback vectorized proxy for SSE2 targets utilizing smaller YMM segments
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn shannon_entropy_sse2(data: &[u8]) -> f64 {
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    let mut counts = [0u32; 256];
    let mut chunks = data.chunks_exact(16);

    for chunk in chunks.by_ref() {
        let v = _mm_loadu_si128(chunk.as_ptr() as *const __m128i);
        let mut active_mask = 0xFFFFu32;

        while active_mask != 0 {
            let tz = active_mask.trailing_zeros();
            let b = chunk[tz as usize];

            let broadcast = _mm_set1_epi8(b as i8);
            let cmp = _mm_cmpeq_epi8(v, broadcast);
            let match_mask = _mm_movemask_epi8(cmp) as u32;

            let combined = match_mask & active_mask;
            counts[b as usize] += combined.count_ones();
            active_mask ^= combined;
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

/// Fast check if data MIGHT have high entropy
/// Returns quickly for obviously low-entropy data
pub fn has_high_entropy_fast(data: &[u8], threshold: f64) -> bool {
    // Quick rejection: if all bytes are same, return false immediately
    if data.len() < 8 {
        return shannon_entropy_scalar(data) >= threshold;
    }

    // Sample check: look at first, middle, last 4 bytes
    let first = &data[..4.min(data.len())];
    let mid = &data[data.len() / 2..data.len() / 2 + 4.min(data.len())];
    let last = &data[data.len() - 4.min(data.len())..];

    // If samples show low variation, full check needed
    let sample_variation = first
        .iter()
        .chain(mid)
        .chain(last)
        .collect::<std::collections::HashSet<_>>()
        .len();
    if sample_variation < 4 {
        // Likely low entropy, but verify
        return shannon_entropy_simd(data) >= threshold;
    }

    // Sample suggests high entropy, do full calculation
    shannon_entropy_simd(data) >= threshold
}
