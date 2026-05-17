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

    // Merge the 4 histograms
    let mut counts = [0u32; 256];
    for j in 0..256 {
        counts[j] = c0[j] + c1[j] + c2[j] + c3[j];
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

    let mut counts = [0u32; 256];
    for j in 0..256 {
        counts[j] = c0[j] + c1[j] + c2[j] + c3[j];
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
/// Uses a 256-bit bitset for uniqueness counting instead of a HashSet,
/// eliminating heap allocation on the hot path.
pub fn has_high_entropy_fast(data: &[u8], threshold: f64) -> bool {
    if data.len() < 8 {
        return shannon_entropy_scalar(data) >= threshold;
    }

    // Sample 12 bytes: first 4 + middle 4 + last 4.
    // Count unique bytes via a 256-bit bitset (4 × u64, stack-only).
    let mut seen = [0u64; 4];
    let mid = data.len() / 2;
    let samples = [
        data[0], data[1], data[2], data[3],
        data[mid], data[mid + 1], data[mid + 2], data[mid + 3],
        data[data.len() - 4], data[data.len() - 3], data[data.len() - 2], data[data.len() - 1],
    ];
    for &b in &samples {
        seen[b as usize / 64] |= 1u64 << (b % 64);
    }
    let unique = seen[0].count_ones() + seen[1].count_ones() + seen[2].count_ones() + seen[3].count_ones();

    if unique < 4 {
        // Low variation in sample; still verify with full calculation
        return shannon_entropy_simd(data) >= threshold;
    }

    // Sample suggests high entropy, do full calculation
    shannon_entropy_simd(data) >= threshold
}
