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
            return crate::entropy_fast_x86::shannon_entropy_avx2(data);
        }
        if is_x86_feature_detected!("sse2") {
            return crate::entropy_fast_x86::shannon_entropy_sse2(data);
        }
    }

    shannon_entropy_scalar(data)
}

/// AArch64 true Neon SIMD parallel histogram calculations.
#[cfg(target_arch = "aarch64")]
pub fn shannon_entropy_simd(data: &[u8]) -> f64 {
    crate::entropy_fast_neon::shannon_entropy_neon(data)
}

/// Generic fallback for all other architectures.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn shannon_entropy_simd(data: &[u8]) -> f64 {
    shannon_entropy_scalar(data)
}

/// Canonical byte-frequency histogram carrying KeyHog's null-byte contract.
///
/// Bytes are grouped into 8-byte chunks from offset 0. A fully-null chunk is
/// skipped as binary padding (its 8 bytes leave `active_len`); every other
/// chunk — including one that merely *contains* nulls — is counted in full, as
/// is the sub-8 remainder (a lone trailing null drops out). Returns the merged
/// 256-bin histogram and `active_len` (input length minus the padding bytes).
///
/// This is the single definition of that contract. The scalar path and every
/// SIMD path (`avx2`/`sse2`/`avx512`/`neon`) count through here, so they agree
/// bit-for-bit regardless of pointer alignment or input length. Folding it into
/// one helper also removes the divergence an alignment-prologue histogram used
/// to introduce on short/unaligned inputs, where the byte-at-a-time prologue
/// dropped *every* null individually instead of honoring the 8-byte contract.
///
/// Counting is memory-bound: a single `counts[b] += 1` carries a load-add-store
/// dependency chain, so 8 independent accumulators (every 8th byte) let the
/// out-of-order engine issue 8 chains in parallel and saturate the load/store
/// ports (KH-27). Wider vectors win nothing in the count — they specialize only
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

/// Shannon entropy in bits/byte over the non-padding bytes of `data`.
///
/// Counts through [`histogram_8way`] (the shared null contract), then reduces
/// with a `count·log2(count)` table for short inputs (`active_len <= 255`,
/// KH-28) or the direct `-Σ p·log2 p` form for longer ones.
#[inline]
pub fn shannon_entropy_scalar(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let (counts, active_len) = histogram_8way(data);
    if active_len == 0 {
        return 0.0;
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
                return crate::entropy_fast_x86::has_high_entropy_fast_x86(data, threshold);
            }
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe {
            return crate::entropy_fast_neon::has_high_entropy_fast_neon(data, threshold);
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

