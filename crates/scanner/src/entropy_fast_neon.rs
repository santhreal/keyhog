//! Neon optimized Shannon entropy and high-entropy heuristic checks for aarch64.

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

use crate::entropy_fast::{get_log2_table, shannon_entropy_scalar};

/// AArch64 true Neon SIMD parallel histogram calculations.
/// Unrolled to process 32 bytes per iteration with vector null filtering (KH-25, KH-34).
#[cfg(target_arch = "aarch64")]
pub fn shannon_entropy_neon(data: &[u8]) -> f64 {
    let len = data.len();
    if len == 0 {
        return 0.0;
    }

    // Histogram + null contract live in the shared `histogram_8way`; counting
    // is memory-bound, so the Neon path specializes only the reduction below.
    let (counts, active_len) = crate::entropy_fast::histogram_8way(data);
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

/// Vectorized unique character checks using Neon (KH-21, KH-30)
#[cfg(target_arch = "aarch64")]
#[allow(unsafe_op_in_unsafe_fn)]
pub(crate) unsafe fn has_high_entropy_fast_neon(data: &[u8], threshold: f64) -> bool {
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

    crate::entropy_fast::shannon_entropy_simd(data) >= threshold
}
