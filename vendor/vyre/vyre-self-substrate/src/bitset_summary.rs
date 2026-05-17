//! Bitset summary substrate consumer.
//!
//! Wires `vyre_primitives::bitset::popcount::cpu_ref` and several
//! companion bitset operations into the dispatch path so the
//! optimizer / cache invalidator can summarize how saturated their
//! reachability / alias / dirty-set bitsets are without each pass
//! re-implementing popcount inline.

use vyre_primitives::bitset::popcount::{
    cpu_ref as primitive_popcount, cpu_ref_into as primitive_popcount_into,
};

/// Per-word popcount via the bitset primitive. Bumps the
/// dataflow-fixpoint substrate counter so dispatch dashboards
/// register every summary.
#[must_use]
pub fn per_word_popcount(input: &[u32]) -> Vec<u32> {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    primitive_popcount(input)
}

/// Per-word popcount into caller-owned storage.
pub fn per_word_popcount_into(input: &[u32], out: &mut Vec<u32>) {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    primitive_popcount_into(input, out);
}

/// Total set-bit count across the bitset. Saturating-summed so a
/// 32-billion-bit bitset doesn't overflow.
#[must_use]
pub fn total_set_bits(input: &[u32]) -> u64 {
    let mut total: u64 = 0;
    for word in input {
        total = total.saturating_add(u64::from(word.count_ones()));
    }
    total
}

/// Saturation ratio in `[0.0, 1.0]`: fraction of bits set across the
/// bitset's full word capacity. The dispatch-time tracker uses this
/// to detect "alias-set is becoming dense, switch to whole-program
/// reachability instead of per-region masks".
#[must_use]
pub fn saturation_ratio(input: &[u32]) -> f64 {
    if input.is_empty() {
        return 0.0;
    }
    let capacity_bits = (input.len() as u64) * 32;
    if capacity_bits == 0 {
        return 0.0;
    }
    let set = total_set_bits(input);
    (set as f64) / (capacity_bits as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_yields_empty_summary() {
        let v = per_word_popcount(&[]);
        assert!(v.is_empty());
        assert_eq!(total_set_bits(&[]), 0);
        assert_eq!(saturation_ratio(&[]), 0.0);
    }

    #[test]
    fn full_word_is_thirty_two_bits() {
        let v = per_word_popcount(&[0xFFFF_FFFFu32]);
        assert_eq!(v, vec![32u32]);
        assert_eq!(total_set_bits(&[0xFFFF_FFFF]), 32);
        assert!((saturation_ratio(&[0xFFFF_FFFF]) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn mixed_words_count_correctly() {
        // 0b1111 = 4 bits, 0b101 = 2 bits.
        let v = per_word_popcount(&[0b1111u32, 0b101]);
        assert_eq!(v, vec![4, 2]);
        assert_eq!(total_set_bits(&[0b1111, 0b101]), 6);
    }

    #[test]
    fn popcount_into_reuses_capacity() {
        let mut out = Vec::with_capacity(8);
        per_word_popcount_into(&[0b1111u32, 0xFFFF_FFFF], &mut out);
        let capacity = out.capacity();
        assert_eq!(out, vec![4, 32]);

        per_word_popcount_into(&[0b1010u32], &mut out);
        assert_eq!(out.capacity(), capacity);
        assert_eq!(out, vec![2]);
    }

    /// Closure-bar: substrate output equals primitive output exactly.
    #[test]
    fn matches_primitive_directly() {
        let input = vec![0u32, 1, 0xFFFF_FFFF, 0xAAAA_AAAA, 0x12345678];
        assert_eq!(per_word_popcount(&input), primitive_popcount(&input));
    }

    /// Adversarial: half-saturated bitset yields ratio 0.5.
    #[test]
    fn half_saturation_ratio() {
        // 0xAAAA_AAAA has 16 bits set out of 32.
        let r = saturation_ratio(&[0xAAAA_AAAAu32]);
        assert!((r - 0.5).abs() < 1e-9, "expected 0.5, got {r}");
    }

    /// Adversarial: a bitset that's 32 entries wide but only one bit
    /// set has saturation ≈ 1/(32*32).
    #[test]
    fn single_bit_in_large_bitset() {
        let mut input = vec![0u32; 32];
        input[5] = 1;
        let r = saturation_ratio(&input);
        let expected = 1.0 / 1024.0;
        assert!((r - expected).abs() < 1e-9);
    }

    /// Idempotence: per_word_popcount on the same input is
    /// deterministic.
    #[test]
    fn deterministic_summary() {
        let input = vec![0xCAFE_BABEu32, 0x1234_5678];
        let a = per_word_popcount(&input);
        let b = per_word_popcount(&input);
        assert_eq!(a, b);
    }
}
