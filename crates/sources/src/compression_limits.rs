//! Shared compression memory limits.

/// Smallest zstd `windowLog` whose window (`1 << log`) covers `budget`, clamped
/// to libzstd's valid range `[10, 31]`.
pub(crate) fn zstd_window_log_max_for_budget(budget: u64) -> u32 {
    let b = budget.max(1 << 10);
    let log = 64 - (b - 1).leading_zeros();
    log.clamp(10, 31)
}

#[cfg(test)]
mod tests {
    use super::zstd_window_log_max_for_budget as window_log;

    // This cap is the zstd decompression-bomb defense: it bounds the decoder's
    // window memory (`1 << windowLog`) so a tiny `.zst` declaring a huge window
    // cannot force a multi-GiB allocation. The bound must be (a) never below the
    // libzstd floor of 10, (b) never above the ceiling of 31 (= a 2 GiB window,
    // libzstd's maximum), (c) large enough to actually cover the requested
    // budget while that budget is representable in a <=31-bit window, and (d)
    // monotonic so a larger budget never SHRINKS the window.

    #[test]
    fn budget_zero_clamps_to_floor_10() {
        assert_eq!(window_log(0), 10);
    }

    #[test]
    fn budget_below_one_kib_clamps_to_floor_10() {
        for b in [1u64, 2, 17, 100, 512, 1023] {
            assert_eq!(window_log(b), 10, "budget {b} must clamp to the 10 floor");
        }
    }

    #[test]
    fn budget_exactly_one_kib_is_10() {
        assert_eq!(window_log(1 << 10), 10);
    }

    #[test]
    fn budget_one_over_one_kib_steps_to_11() {
        assert_eq!(window_log((1 << 10) + 1), 11);
    }

    #[test]
    fn exact_power_of_two_yields_that_log() {
        for k in 10u32..=31 {
            assert_eq!(
                window_log(1u64 << k),
                k,
                "2^{k} should map to windowLog {k}"
            );
        }
    }

    #[test]
    fn just_over_a_power_of_two_rounds_up() {
        for k in 10u32..31 {
            assert_eq!(
                window_log((1u64 << k) + 1),
                k + 1,
                "2^{k}+1 needs the next-larger window {}",
                k + 1
            );
        }
    }

    #[test]
    fn budget_at_two_to_31_is_ceiling_31() {
        assert_eq!(window_log(1 << 31), 31);
    }

    #[test]
    fn budget_above_two_to_31_clamps_to_ceiling_31() {
        for b in [(1u64 << 31) + 1, 1 << 32, 1 << 40, 1 << 50, u64::MAX] {
            assert_eq!(window_log(b), 31, "budget {b} must clamp to the 31 ceiling");
        }
    }

    #[test]
    fn u64_max_does_not_panic_and_is_31() {
        assert_eq!(window_log(u64::MAX), 31);
    }

    #[test]
    fn result_is_always_within_libzstd_range() {
        for b in [
            0u64,
            1,
            1023,
            1024,
            1025,
            1 << 15,
            1 << 20,
            1 << 31,
            1 << 40,
            u64::MAX,
        ] {
            let log = window_log(b);
            assert!(
                (10..=31).contains(&log),
                "windowLog {log} for budget {b} is out of [10,31]"
            );
        }
    }

    #[test]
    fn window_covers_budget_while_representable() {
        // For any budget that a 31-bit window can hold, `1 << log` must be >= it.
        for b in [
            1u64,
            1024,
            1025,
            4096,
            65_537,
            (1 << 20) + 7,
            1 << 30,
            1 << 31,
        ] {
            let log = window_log(b);
            assert!(
                (1u64 << log) >= b,
                "windowLog {log} (window {}) fails to cover budget {b}",
                1u64 << log
            );
        }
    }

    #[test]
    fn window_is_the_smallest_that_covers() {
        // Tightness: above the floor and below the ceiling, the next-smaller
        // window must be too small (no memory is wasted).
        for b in [1025u64, 4096, 65_537, (1 << 20) + 7, (1 << 24) + 1, 1 << 31] {
            let log = window_log(b);
            assert!(
                (1u64 << (log - 1)) < b,
                "windowLog {log} is not tight for budget {b}: {} already covers it",
                1u64 << (log - 1)
            );
        }
    }

    #[test]
    fn is_monotonic_non_decreasing_in_budget() {
        let mut prev = 0u32;
        let mut b = 1u64;
        while b < (1u64 << 40) {
            let log = window_log(b);
            assert!(
                log >= prev,
                "windowLog dropped from {prev} to {log} at budget {b}"
            );
            prev = log;
            b = b.saturating_mul(2).saturating_add(1);
        }
    }
}
