//! Shared compression memory limits.

/// Smallest zstd `windowLog` whose window (`1 << log`) covers `budget`, clamped
/// to libzstd's valid range `[10, 31]`.
pub(crate) fn zstd_window_log_max_for_budget(budget: u64) -> u32 {
    let b = budget.max(1 << 10);
    let log = 64 - (b - 1).leading_zeros();
    log.clamp(10, 31)
}

#[cfg(test)]
#[path = "../tests/unit/compression_limits.rs"]
mod tests;
