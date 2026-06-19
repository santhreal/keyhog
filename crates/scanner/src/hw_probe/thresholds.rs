//! Routing crossover thresholds. Internal constants feed the tier lookup
//! functions; CLI/reporting consumes those functions instead of duplicating
//! raw threshold values.
//!
//! Thresholds are **GPU-tier-aware** instead of one-size-fits-all.
//! The legacy single-value `GPU_MIN_BYTES` / `GPU_BYTES_BREAKEVEN_SOLO`
//! constants are kept as the conservative (low-tier) defaults; the
//! router consults [`super::gpu_min_bytes_for_tier`] /
//! [`super::gpu_solo_bytes_for_tier`] to pick the right breakeven for
//! the actual adapter.
//!
//! The tier→threshold map is calibrated against the published dispatch
//! latency of each GPU class:
//!
//! | Tier   | Adapter examples                | Dispatch latency | GPU activates at |
//! |--------|---------------------------------|------------------|-------------------|
//! | High   | RTX 40/50, A100, H100, M-series Max | 100-300 µs   | **2 MiB**         |
//! | Mid    | RTX 20/30, GTX 16, Arc, M-series base | 600-1500 µs | 16 MiB            |
//! | Low    | iGPU (UHD/Iris), Vega, older cards   | 2-5 ms         | 64 MiB            |
//!
//! At Hyperscan's typical 3 GB/s, breakeven workload = dispatch_latency × 3 GB/s.
//! 100 µs × 3000 bytes/µs ≈ 300 KB (round up to 2 MiB for safety margin
//! + per-batch parallel-CPU contention).

/// **Conservative** (low-tier) minimum total scan-buffer size before
/// we'll dispatch to GPU. Top-tier GPUs (RTX 40/50, A100/H100,
/// M-series Max) get the much lower [`GPU_MIN_BYTES_HIGH_TIER`]
/// threshold instead.
pub(crate) const GPU_MIN_BYTES: u64 = 64 * 1024 * 1024;
/// Mid-tier (RTX 20/30, GTX 16, Intel Arc, M-series base): 16 MiB.
pub(crate) const GPU_MIN_BYTES_MID_TIER: u64 = 16 * 1024 * 1024;
/// High-tier (RTX 40/50, A100/H100, M-series Max): 2 MiB.
/// At ~100 µs dispatch latency on these GPUs vs Hyperscan's
/// 3 GB/s, breakeven workload is ~300 KB; 2 MiB gives headroom
/// for the per-batch parallel-CPU contention that Hyperscan
/// benefits from.
pub(crate) const GPU_MIN_BYTES_HIGH_TIER: u64 = 2 * 1024 * 1024;
/// Pattern count above which GPU literal matching becomes worthwhile
/// regardless of buffer size - many patterns saturate Hyperscan's
/// scratch space and serial AC. Conservative (low-tier) default;
/// see [`super::gpu_pattern_breakeven_for_tier`] for the tier-aware value.
pub(crate) const GPU_PATTERN_BREAKEVEN: usize = 2_000;
/// High-tier GPUs (RTX 40/50, A100/H100, M-Max) win on as few as
/// 100 patterns once dispatch overhead is sub-millisecond.
pub(crate) const GPU_PATTERN_BREAKEVEN_HIGH_TIER: usize = 100;
/// Mid-tier crossover: 500 patterns.
pub(crate) const GPU_PATTERN_BREAKEVEN_MID_TIER: usize = 500;
/// Single-file size that justifies GPU even at low pattern counts.
/// One device dispatch beats saturating one CPU core with Hyperscan
/// when the file alone is this big.
pub(crate) const GPU_BYTES_BREAKEVEN_SOLO: u64 = 256 * 1024 * 1024;
/// High-tier solo cap: 16 MiB single file already justifies GPU
/// dispatch on a 5090-class adapter.
pub(crate) const GPU_BYTES_BREAKEVEN_SOLO_HIGH_TIER: u64 = 16 * 1024 * 1024;
/// Mid-tier solo cap: 64 MiB.
pub(crate) const GPU_BYTES_BREAKEVEN_SOLO_MID_TIER: u64 = 64 * 1024 * 1024;
