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
//! The fixed tier map remains conservative because it cannot distinguish a
//! cold one-shot process from a warm daemon. The production-window RTX 5090
//! baseline proves a warm 8 MiB GPU win (31.4524 ms vs 35.0860 ms Hyperscan),
//! but not a cold-process win. Persisted autoroute calibration owns aggressive
//! workload-specific decisions; this heuristic must not substitute for them.
//!
//! | Tier   | Adapter examples                    | Heuristic starts at |
//! |--------|-------------------------------------|---------------------|
//! | High   | RTX 40/50, A100, H100, M-series Max | 128 MiB             |
//! | Mid    | RTX 20/30, GTX 16, Arc, M-series base | 256 MiB           |
//! | Low    | iGPU (UHD/Iris), Vega, older cards   | 512 MiB             |

/// Bytes per binary megabyte (MiB). Single owner of the `1024 * 1024`
/// multiplier shared by the GPU byte-size thresholds below.
const MIB: u64 = 1024 * 1024;

/// **Conservative** (low-tier) minimum total scan-buffer size before
/// we'll dispatch to GPU. Top-tier GPUs (RTX 40/50, A100/H100,
/// M-series Max) get the much lower [`GPU_MIN_BYTES_HIGH_TIER`]
/// threshold instead.
pub(crate) const GPU_MIN_BYTES: u64 = 512 * MIB;
/// Mid-tier (RTX 20/30, GTX 16, Intel Arc, M-series base): 256 MiB.
pub(crate) const GPU_MIN_BYTES_MID_TIER: u64 = 256 * MIB;
/// High-tier fixed fallback: 128 MiB. Calibrated routing may select GPU at a
/// smaller exact bucket when cold/warm evidence proves it fastest.
pub(crate) const GPU_MIN_BYTES_HIGH_TIER: u64 = 128 * MIB;
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
/// Single-file size that justifies GPU even at low pattern counts on low-tier
/// adapters. Kept no more aggressive than the measured no-win high-tier range.
pub(crate) const GPU_BYTES_BREAKEVEN_SOLO: u64 = 1024 * MIB;
/// High-tier fixed single-file fallback: 256 MiB. Smaller exact buckets require
/// persisted cold/warm calibration evidence.
pub(crate) const GPU_BYTES_BREAKEVEN_SOLO_HIGH_TIER: u64 = 256 * MIB;
/// Mid-tier solo cap: 512 MiB.
pub(crate) const GPU_BYTES_BREAKEVEN_SOLO_MID_TIER: u64 = 512 * MIB;
