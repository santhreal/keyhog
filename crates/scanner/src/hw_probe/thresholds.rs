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
//! The tier→threshold map is conservative because the live region-presence GPU
//! route is still full-scan limited by host coalescing/readback and the shared
//! CPU phase-2 tail. The last high-tier RTX 5090 sweep (2026-06-19) did not
//! beat best CPU/SIMD through 64 MiB, so heuristic GPU routing starts beyond
//! that measured no-win range. Install-time autoroute calibration is
//! authoritative and still measures GPU candidates when explicitly opted in.
//!
//! | Tier   | Adapter examples                    | Heuristic starts at |
//! |--------|-------------------------------------|---------------------|
//! | High   | RTX 40/50, A100, H100, M-series Max | 128 MiB             |
//! | Mid    | RTX 20/30, GTX 16, Arc, M-series base | 256 MiB           |
//! | Low    | iGPU (UHD/Iris), Vega, older cards   | 512 MiB             |

/// **Conservative** (low-tier) minimum total scan-buffer size before
/// we'll dispatch to GPU. Top-tier GPUs (RTX 40/50, A100/H100,
/// M-series Max) get the much lower [`GPU_MIN_BYTES_HIGH_TIER`]
/// threshold instead.
pub(crate) const GPU_MIN_BYTES: u64 = 512 * 1024 * 1024;
/// Mid-tier (RTX 20/30, GTX 16, Intel Arc, M-series base): 256 MiB.
pub(crate) const GPU_MIN_BYTES_MID_TIER: u64 = 256 * 1024 * 1024;
/// High-tier (RTX 40/50, A100/H100, M-series Max): 128 MiB. The live
/// region-presence route did not beat CPU/SIMD through 64 MiB on RTX 5090, so
/// fixed heuristic routing must not engage at or below that measured range.
pub(crate) const GPU_MIN_BYTES_HIGH_TIER: u64 = 128 * 1024 * 1024;
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
pub(crate) const GPU_BYTES_BREAKEVEN_SOLO: u64 = 1024 * 1024 * 1024;
/// High-tier solo cap: 256 MiB. Smaller files require install-time calibration
/// evidence before GPU can be trusted as fastest.
pub(crate) const GPU_BYTES_BREAKEVEN_SOLO_HIGH_TIER: u64 = 256 * 1024 * 1024;
/// Mid-tier solo cap: 512 MiB.
pub(crate) const GPU_BYTES_BREAKEVEN_SOLO_MID_TIER: u64 = 512 * 1024 * 1024;
