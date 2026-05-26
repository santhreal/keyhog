//! LR1-A2 hand-written unit tests (one `#[test]` per file).

mod classify_gpu_tier_rtx4090_high;
mod classify_gpu_tier_a100_high;
mod classify_gpu_tier_rtx3060_mid;
mod classify_gpu_tier_intel_arc_mid;
mod classify_gpu_tier_uhd_low;
mod classify_gpu_tier_none_is_low;
mod gpu_min_bytes_high_tier_2mb;
mod gpu_min_bytes_mid_tier_16mb;
mod gpu_min_bytes_low_tier_64mb;
mod gpu_pattern_breakeven_high_100;
mod gpu_solo_bytes_high_tier;
mod select_backend_rejects_software_gpu;
mod select_backend_env_gpu_override;
mod scan_backend_label_gpu;
mod scan_backend_label_megascan;
mod scan_backend_label_simd;
mod scan_backend_label_cpu_fallback;
