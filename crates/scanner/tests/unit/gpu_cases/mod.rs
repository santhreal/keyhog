//! LR1-A2 hand-written unit tests (one `#[test]` per file).

mod gpu_available_is_boolean;
mod probe_hardware_reports_cores;
mod probe_hardware_is_cached;
mod startup_banner_no_gpu;
mod startup_banner_software_gpu_ignored;
mod gpu_self_test_returns_result;
mod select_backend_high_tier_large_file;
mod select_backend_small_workload_stays_simd;
