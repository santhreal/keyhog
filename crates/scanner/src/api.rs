//! Curated public re-export surface for `keyhog-scanner`.
//!
//! `lib.rs` declares the scanner subsystems; this module keeps the root
//! compatibility exports in one place.

pub use crate::engine::{
    compile_gpu_literal_artifacts, compile_gpu_literal_artifacts_default, gpu_batch_input_limit,
    gpu_batch_input_limit_bounds, gpu_literal_artifact_cache_dir, profile_dump, profile_reset,
    set_gpu_batch_input_limit, set_perf_trace_enabled, set_profile_enabled, CompiledScanner,
    CompiledScannerRuntime, GpuInitPolicy, GpuLiteralArtifact, GpuLiteralArtifacts,
};
pub use crate::error::{Result, ScanError};
pub use crate::hw_probe::{probe_hardware, select_backend, HardwareCaps, ScanBackend};
pub use crate::types::{
    regex_dfa_limit_default, set_regex_dfa_limit, ScannerConfig, ScannerTuningConfig,
};
pub use crate::util_hash::{FNV_OFFSET_BASIS, FNV_PRIME};
