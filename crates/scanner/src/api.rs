//! Curated public re-export surface for `keyhog-scanner`.
//!
//! `lib.rs` declares the scanner subsystems; this module keeps the root
//! compatibility exports in one place.

pub use crate::compiled_scanner::{
    CompiledScannerRuntime, GpuBackendAvailability, GpuBackendCandidateStatus, GpuInitPolicy,
};
pub use crate::engine::{
    BackendRecoveryReceipt, CoalescedScanOutcome, CompiledScanner, Phase1AdmissionPlan,
    Phase1AdmissionSummary, RecoveredInputRange,
};
pub use crate::error::{Result, ScanError};
pub use crate::gpu_input_budget::{
    gpu_batch_input_limit, gpu_batch_input_limit_bounds, set_gpu_batch_input_limit,
};
pub use crate::gpu_literal_artifacts::{
    compile_gpu_literal_artifacts, compile_gpu_literal_artifacts_default,
    gpu_literal_artifact_cache_dir, GpuLiteralArtifact, GpuLiteralArtifacts,
};
pub use crate::hw_probe::{probe_hardware, select_backend, HardwareCaps, ScanBackend};
pub use crate::scan_profile::{
    dump as profile_dump, reset as profile_reset, set_perf_trace_enabled, set_profile_enabled,
};
pub use crate::types::{
    regex_dfa_limit_default, set_regex_dfa_limit, ScanExecutionRoute, ScannerConfig,
    ScannerTuningConfig,
};
pub use crate::util_hash::{FNV_OFFSET_BASIS, FNV_PRIME};
