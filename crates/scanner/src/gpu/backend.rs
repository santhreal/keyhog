//! Single boundary for GPU acquisition, device artifacts, execution, and diagnostics.
//!
//! CUDA, Metal, and WGPU peer lifecycle and the WGPU MoE implementation are deliberately
//! private modules. Scanner code consumes only the narrow reexports below, so
//! backend-specific lazy cells, artifacts, and diagnostics cannot grow a second
//! lifecycle owner.

mod acquisition;
#[cfg(feature = "gpu")]
mod artifact;
#[cfg(feature = "gpu")]
mod diagnostics;
#[cfg(feature = "gpu")]
mod execution;
#[cfg(feature = "gpu")]
mod resident_evidence;

#[cfg(all(test, feature = "gpu", target_os = "linux"))]
pub(crate) use acquisition::load_dynamic_library;
#[cfg(all(feature = "gpu", target_os = "linux"))]
pub(crate) use acquisition::probe_cuda_peer;
pub use acquisition::GpuBackendAvailability;
pub(crate) use acquisition::{GpuBackendAcquisitionFailure, GpuBackendPeers};

#[cfg(feature = "gpu")]
pub(crate) use acquisition::get_gpu;
#[cfg(feature = "gpu")]
pub(crate) use diagnostics::moe_runtime_degrade;
#[cfg(feature = "gpu")]
pub(crate) use execution::{
    batch_score_features, gpu_moe_parity_max_divergence, GPU_MOE_PARITY_TOLERANCE,
};
#[cfg(all(test, feature = "gpu"))]
pub(crate) use resident_evidence::with_test_resident_dispatch_failure;
#[cfg(feature = "gpu")]
pub(crate) use resident_evidence::{
    scan_gpu_literal_evidence_by_region_resident, GpuResidentLiteralSlot,
};

#[cfg(all(test, feature = "gpu"))]
use crate::ml_scorer::GPU_BATCH_THRESHOLD;
#[cfg(all(test, feature = "gpu"))]
use acquisition::lazy_acquire;
#[cfg(all(test, feature = "gpu", target_os = "linux"))]
use acquisition::run_cuda_after_preflight;
#[cfg(all(test, feature = "gpu"))]
use artifact::validate_weights_size;
#[cfg(all(test, feature = "gpu"))]
use diagnostics::{
    classify_gpu_init_failure, on_gpu_init_failed, GpuInitError, GpuInitFailureAction,
};
#[cfg(all(test, feature = "gpu"))]
use execution::{
    checked_moe_scores, dispatch_moe_batch, gpu_moe_parity_probe_features, GpuParams, INPUT_DIM,
};
#[cfg(all(test, feature = "gpu"))]
use std::sync::OnceLock;
#[cfg(all(test, feature = "gpu"))]
use std::time::Duration;

#[cfg(all(test, feature = "gpu"))]
#[path = "../../tests/unit/gpu_backend.rs"]
mod tests;
#[cfg(all(test, feature = "gpu"))]
#[path = "../../tests/unit/gpu_evidence_dispatch.rs"]
mod gpu_evidence_dispatch_tests;
