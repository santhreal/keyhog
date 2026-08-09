//! Single boundary for GPU acquisition, device artifacts, execution, and diagnostics.
//!
//! CUDA, Metal, and WGPU peer lifecycle remain private. Scanner code consumes
//! only backend-neutral VYRE handles and compact execution evidence.

mod acquisition;
#[cfg(feature = "gpu")]
mod resident_evidence;

#[cfg(all(test, feature = "gpu", target_os = "linux"))]
pub(crate) use acquisition::load_dynamic_library;
#[cfg(all(feature = "gpu", target_os = "linux"))]
pub(crate) use acquisition::probe_cuda_peer;
pub use acquisition::GpuBackendAvailability;
pub(crate) use acquisition::{GpuBackendAcquisitionFailure, GpuBackendPeers, SelectedGpuPeer};

#[cfg(all(test, feature = "gpu"))]
pub(crate) use resident_evidence::{
    reset_test_max_in_flight_slots, test_max_in_flight_slots, with_test_resident_dispatch_failure,
};
#[cfg(feature = "gpu")]
pub(crate) use resident_evidence::{
    scan_gpu_literal_evidence_by_region_resident, GpuResidentLiteralOverlap, GpuResidentLiteralSlot,
};

#[cfg(all(test, feature = "gpu"))]
use acquisition::lazy_acquire;
#[cfg(all(test, feature = "gpu", target_os = "linux"))]
use acquisition::run_cuda_after_preflight;
#[cfg(all(test, feature = "gpu"))]
use std::sync::OnceLock;

#[cfg(all(test, feature = "gpu"))]
#[path = "../../tests/unit/gpu_backend.rs"]
mod tests;
