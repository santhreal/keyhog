//! CUDA backend module: device lifecycle, allocation pools, and kernel dispatch.
//!
//! `allocations` owns transient device and pinned-host pools plus the
//! `cuda_check` error wrapper. `module_cache` owns loaded PTX modules.
//! `resident` owns long-lived CUDA allocations and in-flight handle guards.
//! `dispatch` owns the `CudaBackend` struct, launch geometry, and
//! kernel-launch orchestration. The public surface is re-exported below.

/// Device-side allocation pools, pinned-host pools, and `cuda_check`.
pub mod allocations;
/// Capability, feature-flag, and validation-cache policy.
pub(crate) mod capabilities;
/// cudaGraph capture-and-replay path. Records one full Program dispatch into
/// a `CUgraph` then replays it on demand to reduce hot-path launch overhead.
pub mod cuda_graph;
/// cudaGraph replay path.
pub(crate) mod cuda_graph_replay;
/// CUDA backend handle, launch geometry, and kernel-launch orchestration —
/// including the cooperative-launch path that routes through
/// `cuLaunchCooperativeKernel` when the caller opts in via
/// `DispatchConfig::cooperative`.
pub mod dispatch;
/// Host-borrowed buffer dispatch path.
pub(crate) mod host_dispatch;
/// Raw CUDA kernel launch boundary.
pub(crate) mod launch;
/// Loaded PTX module cache and submodular eviction policy.
pub(crate) mod module_cache;
/// CUDA output readback range handling.
pub(crate) mod output_range;
/// Shared dispatch-plan assembly helpers.
pub(crate) mod plan;
/// PTX target probing against the live CUDA driver.
pub(crate) mod ptx_target;
/// Resident buffer management — long-lived device allocations.
pub(crate) mod resident;
/// Resident-buffer dispatch path.
pub(crate) mod resident_dispatch;
/// Host and device copies for resident buffers.
pub(crate) mod resident_io;

pub(crate) use allocations::*;
pub(crate) use module_cache::ModuleCacheKey;
pub(crate) use plan::CudaDispatchPlan;
pub(crate) use resident::ResidentUseGuard;
// Public surface — these names appear on the crate root.
pub use cuda_graph::CachedCudaGraph;
pub use dispatch::CudaBackend;
pub use module_cache::CudaPtxSourceCacheSnapshot;
pub use resident::CudaResidentBuffer;
