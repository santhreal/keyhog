//! GPU runtime policy + require-GPU preflight policy.
//!
//! Split out of `gpu.rs` (Law 5 / 500-LOC modularity cap): these are the
//! explicit runtime-policy readers plus the `require-GPU` preflight that fails
//! closed when a GPU is demanded but absent. Re-exported from `gpu` via
//! `pub use policy::*`.

use std::{
    fmt,
    sync::atomic::{AtomicU8, Ordering},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum GpuRuntimePolicy {
    Auto = 0,
    Disabled = 1,
    Required = 2,
}

impl GpuRuntimePolicy {
    #[must_use]
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Disabled => "off",
            Self::Required => "required",
        }
    }

    #[must_use]
    pub const fn is_disabled(self) -> bool {
        matches!(self, Self::Disabled)
    }

    #[must_use]
    pub const fn is_required(self) -> bool {
        matches!(self, Self::Required)
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Disabled,
            2 => Self::Required,
            _ => Self::Auto,
        }
    }
}

impl fmt::Display for GpuRuntimePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).label())
    }
}

static GPU_RUNTIME_POLICY: AtomicU8 = AtomicU8::new(GpuRuntimePolicy::Auto as u8);

#[derive(Debug, Clone, Default)]
pub(crate) struct GpuRuntimeProbe {
    pub(crate) available: bool,
    pub(crate) name: Option<String>,
    pub(crate) buffer_limit_mb: Option<u64>,
    pub(crate) runtime_identity: Option<String>,
    pub(crate) is_software: bool,
}

/// Set the process-wide GPU runtime policy (`Auto`/`On`/`Off`) consulted by
/// backend routing and GPU init.
pub fn set_gpu_runtime_policy(policy: GpuRuntimePolicy) {
    GPU_RUNTIME_POLICY.store(policy as u8, Ordering::SeqCst);
}

/// The current process-wide GPU runtime policy.
#[must_use]
pub fn gpu_runtime_policy() -> GpuRuntimePolicy {
    GpuRuntimePolicy::from_u8(GPU_RUNTIME_POLICY.load(Ordering::SeqCst))
}

/// Probe GPU availability and adapter metadata without panicking.
///
/// Honours the explicit disabled GPU policy before adapter enumeration, so a
/// CPU-only process never touches a broken driver stack.
#[must_use]
pub(crate) fn gpu_probe() -> GpuRuntimeProbe {
    if gpu_disabled_by_policy() {
        return GpuRuntimeProbe::default();
    }
    #[cfg(all(feature = "gpu", target_os = "linux"))]
    if let Ok(cuda) = super::probe_cuda_peer() {
        // LAW10: hardware probe for CUDA peer; absent accelerator is surfaced and recall preserved through CPU/SIMD path
        let name = if cuda.name.is_empty() {
            format!(
                "NVIDIA GPU (CUDA cap {}.{})",
                cuda.compute_capability.0, cuda.compute_capability.1
            )
        } else {
            cuda.name.clone()
        };
        return GpuRuntimeProbe {
            available: true,
            name: Some(name),
            buffer_limit_mb: Some(cuda.total_memory / (1024 * 1024)),
            runtime_identity: super::linux_cuda_runtime_identity().ok(), // LAW10: optional driver identity probe; diagnostic accessor reporting-only
            is_software: false,
        };
    }
    #[cfg(feature = "gpu")]
    if let Some(gpu) = super::gpu_adapter_probe() {
        return GpuRuntimeProbe {
            available: !gpu.is_software,
            name: Some(gpu.name.clone()),
            buffer_limit_mb: Some(gpu.buffer_limit_mb),
            runtime_identity: Some(gpu.runtime_identity.clone()),
            is_software: gpu.is_software,
        };
    }
    if let Some(physical_name) = crate::hw_probe::platform::detect_physical_gpu_name() {
        return GpuRuntimeProbe {
            available: false,
            name: Some(physical_name),
            buffer_limit_mb: None,
            runtime_identity: None,
            is_software: false,
        };
    }
    GpuRuntimeProbe::default()
}

/// True when the resolved runtime policy demands a usable GPU and a silent CPU
/// fallback is forbidden.
#[must_use]
pub fn gpu_required_by_policy() -> bool {
    gpu_runtime_policy().is_required()
}

/// Require-GPU preflight, independent of backend routing.
///
/// When the policy is not [`GpuRuntimePolicy::Required`] this is a no-op and
/// returns `Ok(())`. When it is required, the contract is to refuse to run when
/// no usable GPU adapter is detected. This check fires on the no-GPU path the
/// flag exists for; it does not depend on `select_backend` having chosen GPU
/// first.
///
/// Returns `Err(diagnostic)` when no acquired CUDA or WGPU peer passes the
/// production region-presence parity self-test. The caller maps that to the
/// documented exit code 12. Returning an `Err` here - rather than calling
/// `std::process::exit` from the library - keeps embedders alive (finding
/// M12).
pub fn require_gpu_preflight() -> Result<(), String> {
    require_gpu_preflight_with_policy(gpu_runtime_policy())
}

pub(crate) fn require_gpu_preflight_with_policy(policy: GpuRuntimePolicy) -> Result<(), String> {
    if !policy.is_required() {
        return Ok(());
    }

    if let Err(reason) = super::gpu_region_presence_self_test() {
        // The policy reaches `Required` from `--require-gpu` OR from an
        // explicit GPU `--backend`, and this layer cannot see which. Naming
        // only the flag sent an operator who wrote `--backend gpu-cuda`
        // looking for a flag they never passed, so the message names the
        // condition and every way to leave it.
        return Err(format!(
            "GPU execution is required by the resolved runtime policy (--require-gpu, or an \
             explicit --backend gpu-cuda/gpu-metal/gpu-wgpu) but no complete production GPU peer \
             set passed region-presence parity ({reason}); refusing to run on CPU. Fix the GPU \
             stack, or drop --require-gpu and any explicit GPU --backend to allow CPU execution."
        ));
    }

    Ok(())
}

pub(crate) fn gpu_disabled_by_policy() -> bool {
    gpu_runtime_policy().is_disabled()
}
