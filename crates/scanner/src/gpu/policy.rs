//! GPU runtime policy + require-GPU preflight policy.
//!
//! Split out of `gpu.rs` (Law 5 / 500-LOC modularity cap): these are the
//! explicit runtime-policy readers plus the `require-GPU` preflight that fails
//! closed when a GPU is demanded but absent. Re-exported from `gpu` via
//! `pub use policy::*`.

#[cfg(feature = "gpu")]
use super::backend;
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

pub fn set_gpu_runtime_policy(policy: GpuRuntimePolicy) {
    GPU_RUNTIME_POLICY.store(policy as u8, Ordering::SeqCst);
}

#[must_use]
pub fn gpu_runtime_policy() -> GpuRuntimePolicy {
    GpuRuntimePolicy::from_u8(GPU_RUNTIME_POLICY.load(Ordering::SeqCst))
}

/// Probe GPU availability and adapter metadata without panicking.
///
/// Honours the explicit disabled GPU policy by reporting "no GPU available"
/// without ever calling `backend::get_gpu()`. The MoE compute-shader init
/// happens lazily inside `get_gpu()`, so this short-circuit is the difference
/// between "adapter request blocks for minutes on broken driver stacks" and
/// "scanner starts like every other CPU-only tool".
#[must_use]
pub(crate) fn gpu_probe() -> (bool, Option<String>, Option<u64>) {
    if gpu_disabled_by_policy() {
        return (false, None, None);
    }
    #[cfg(feature = "gpu")]
    if let Some(gpu) = backend::get_gpu() {
        return (true, Some(gpu.gpu_name().to_string()), gpu.vram_mb());
    }
    (false, None, None)
}

/// True when the resolved runtime policy demands a usable GPU and a silent CPU
/// fallback is forbidden.
#[must_use]
pub fn gpu_required_by_policy() -> bool {
    gpu_runtime_policy() == GpuRuntimePolicy::Required
}

/// Require-GPU preflight, independent of backend routing.
///
/// When the policy is not [`GpuRuntimePolicy::Required`] this is a no-op and
/// returns `Ok(())`. When it is required, the contract is to refuse to run when
/// no usable GPU adapter is detected. This check fires on the no-GPU path the
/// flag exists for; it does not depend on `select_backend` having chosen GPU
/// first.
///
/// Returns `Err(diagnostic)` when a GPU is required but the host has no
/// non-software adapter, or the GPU self-test (adapter init + one real MoE
/// compute dispatch) fails. The caller (CLI run loop) maps that to the
/// documented exit code 2. Returning an `Err` here - rather than calling
/// `std::process::exit` from the library - keeps embedders alive (finding
/// M12).
pub fn require_gpu_preflight() -> Result<(), String> {
    if !gpu_required_by_policy() {
        return Ok(());
    }

    let caps = crate::hw_probe::probe_hardware();
    if !caps.gpu_available || caps.gpu_is_software {
        let detail = match (&caps.gpu_name, caps.gpu_is_software) {
            (Some(name), true) => {
                format!("only a software GPU adapter is present ({name})")
            }
            (Some(name), false) => format!("adapter present but unusable ({name})"),
            (None, _) => "no GPU adapter detected".to_string(),
        };
        return Err(format!(
            "--require-gpu requested but {detail}; refusing to run on CPU. \
             Install or enable a non-software GPU adapter + driver, or run \
             without --require-gpu to allow the CPU/SIMD path."
        ));
    }

    // A non-software adapter is reported. Prove it can actually run a
    // production-sized MoE dispatch before declaring the requirement met -
    // a present-but-broken GPU (driver mismatch, dispatch reject) is exactly
    // the regression the flag is meant to catch on self-hosted runners.
    if let Err(reason) = super::gpu_self_test() {
        return Err(format!(
            "--require-gpu requested but the GPU self-test failed ({reason}); \
             refusing to run on CPU. Fix the GPU stack or run without \
             --require-gpu."
        ));
    }

    Ok(())
}

pub(crate) fn gpu_disabled_by_policy() -> bool {
    matches!(gpu_runtime_policy(), GpuRuntimePolicy::Disabled)
}
