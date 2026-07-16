use crate::hw_probe::ScanBackend;

use super::CompiledScanner;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SelectedGpuDispatchError {
    reason: String,
}

impl SelectedGpuDispatchError {
    pub(crate) fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    pub(crate) fn reason(&self) -> &str {
        &self.reason
    }
}

impl std::fmt::Display for SelectedGpuDispatchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for SelectedGpuDispatchError {}

/// Error message when routing forces GPU but the scanner cannot dispatch.
#[must_use]
pub(crate) fn gpu_forced_unavailable_message(
    scanner: &CompiledScanner,
    backend: ScanBackend,
) -> Option<String> {
    if !backend.is_gpu() {
        return None;
    }
    if scanner.gpu_stack_usable_for(backend) {
        return None;
    }
    Some(format!(
        "{} selected but GPU stack unavailable (gpu_literals={}, gpu_backend={}, gpu_matcher={}) - \
         silent CPU fallback is forbidden; repair this GPU driver and recalibrate autoroute, or explicitly choose another backend",
        backend.label(),
        scanner.gpu_literals.is_some(),
        scanner.gpu_backends.get(backend).is_some(),
        scanner.gpu_matcher().is_some(),
    ))
}

/// Exit from the infallible direct-library API when its selected GPU cannot
/// dispatch. CLI autoroute uses the fallible coalesced boundary and owns visible
/// replay of the same stable input instead.
///
/// ## Why a scanner hard exit survives in the library here (M12)
///
/// The clean fail-closed path for `--require-gpu` on a no-GPU host
/// is the CLI preflight ([`crate::gpu::require_gpu_preflight`], called from
/// `orchestrator::run` before any scan) which returns the documented
/// `ExitCode` through the CLI - no library `process::exit`, so embedders
/// stay alive. This function's hard exit covers a *different*, narrower
/// case: a caller chose an infallible direct-backend API whose return type has
/// no error channel. The process exit is bounded to that explicit contract;
/// production orchestrators call the fallible companion and preserve coverage.
pub(crate) fn require_selected_gpu_stack(scanner: &CompiledScanner, backend: ScanBackend) {
    if let Some(msg) = gpu_forced_unavailable_message(scanner, backend) {
        crate::process_exit::require_gpu_unmet(msg);
    }
}

/// Record the concrete dispatch failure and terminate the selected GPU route.
///
/// Keeping this operation divergent makes it impossible for an error branch to
/// retain an unreachable CPU/SIMD substitution after the failure is surfaced.
pub(crate) fn fail_selected_gpu_dispatch(scanner: &CompiledScanner, reason: &str) -> ! {
    fail_selected_gpu_dispatch_error(scanner, SelectedGpuDispatchError::new(reason))
}

pub(crate) fn fail_selected_gpu_dispatch_error(
    scanner: &CompiledScanner,
    error: SelectedGpuDispatchError,
) -> ! {
    scanner.record_gpu_runtime_fault(error.reason());
    crate::process_exit::require_gpu_unmet(format!(
        "selected GPU dispatch failed at runtime ({error}) \
(literals={}, backend={}, matcher={}); refusing to substitute CPU/SIMD. \
Run `keyhog backend --self-test`, then recalibrate autoroute or select another backend explicitly",
        scanner.gpu_literals.is_some(),
        scanner.gpu_backends.availability().any(),
        scanner.gpu_matcher().is_some(),
    ));
}
