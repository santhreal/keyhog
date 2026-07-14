//! KH-GAP-002: explicit failure when the selected GPU backend is unavailable.
//!
//! Runtime GPU dispatch failures also fail the selected route. The hardware
//! probe + compile-time visibility
//! warnings can't catch the case where GPU acquisition succeeds but
//! a specific scan dispatch fails (vyre lowering rejecting a
//! program, CUDA driver returning a transient error, etc.). Per
//! the no-silent-fallback rule, the user needs to know the scan
//! did not actually use the GPU it selected.

pub(crate) use super::gpu_forced_helpers::{
    fail_selected_gpu_dispatch, require_selected_gpu_stack,
};
#[cfg(feature = "gpu")]
pub(crate) use super::gpu_forced_helpers::{
    fail_selected_gpu_dispatch_error, SelectedGpuDispatchError,
};
use super::CompiledScanner;

impl CompiledScanner {
    pub(super) fn record_gpu_runtime_fault(&self, reason: impl Into<String>) {
        let reason = reason.into();
        if let Ok(mut slot) = self.gpu_last_degrade_reason.lock() {
            // LAW10: poison loses only the diagnostic string; the compatibility counter below still records the runtime fault.
            *slot = Some(reason);
        }
        self.gpu_degrade_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
