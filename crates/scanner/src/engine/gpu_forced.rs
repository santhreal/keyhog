//! Direct-library GPU selection and runtime-fault accounting.
//!
//! Infallible backend APIs preserve their explicit process contract here.
//! Production orchestrators use the scanner's fallible coalesced boundary,
//! visibly replay stable input, and report complete-after-recovery receipts.

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
