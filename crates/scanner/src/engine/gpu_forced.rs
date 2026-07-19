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
        // Poison still stores the reason: a poisoned mutex must not drop the
        // only diagnostic while the degrade counter still increments (KH-1290).
        let mut slot = self
            .gpu_last_degrade_reason
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *slot = Some(reason);
        self.gpu_degrade_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
