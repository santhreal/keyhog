//! GPU dispatch errors and runtime-fault accounting.
//!
//! Selected-backend library APIs return structured errors. Recovery-aware
//! orchestrators may replay stable input and retain an exact recovery receipt.

#[cfg(feature = "gpu")]
pub(crate) use super::gpu_forced_helpers::SelectedGpuDispatchError;
use super::CompiledScanner;

impl CompiledScanner {
    pub(super) fn record_gpu_runtime_fault(&self, reason: impl Into<String>) {
        let reason = reason.into();
        // Poison still stores the reason: a poisoned mutex must not drop the
        // only diagnostic while the degrade counter still increments (KH-1290).
        let mut slot = self
            .gpu_last_degrade_reason
            .lock()
            // LAW10: reporting-only; poison does not invalidate the recorded degradation reason, and the operator-visible counter is incremented below.
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *slot = Some(reason);
        self.gpu_degrade_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// True when a runtime literal source or packed matcher, backend handle, and
    /// compiled matcher are all present.
    pub(crate) fn gpu_stack_usable_for(&self, backend: crate::hw_probe::ScanBackend) -> bool {
        (self.gpu_literals.is_some() || self.gpu_matcher.get().is_some_and(Option::is_some))
            && self.gpu_backend(backend).is_some()
            && self.gpu_matcher().is_some()
    }
}
