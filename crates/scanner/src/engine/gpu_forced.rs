//! KH-GAP-002: explicit failure when the selected GPU backend is unavailable.
//!
//! Also: one-shot loud warning on runtime GPU dispatch failure that
//! degrades to CPU. The hardware probe + compile-time visibility
//! warnings can't catch the case where GPU acquisition succeeds but
//! a specific scan dispatch fails (vyre lowering rejecting a
//! program, CUDA driver returning a transient error, etc.). Per
//! the no-silent-fallback rule, the user needs to know the scan
//! didn't actually use the GPU they thought was active.

pub(crate) use super::gpu_forced_helpers::{
    deny_silent_gpu_degrade, deny_silent_gpu_degrade_with_reason,
};
use super::CompiledScanner;

impl CompiledScanner {
    pub(super) fn record_gpu_degrade(&self, reason: impl Into<String>) {
        let reason = reason.into();
        if let Ok(mut slot) = self.gpu_last_degrade_reason.lock() {
            // LAW10: poison loses only the diagnostic string; gpu_degrade_count below still records the runtime degrade.
            *slot = Some(reason);
        }
        self.gpu_degrade_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
