//! VYRE GPU backend acquisition, routing evidence, and recovery accounting.
//!
//! KeyHog owns orchestration only. Detector kernels, compiled programs,
//! resident resources, transfers, dispatch, and readback are implemented by
//! VYRE and exposed through its backend-neutral interfaces.
#[cfg(feature = "gpu")]
mod adapter_probe;
mod backend;
pub mod device_set;
#[cfg(feature = "gpu")]
pub(crate) mod evidence;
#[cfg(all(test, feature = "gpu", target_os = "linux"))]
pub(crate) use backend::load_dynamic_library;
#[cfg(all(feature = "gpu", target_os = "linux"))]
pub(crate) use backend::probe_cuda_peer;
pub use backend::GpuBackendAvailability;
#[cfg(feature = "gpu")]
pub use backend::{
    acquire_ordered_gpu_device_set, enumerate_gpu_device_census, AcquiredGpuDeviceSet,
};
#[cfg(feature = "gpu")]
pub(crate) use backend::{
    gpu_resident_literal_required_device_bytes, scan_gpu_literal_evidence_by_region_resident,
    GpuResidentLiteralOverlap, GpuResidentLiteralSlot,
};
#[cfg(all(test, feature = "gpu"))]
pub(crate) use backend::{
    reset_test_max_in_flight_slots, test_max_in_flight_slots, with_test_resident_dispatch_failure,
};
pub(crate) use backend::{GpuBackendAcquisitionFailure, GpuBackendPeers, SelectedGpuPeer};
#[cfg(all(test, feature = "gpu"))]
pub(crate) use evidence::{
    host_data_movement_snapshot, reset_host_data_movement_counters, GpuHostDataMovementSite,
};
type RecoveryReceiptCounter = std::sync::Arc<std::sync::atomic::AtomicU64>;

thread_local! {
    static RECOVERY_RECEIPT_COUNTER: std::cell::RefCell<Option<RecoveryReceiptCounter>> =
        const { std::cell::RefCell::new(None) };
}

struct RecoveryReceiptCounterGuard {
    previous: Option<RecoveryReceiptCounter>,
}

impl Drop for RecoveryReceiptCounterGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        RECOVERY_RECEIPT_COUNTER.with_borrow_mut(|counter| {
            *counter = previous;
        });
    }
}

pub(crate) fn capture_recovery_receipts() -> Option<RecoveryReceiptCounter> {
    RECOVERY_RECEIPT_COUNTER.with_borrow(|counter| counter.clone())
}

pub(crate) fn with_captured_recovery_receipts<T>(
    counter: Option<&RecoveryReceiptCounter>,
    operation: impl FnOnce() -> T,
) -> T {
    let previous = RECOVERY_RECEIPT_COUNTER
        .with_borrow_mut(|current| std::mem::replace(&mut *current, counter.cloned()));
    let _guard = RecoveryReceiptCounterGuard { previous };
    operation()
}

pub(crate) fn with_recovery_receipt_scope<T>(operation: impl FnOnce() -> T) -> (T, u64) {
    let counter = RecoveryReceiptCounter::new(std::sync::atomic::AtomicU64::new(0));
    let result = with_captured_recovery_receipts(Some(&counter), operation);
    let receipts = counter.load(std::sync::atomic::Ordering::Relaxed);
    (result, receipts)
}

/// Record one request-scoped GPU recovery receipt.
pub(crate) fn record_recovery_receipt() {
    RECOVERY_RECEIPT_COUNTER.with_borrow(|counter| {
        if let Some(counter) = counter {
            match counter.fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |receipts| Some(receipts.saturating_add(1)),
            ) {
                Ok(_) => {}
                // LAW10: impossible unconditional update rejection is surfaced loudly to
                // stderr and tracing; no recovery receipt is silently dropped.
                Err(_) => {
                    eprintln!(
                        "keyhog: recovery receipt counter rejected an unconditional saturating update"
                    );
                    tracing::error!(
                        target: "keyhog::gpu",
                        "recovery receipt counter rejected an unconditional saturating update"
                    );
                }
            }
        }
    });
}
mod policy;
pub use policy::*;
mod self_test;
pub use self_test::*;

#[cfg(all(feature = "gpu", target_os = "linux"))]
pub(crate) use adapter_probe::linux_cuda_runtime_identity;
#[cfg(feature = "gpu")]
pub(crate) use adapter_probe::{
    gpu_adapter_device_identity, gpu_adapter_probe, is_software_adapter,
};

/// Render the feature-extraction and confidence-score timing split from typed
/// profiler counters. The scorer records CPU work identically for every route.
pub(crate) fn format_ml_split(feature_ns: u64, score_ns: u64) -> String {
    let f = feature_ns as f64 / 1e6;
    let s = score_ns as f64 / 1e6;
    format!(
        "=== ML split: feature_extract={f:.1}ms moe_score={s:.1}ms (score = {:.1}% of ML compute) ===",
        100.0 * s / (f + s).max(1e-9),
    )
}

/// Build the feature/score split from one drained typed-metric batch. Missing
/// counters read as zero; the caller prints nothing when both are zero.
pub(crate) fn ml_split_from_typed(metrics: &[keyhog_profile::TypedMetricRecordV2]) -> (u64, u64) {
    let value = |counter: keyhog_profile::CounterId| {
        metrics
            .iter()
            .find(|record| record.metric_id == counter.metric_id())
            .map_or(0, |record| record.value)
    };
    (
        value(keyhog_profile::CounterId::MlFeatureNs),
        value(keyhog_profile::CounterId::MlScoreNs),
    )
}

/// Return `true` when a VYRE GPU detection route is available in this
/// build/runtime.
///
/// Honors the resolved runtime policy before touching adapter acquisition.
///
/// # Examples
///
/// ```rust
/// use keyhog_scanner::gpu::gpu_available;
/// let _ = gpu_available();
/// ```
pub fn gpu_available() -> bool {
    gpu_probe().available
}

#[cfg(test)]
#[path = "../tests/unit/gpu_evidence_cpu_silence.rs"]
mod gpu_evidence_cpu_silence_tests;
#[cfg(all(test, feature = "gpu"))]
#[path = "../tests/unit/gpu_evidence_recovery.rs"]
mod gpu_evidence_recovery_tests;
