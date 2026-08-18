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

/// GPU region dispatch phase breakdown and detail metrics drained from typed profiler storage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct GpuDispatchSplit {
    pub matcher_ns: u64,
    pub coalesce_ns: u64,
    pub dispatch_ns: u64,
    pub derive_ns: u64,
    pub floor_ns: u64,
    pub phase2_gpu_ns: u64,
    pub coalesced_bytes: u64,
    pub max_dispatch_bytes: u64,
    pub dispatch_calls: u64,
    pub recoveries: u64,
    pub presence_bits: u64,
    pub underfire_recovered: u64,
    pub trigger_bits: u64,
    pub phase2_admitted: u64,
    pub phase2_evidence_bits: u64,
    pub phase2_haystack_uploads: u64,
    pub phase2_complete_chunks: u64,
    pub phase2_complete_rows: u64,
    pub phase2_excluded_oversized: u64,
    pub phase2_excluded_non_ascii: u64,
    pub phase2_always_anchor_chunks: u64,
    pub phase2_always_anchor_candidate_rows: u64,
    pub phase2_always_anchor_candidate_count: u64,
    pub confirmed_anchor_candidate_rows: u64,
    pub confirmed_anchor_candidate_count: u64,
    pub generic_keyword_candidate_rows: u64,
    pub generic_keyword_candidate_count: u64,
}

impl GpuDispatchSplit {
    pub(crate) fn any_recorded(&self) -> bool {
        self.matcher_ns > 0
            || self.coalesce_ns > 0
            || self.dispatch_ns > 0
            || self.derive_ns > 0
            || self.floor_ns > 0
            || self.phase2_gpu_ns > 0
            || self.dispatch_calls > 0
    }
}

pub(crate) fn gpu_dispatch_split_from_typed(
    metrics: &[keyhog_profile::TypedMetricRecordV2],
) -> GpuDispatchSplit {
    let value = |counter: keyhog_profile::CounterId| {
        metrics
            .iter()
            .find(|record| record.metric_id == counter.metric_id())
            .map_or(0, |record| record.value)
    };
    GpuDispatchSplit {
        matcher_ns: value(keyhog_profile::CounterId::GpuMatcherNs),
        coalesce_ns: value(keyhog_profile::CounterId::GpuCoalesceNs),
        dispatch_ns: value(keyhog_profile::CounterId::GpuDispatchNs),
        derive_ns: value(keyhog_profile::CounterId::GpuDeriveNs),
        floor_ns: value(keyhog_profile::CounterId::GpuRecallFloorNs),
        phase2_gpu_ns: value(keyhog_profile::CounterId::Phase2GpuAdmissionNs),
        coalesced_bytes: value(keyhog_profile::CounterId::GpuCoalescedBytes),
        max_dispatch_bytes: value(keyhog_profile::CounterId::GpuMaxDispatchBytes),
        dispatch_calls: value(keyhog_profile::CounterId::GpuDispatchCalls),
        recoveries: value(keyhog_profile::CounterId::GpuRecoveries),
        presence_bits: value(keyhog_profile::CounterId::GpuPresenceBits),
        underfire_recovered: value(keyhog_profile::CounterId::GpuUnderfireRecovered),
        trigger_bits: value(keyhog_profile::CounterId::GpuTriggerBits),
        phase2_admitted: value(keyhog_profile::CounterId::Phase2GpuAdmitted),
        phase2_evidence_bits: value(keyhog_profile::CounterId::Phase2GpuEvidenceBits),
        phase2_haystack_uploads: value(keyhog_profile::CounterId::Phase2GpuHaystackUploads),
        phase2_complete_chunks: value(keyhog_profile::CounterId::Phase2GpuCompleteChunks),
        phase2_complete_rows: value(keyhog_profile::CounterId::Phase2GpuCompleteRows),
        phase2_excluded_oversized: value(keyhog_profile::CounterId::Phase2GpuExcludedOversized),
        phase2_excluded_non_ascii: value(keyhog_profile::CounterId::Phase2GpuExcludedNonAscii),
        phase2_always_anchor_chunks: value(keyhog_profile::CounterId::Phase2AlwaysAnchorChunks),
        phase2_always_anchor_candidate_rows: value(
            keyhog_profile::CounterId::Phase2AlwaysAnchorCandidateRows,
        ),
        phase2_always_anchor_candidate_count: value(
            keyhog_profile::CounterId::Phase2AlwaysAnchorCandidateCount,
        ),
        confirmed_anchor_candidate_rows: value(
            keyhog_profile::CounterId::ConfirmedAnchorCandidateRows,
        ),
        confirmed_anchor_candidate_count: value(
            keyhog_profile::CounterId::ConfirmedAnchorCandidateCount,
        ),
        generic_keyword_candidate_rows: value(
            keyhog_profile::CounterId::GenericKeywordCandidateRows,
        ),
        generic_keyword_candidate_count: value(
            keyhog_profile::CounterId::GenericKeywordCandidateCount,
        ),
    }
}

pub(crate) fn format_gpu_dispatch_split(split: &GpuDispatchSplit) -> String {
    let m = split.matcher_ns as f64 / 1e6;
    let c = split.coalesce_ns as f64 / 1e6;
    let d = split.dispatch_ns as f64 / 1e6;
    let der = split.derive_ns as f64 / 1e6;
    let f = split.floor_ns as f64 / 1e6;
    let p2 = split.phase2_gpu_ns as f64 / 1e6;
    let total_compute = c + d + der;
    let coalesce_mib_s = if split.coalesce_ns > 0 && split.coalesced_bytes > 0 {
        (split.coalesced_bytes as f64 / (1024.0 * 1024.0)) / (split.coalesce_ns as f64 / 1e9)
    } else {
        0.0
    };
    format!(
        "=== GPU dispatch split: matcher={m:.3}ms coalesce={c:.3}ms ({coalesce_mib_s:.1} MiB/s) dispatch={d:.3}ms derive={der:.3}ms floor={f:.3}ms phase2_gpu={p2:.3}ms (compute = {:.1}% transfer/kernel) dispatches={} coalesced_bytes={} trigger_bits={} ===",
        if total_compute > 0.0 { 100.0 * d / total_compute } else { 0.0 },
        split.dispatch_calls,
        split.coalesced_bytes,
        split.trigger_bits,
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
