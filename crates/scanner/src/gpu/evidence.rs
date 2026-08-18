//! Accelerator evidence: one normalized typed metric set for CUDA, Metal, and
//! WGPU routes, recorded through the keyhog-profile runtime.
//!
//! Normalization (CUDA/Metal/WGPU share every metric): per-backend capability
//! differences are reported as `GpuCapabilityUnsupported` events instead of
//! diverging into per-backend counters. Typed identity and capability evidence
//! fires on the FIRST GPU dispatch that executes under each profile runtime
//! (keyed by the runtime's unique context id), never at acquisition. A
//! selected CPU scanner retains no GPU peer, while the calibration scanner
//! may census peers without dispatching them. Acquisition-time recording would
//! break the "CPU scans stay silent" contract. String identity facets (adapter
//! name, driver, driver_info) have no string-typed profile API; they ride the
//! scanner backend state's warm identity and tracing, while the typed channel
//! carries the numeric facets (backend kind, PCI vendor/device ids).
//!
//! Retained state: two process-wide residency atomics (exact, lossless) and
//! one bounded per-context dedup set ([`MAX_RECORDED_CONTEXTS`]); overflow of
//! the set is counted and warned on the `keyhog::gpu` tracing target with the
//! exact running loss count, never silently re-recorded or panicked on.

use keyhog_profile::{AnnotationId, CounterId, EventId, GaugeId, MetricId};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Normalized backend identity codes recorded as `GpuAdapterAcquired` /
/// `GpuBackendKind` / `BackendRecovered` values.
pub(crate) const BACKEND_CUDA: u64 = 1;
pub(crate) const BACKEND_METAL: u64 = 2;
pub(crate) const BACKEND_WGPU: u64 = 3;

/// Map a `vyre::VyreBackend::id()` to the normalized backend code. Vyre ids
/// are frozen per backend; anything unrecognized is treated as WGPU because
/// the only in-tree backends are cuda/metal/wgpu.
pub(crate) fn backend_code(backend_id: &str) -> u64 {
    match backend_id {
        "cuda" => BACKEND_CUDA,
        "metal" => BACKEND_METAL,
        _ => BACKEND_WGPU,
    }
}

/// Fault-kind codes recorded as `GpuFault` event values.
pub(crate) mod fault {
    pub(crate) const DISPATCH: u64 = 1;
}

/// Capability codes recorded as `GpuCapabilityUnsupported` event values.
pub(crate) mod capability {
    pub(crate) const KERNEL_TIMESTAMPS: u64 = 1;
    pub(crate) const OCCUPANCY: u64 = 2;
    pub(crate) const UTILIZATION: u64 = 3;
    pub(crate) const STALL_COUNTERS: u64 = 4;
}

/// Upper bound on retained per-context dedup slots. One profile runtime
/// claims at most 3 identity slots plus 3*4 capability slots, so 1024 slots
/// cover at least 68 fully-instrumented sessions per process.
const MAX_RECORDED_CONTEXTS: usize = 1024;

/// Bounded dedup set for once-per-runtime evidence (identity, capability
/// reports). Loss on overflow is counted, never silent.
struct ContextClaimSet {
    seen: BTreeSet<(u64, u16)>,
    lost: u64,
}

impl ContextClaimSet {
    const fn new() -> Self {
        Self {
            seen: BTreeSet::new(),
            lost: 0,
        }
    }

    /// Returns true exactly once per (context, slot); false on repeats and on
    /// capacity overflow (counted as loss).
    fn claim(&mut self, context: u64, slot: u16) -> bool {
        if self.seen.contains(&(context, slot)) {
            return false;
        }
        if self.seen.len() >= MAX_RECORDED_CONTEXTS {
            self.lost = self.lost.saturating_add(1);
            tracing::warn!(
                target: "keyhog::gpu",
                context,
                slot,
                lost = self.lost,
                capacity = MAX_RECORDED_CONTEXTS,
                "accelerator evidence dedup set is full; this once-per-runtime record is dropped"
            );
            return false;
        }
        self.seen.insert((context, slot));
        true
    }
}

static CONTEXT_CLAIMS: Mutex<ContextClaimSet> = Mutex::new(ContextClaimSet::new());

fn claim_once(context: u64, slot: u16) -> bool {
    // LAW10: poisoned dedup lock recovers in place. The claim set is a once-per-runtime
    // evidence de-duplicator, never a finding path; its contents stay consistent across a
    // panic (insert-only) and failing closed here would drop GPU evidence instead.
    let mut claims = CONTEXT_CLAIMS
        .lock()
        // LAW10: poison recovery retains the insert-only evidence set, so no claim is lost.
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    claims.claim(context, slot)
}

const IDENTITY_SLOT_BASE: u16 = 0;
const CAPABILITY_SLOT_BASE: u16 = 0x100;

/// Numeric adapter identity facets plus the string facets for tracing.
pub(crate) struct AdapterIdentity<'a> {
    pub(crate) backend_code: u64,
    /// PCI vendor id; 0 when the backend does not expose one.
    pub(crate) vendor: u32,
    /// PCI device id; 0 when the backend does not expose one.
    pub(crate) device: u32,
    pub(crate) is_software: bool,
    pub(crate) name: &'a str,
    pub(crate) driver: &'a str,
    pub(crate) driver_info: &'a str,
}

/// Record adapter identity once per profile runtime and backend. No-op when
/// no runtime is active or when this runtime already recorded this backend.
pub(crate) fn record_adapter_identity(identity: &AdapterIdentity<'_>) {
    let Some(runtime) = keyhog_profile::current_runtime() else {
        return;
    };
    let slot = IDENTITY_SLOT_BASE + identity.backend_code as u16;
    if !claim_once(runtime.context_id(), slot) {
        return;
    }
    keyhog_profile::record_event(EventId::GpuAdapterAcquired, identity.backend_code);
    keyhog_profile::record_annotation(AnnotationId::GpuBackendKind, identity.backend_code);
    keyhog_profile::record_annotation(AnnotationId::GpuAdapterVendor, u64::from(identity.vendor));
    keyhog_profile::record_annotation(AnnotationId::GpuAdapterDevice, u64::from(identity.device));
    tracing::info!(
        target: "keyhog::gpu",
        adapter = identity.name,
        backend = identity.backend_code,
        vendor = format_args!("{:#06x}", identity.vendor),
        device = format_args!("{:#06x}", identity.device),
        driver = identity.driver,
        driver_info = identity.driver_info,
        is_software = identity.is_software,
        "GPU adapter identity recorded for the active profile"
    );
}

/// Capability-report one unsupported accelerator capability once per profile
/// runtime and backend. This is the explicit-gap channel: a metric that a
/// backend cannot expose is reported here instead of silently absent.
pub(crate) fn report_capability_unsupported(backend_code: u64, capability: u64) {
    let Some(runtime) = keyhog_profile::current_runtime() else {
        return;
    };
    let slot = CAPABILITY_SLOT_BASE + capability as u16;
    if !claim_once(runtime.context_id(), slot) {
        return;
    }
    keyhog_profile::record_event(EventId::GpuCapabilityUnsupported, capability);
    tracing::debug!(
        target: "keyhog::gpu",
        backend = backend_code,
        capability,
        "accelerator capability is unsupported on this backend; the profile records an explicit gap"
    );
}

/// Report the device counter capabilities no in-tree backend exposes through
/// the sealed `vyre::VyreBackend` trait or wgpu 25: occupancy, utilization,
/// and stall counters. Deduped per runtime and backend.
pub(crate) fn report_counter_caps_unsupported(backend_code: u64) {
    for capability in [
        capability::OCCUPANCY,
        capability::UTILIZATION,
        capability::STALL_COUNTERS,
    ] {
        report_capability_unsupported(backend_code, capability);
    }
}

/// Host-to-device upload evidence for one dispatch batch. `ns` is the upload
/// transfer and staging latency in nanoseconds.
pub(crate) fn record_upload(bytes: u64, ns: Option<u64>) {
    keyhog_profile::add_counter(CounterId::GpuUploadBytes, bytes);
    if let Some(ns) = ns {
        keyhog_profile::add_counter(CounterId::GpuUploadNs, ns);
        keyhog_profile::record_distribution(MetricId::GpuUploadNs, ns);
    }
}

/// Device-to-host readback evidence for one dispatch batch. `ns` is the readback
/// transfer latency in nanoseconds.
pub(crate) fn record_readback(bytes: u64, ns: Option<u64>) {
    keyhog_profile::add_counter(CounterId::GpuReadbackBytes, bytes);
    if let Some(ns) = ns {
        keyhog_profile::add_counter(CounterId::GpuReadbackNs, ns);
        keyhog_profile::record_distribution(MetricId::GpuReadbackNs, ns);
    }
}

/// Host-observed submission-to-completion latency (queue wait + kernel +
/// on-device copies + map latency) for one dispatch.
pub(crate) fn record_submit_to_complete(ns: u64) {
    keyhog_profile::add_counter(CounterId::GpuSubmitToCompleteNs, ns);
    keyhog_profile::record_distribution(MetricId::GpuSubmitToCompleteNs, ns);
}

/// Device-reported kernel execution time (timestamp queries where the backend
/// exposes them).
pub(crate) fn record_kernel(ns: u64) {
    keyhog_profile::add_counter(CounterId::GpuKernelNs, ns);
    keyhog_profile::record_distribution(MetricId::GpuKernelNs, ns);
}

/// Submission-to-completion minus device kernel time: accelerator queue wait
/// plus on-device copy and map latency, the host-attributable non-kernel
/// fraction.
pub(crate) fn record_queue_wait(ns: u64) {
    keyhog_profile::add_counter(CounterId::GpuQueueWaitNs, ns);
    keyhog_profile::record_distribution(MetricId::GpuQueueWaitNs, ns);
}

/// One dispatch batch submitted to the device.
pub(crate) fn record_dispatch_submitted() {
    keyhog_profile::add_counter(CounterId::GpuDispatchCalls, 1);
}

/// One accelerator fault. `kind` is a [`fault`] code.
pub(crate) fn record_fault(_backend_code: u64, kind: u64) {
    keyhog_profile::add_counter(CounterId::GpuFaults, 1);
    keyhog_profile::record_event(EventId::GpuFault, kind);
}

/// One retry attempt after a fault (1-based attempt index).
pub(crate) fn record_retry(attempt: u64) {
    keyhog_profile::add_counter(CounterId::GpuRetries, 1);
    keyhog_profile::record_annotation(AnnotationId::RetryAttempt, attempt);
}

/// One recovery: work a faulted accelerator could not finish is completed by
/// another route. Uses the existing `BackendRecovered` event pattern.
pub(crate) fn record_recovery(backend_code: u64) {
    keyhog_profile::add_counter(CounterId::GpuRecoveries, 1);
    keyhog_profile::record_event(EventId::BackendRecovered, backend_code);
}

/// One batch rescored off-accelerator after a fault (residual CPU work).
pub(crate) fn record_residual_batch() {
    keyhog_profile::add_counter(CounterId::GpuResidualBatches, 1);
}

static DEVICE_RESIDENT_BYTES: AtomicU64 = AtomicU64::new(0);
static DEVICE_PEAK_RESIDENT_BYTES: AtomicU64 = AtomicU64::new(0);

/// Account one device allocation: cumulative alloc counters, current
/// residency gauge, and the per-session high-water gauge.
pub(crate) fn note_device_alloc(bytes: u64) {
    if bytes == 0 {
        return;
    }
    keyhog_profile::add_counter(CounterId::GpuAllocCalls, 1);
    keyhog_profile::add_counter(CounterId::GpuAllocBytes, bytes);
    let current = DEVICE_RESIDENT_BYTES.fetch_add(bytes, Ordering::Relaxed) + bytes;
    DEVICE_PEAK_RESIDENT_BYTES.fetch_max(current, Ordering::Relaxed);
    let peak = DEVICE_PEAK_RESIDENT_BYTES.load(Ordering::Relaxed);
    keyhog_profile::set_gauge(GaugeId::GpuResidentBytes, current);
    keyhog_profile::set_gauge(GaugeId::GpuPeakResidentBytes, peak);
}

/// Account one device release: cumulative free counter and the current
/// residency gauge. The high-water mark is retained.
pub(crate) fn note_device_free(bytes: u64) {
    if bytes == 0 {
        return;
    }
    keyhog_profile::add_counter(CounterId::GpuFreeBytes, bytes);
    let current = DEVICE_RESIDENT_BYTES
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            Some(value.saturating_sub(bytes))
        })
        .map_or(0, |previous| previous.saturating_sub(bytes));
    keyhog_profile::set_gauge(GaugeId::GpuResidentBytes, current);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(crate) enum GpuHostDataMovementSite {
    RegionPresenceScratchCoalesce,
    RegionPresenceScratchScrub,
}

#[allow(dead_code)]
impl GpuHostDataMovementSite {
    pub(crate) const ALL: &'static [Self] = &[
        Self::RegionPresenceScratchCoalesce,
        Self::RegionPresenceScratchScrub,
    ];

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::RegionPresenceScratchCoalesce => "region-presence-scratch-coalesce",
            Self::RegionPresenceScratchScrub => "region-presence-scratch-scrub",
        }
    }
}

static HOST_COPIED_BYTES: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
static HOST_SCRUBBED_BYTES: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

pub(crate) fn record_host_byte_copy(site: GpuHostDataMovementSite, bytes: usize) {
    if bytes == 0 {
        return;
    }
    let idx = match site {
        GpuHostDataMovementSite::RegionPresenceScratchCoalesce => 0,
        GpuHostDataMovementSite::RegionPresenceScratchScrub => 1,
    };
    HOST_COPIED_BYTES[idx].fetch_add(bytes as u64, Ordering::Relaxed);
}

pub(crate) fn record_host_byte_scrub(site: GpuHostDataMovementSite, bytes: usize) {
    if bytes == 0 {
        return;
    }
    let idx = match site {
        GpuHostDataMovementSite::RegionPresenceScratchCoalesce => 0,
        GpuHostDataMovementSite::RegionPresenceScratchScrub => 1,
    };
    HOST_SCRUBBED_BYTES[idx].fetch_add(bytes as u64, Ordering::Relaxed);
}

#[cfg(test)]
pub(crate) fn host_data_movement_snapshot() -> (u64, u64) {
    let copies: u64 = HOST_COPIED_BYTES
        .iter()
        .map(|a| a.load(Ordering::Relaxed))
        .sum();
    let scrubs: u64 = HOST_SCRUBBED_BYTES
        .iter()
        .map(|a| a.load(Ordering::Relaxed))
        .sum();
    (copies, scrubs)
}

#[cfg(test)]
pub(crate) fn reset_host_data_movement_counters() {
    for a in &HOST_COPIED_BYTES {
        a.store(0, Ordering::Relaxed);
    }
    for a in &HOST_SCRUBBED_BYTES {
        a.store(0, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[allow(dead_code)]
pub(crate) enum GpuApiKind {
    Cuda,
    Metal,
    Wgpu,
}

#[allow(dead_code)]
impl GpuApiKind {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Cuda => "cuda",
            Self::Metal => "metal",
            Self::Wgpu => "wgpu",
        }
    }
}

static INITIALIZED_GPU_APIS: [AtomicU64; 3] =
    [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

pub(crate) fn record_gpu_api_initialized(api: GpuApiKind) {
    let idx = match api {
        GpuApiKind::Cuda => 0,
        GpuApiKind::Metal => 1,
        GpuApiKind::Wgpu => 2,
    };
    INITIALIZED_GPU_APIS[idx].fetch_add(1, Ordering::Relaxed);
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn initialized_gpu_api_count() -> usize {
    INITIALIZED_GPU_APIS
        .iter()
        .filter(|a| a.load(Ordering::Relaxed) > 0)
        .count()
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn initialized_gpu_api_counts() -> (u64, u64, u64) {
    (
        INITIALIZED_GPU_APIS[0].load(Ordering::Relaxed),
        INITIALIZED_GPU_APIS[1].load(Ordering::Relaxed),
        INITIALIZED_GPU_APIS[2].load(Ordering::Relaxed),
    )
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn reset_initialized_gpu_api_counters() {
    for a in &INITIALIZED_GPU_APIS {
        a.store(0, Ordering::Relaxed);
    }
}
/// Current (resident, peak) device-byte tracker state; test diagnostics only.
#[cfg(test)]
pub(crate) fn resident_bytes_snapshot() -> (u64, u64) {
    (
        DEVICE_RESIDENT_BYTES.load(Ordering::Relaxed),
        DEVICE_PEAK_RESIDENT_BYTES.load(Ordering::Relaxed),
    )
}

#[cfg(all(test, feature = "gpu"))]
#[path = "../../tests/unit/gpu_evidence.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/unit/gpu_evidence_bounded_dedup.rs"]
mod bounded_dedup_tests;
