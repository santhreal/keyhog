//! Memory, IO, and system evidence: allocator totals with per-stage
//! ownership, page faults, process IO counters, RSS high water, pressure and
//! thermal state, network counters, and decode retention.
//!
//! Proc-backed collectors follow the [`SnapshotCollector`] +
//! [`CollectorCapability`] pattern like the hardware module. Fields the host
//! cannot produce carry an explicit [`Evidence`] gap with the attempted
//! [`HardwareFieldSourceV2`]; nothing is inferred silently.

use crate::allocation::{allocation_capability, allocation_snapshot, AllocationSnapshotV2};
use crate::collector::{CollectorCapability, SnapshotCollector};
use crate::hardware::{milli_ratio, HardwareFieldSourceV2, SourcedEvidenceV2};
use crate::schema::ResourceSnapshot;
use crate::schema_v2::{Evidence, EvidenceGap};
use serde::{Deserialize, Serialize};

#[cfg(all(feature = "process-metrics", target_os = "linux"))]
mod linux;
#[cfg(any(not(feature = "process-metrics"), not(target_os = "linux")))]
mod stubs;
#[cfg(all(feature = "process-metrics", target_os = "linux"))]
use linux as platform;
#[cfg(any(not(feature = "process-metrics"), not(target_os = "linux")))]
use stubs as platform;

pub const SYSTEM_EVIDENCE_V2_VERSION: u16 = 1;

const fn legacy_component_version() -> u16 {
    1
}

fn gap<T>(reason: EvidenceGap) -> Evidence<T> {
    Evidence::unavailable(reason)
}

/// Explicitly observed page-cache state for one source of IO work.
///
/// Callers record what they know from how the IO was performed (for example
/// `O_DIRECT`, an `fadvise` cold read, or a re-read of warm data). The
/// profiler never infers a state from latency; unknown stays unrecorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum IoCacheStateV2 {
    Cold = 1,
    Warm = 2,
    Direct = 3,
}

impl IoCacheStateV2 {
    /// Numeric value stored in the cache-state annotation.
    pub const fn as_value(self) -> u64 {
        self as u64
    }

    /// Decode one annotation value; unknown values are rejected, never coerced.
    pub fn from_value(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::Cold),
            2 => Some(Self::Warm),
            3 => Some(Self::Direct),
            _ => None,
        }
    }
}

/// Session-window allocation totals with live and peak levels at the end.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AllocationTotalsV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub allocations: u64,
    pub deallocations: u64,
    pub allocated_bytes: u64,
    pub deallocated_bytes: u64,
    /// Process live bytes at the end of the window.
    pub live_bytes: u64,
    /// Process peak live bytes observed during the window.
    pub peak_live_bytes: u64,
}

/// Per-stage allocation ownership; `metric_id` is `None` for the root slot
/// that owns allocations made outside any recorded span.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StageAllocationV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    #[serde(default)]
    pub metric_id: Option<crate::MetricId>,
    /// Allocations attributed during the session window.
    pub allocations: u64,
    /// Bytes attributed during the session window.
    pub allocated_bytes: u64,
    /// Live bytes owned by this stage at the end of the window.
    pub live_bytes: u64,
    /// Peak live bytes owned by this stage during the window.
    pub peak_live_bytes: u64,
}

/// Allocator evidence: exact counts when a [`crate::TrackingAllocator`] is
/// installed, an explicit capability gap otherwise.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AllocationEvidenceV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub totals: Evidence<AllocationTotalsV2>,
    #[serde(default)]
    pub stages: Vec<StageAllocationV2>,
}

/// Page-fault deltas across one run from proc stat.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FaultEvidenceV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub minor_faults: SourcedEvidenceV2<u64>,
    pub major_faults: SourcedEvidenceV2<u64>,
}

/// Process IO deltas across one run from `/proc/self/io`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IoEvidenceV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    /// Bytes actually fetched from storage (page cache misses).
    pub read_bytes: SourcedEvidenceV2<u64>,
    /// Bytes actually delivered to storage.
    pub write_bytes: SourcedEvidenceV2<u64>,
    pub read_syscalls: SourcedEvidenceV2<u64>,
    pub write_syscalls: SourcedEvidenceV2<u64>,
    /// Bytes whose writeout was cancelled by truncation or overwrite.
    pub cancelled_write_bytes: SourcedEvidenceV2<u64>,
}

/// Memory levels at the end of one run, including the kernel high water.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryEvidenceV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub resident_bytes: SourcedEvidenceV2<u64>,
    pub virtual_bytes: SourcedEvidenceV2<u64>,
    /// Kernel-maintained exact resident high water (VmHWM).
    pub resident_high_water_bytes: SourcedEvidenceV2<u64>,
    pub swap_bytes: SourcedEvidenceV2<u64>,
}

/// Kernel pressure-stall averages at the end of one run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PressureEvidenceV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    /// PSI cpu some avg10 in thousandths of a percent.
    pub cpu_some_avg10_milli: SourcedEvidenceV2<u64>,
    /// PSI cpu full avg10 in thousandths of a percent.
    pub cpu_full_avg10_milli: SourcedEvidenceV2<u64>,
    /// PSI memory some avg10 in thousandths of a percent.
    pub memory_some_avg10_milli: SourcedEvidenceV2<u64>,
    /// PSI io some avg10 in thousandths of a percent.
    pub io_some_avg10_milli: SourcedEvidenceV2<u64>,
}

/// Thermal state at the end of one run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ThermalEvidenceV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    /// Hottest readable thermal zone in thousandths of a celsius.
    pub max_zone_millicelsius: SourcedEvidenceV2<u64>,
    /// Cumulative core throttle events summed over CPUs that expose them.
    pub throttle_events: SourcedEvidenceV2<u64>,
}

/// Per-process network counters where the host exposes them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkProcessCountersV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub read_bytes: u64,
    pub written_bytes: u64,
}

/// Network evidence: process-level counters or an explicit gap, plus retry
/// activity aggregated from caller annotations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkEvidenceV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub process_counters: SourcedEvidenceV2<NetworkProcessCountersV2>,
    /// Retry annotations recorded by sources and verifiers during the run.
    pub retry_annotations: u64,
}

/// Decode expansion and retained-buffer evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DecodeRetentionEvidenceV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    /// Derived decoder bytes per input byte in thousandths.
    pub expansion_ratio_milli: Evidence<u64>,
    /// Retained buffer bytes reported by the caller at its last update.
    pub retained_bytes: Evidence<u64>,
    /// Retained buffer high water reported during the run.
    pub retained_peak_bytes: Evidence<u64>,
}

/// Complete memory, IO, and system evidence for one run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SystemRunEvidenceV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub allocation: AllocationEvidenceV2,
    pub faults: FaultEvidenceV2,
    pub io: IoEvidenceV2,
    pub memory: MemoryEvidenceV2,
    pub pressure: PressureEvidenceV2,
    pub thermal: ThermalEvidenceV2,
    pub network: NetworkEvidenceV2,
    pub decode: DecodeRetentionEvidenceV2,
}

/// One absolute faults-and-IO reading from procfs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SystemIoSampleV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub minor_faults: SourcedEvidenceV2<u64>,
    pub major_faults: SourcedEvidenceV2<u64>,
    pub read_bytes: SourcedEvidenceV2<u64>,
    pub write_bytes: SourcedEvidenceV2<u64>,
    pub read_syscalls: SourcedEvidenceV2<u64>,
    pub write_syscalls: SourcedEvidenceV2<u64>,
    pub cancelled_write_bytes: SourcedEvidenceV2<u64>,
}

/// One absolute pressure and thermal reading.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PressureThermalSampleV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub cpu_some_avg10_milli: SourcedEvidenceV2<u64>,
    pub cpu_full_avg10_milli: SourcedEvidenceV2<u64>,
    pub memory_some_avg10_milli: SourcedEvidenceV2<u64>,
    pub io_some_avg10_milli: SourcedEvidenceV2<u64>,
    pub max_zone_millicelsius: SourcedEvidenceV2<u64>,
    pub throttle_events: SourcedEvidenceV2<u64>,
}

/// Faults and process-IO collector backed by `/proc/self/stat` and
/// `/proc/self/io` on Linux.
pub struct SystemIoCollector {
    capability: CollectorCapability,
}

impl SystemIoCollector {
    pub fn new() -> Self {
        Self {
            capability: platform::system_io_capability(),
        }
    }
}

impl Default for SystemIoCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotCollector for SystemIoCollector {
    type Snapshot = SystemIoSampleV2;

    fn capability(&self) -> CollectorCapability {
        self.capability.clone()
    }

    fn sample(&mut self) -> Self::Snapshot {
        platform::sample_system_io()
    }
}

/// Pressure-stall and thermal collector backed by `/proc/pressure` and sysfs
/// thermal zones on Linux.
pub struct PressureThermalCollector {
    capability: CollectorCapability,
}

impl PressureThermalCollector {
    pub fn new() -> Self {
        Self {
            capability: platform::pressure_thermal_capability(),
        }
    }
}

impl Default for PressureThermalCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotCollector for PressureThermalCollector {
    type Snapshot = PressureThermalSampleV2;

    fn capability(&self) -> CollectorCapability {
        self.capability.clone()
    }

    fn sample(&mut self) -> Self::Snapshot {
        platform::sample_pressure_thermal()
    }
}

fn sourced_delta_u64(
    end: &SourcedEvidenceV2<u64>,
    start: &SourcedEvidenceV2<u64>,
) -> SourcedEvidenceV2<u64> {
    crate::hardware::sourced_delta(end, start)
}

/// Session-scoped system sampling state owned by `Session`.
pub(crate) struct SystemSession {
    io_collector: SystemIoCollector,
    pressure_collector: PressureThermalCollector,
    io_start: Option<SystemIoSampleV2>,
    allocation_start: Option<AllocationSnapshotV2>,
}

impl SystemSession {
    pub(crate) fn new() -> Self {
        let mut io_collector = SystemIoCollector::new();
        let io_available = matches!(
            io_collector.capability.availability,
            crate::collector::CollectorAvailability::Available
        );
        let io_start = io_available.then(|| io_collector.sample());
        let allocation_start = crate::allocation::allocation_tracking_installed()
            .then(crate::allocation::allocation_snapshot);
        if allocation_start.is_some() {
            crate::allocation::reset_allocation_peaks();
        }
        Self {
            io_collector,
            pressure_collector: PressureThermalCollector::new(),
            io_start,
            allocation_start,
        }
    }

    pub(crate) fn capabilities(&self) -> Vec<CollectorCapability> {
        vec![
            allocation_capability(),
            self.io_collector.capability(),
            self.pressure_collector.capability(),
        ]
    }

    /// Compute final evidence and record run totals as typed session metrics.
    pub(crate) fn finish_evidence(
        mut self,
        runtime: &crate::Runtime,
        finish_resources: &ResourceSnapshot,
        input_bytes: u64,
        derived_decoder_bytes: u64,
    ) -> Evidence<SystemRunEvidenceV2> {
        let io_end = self.io_collector.sample();
        let (faults, io) = match &self.io_start {
            Some(start) => (
                FaultEvidenceV2 {
                    version: SYSTEM_EVIDENCE_V2_VERSION,
                    minor_faults: sourced_delta_u64(&io_end.minor_faults, &start.minor_faults),
                    major_faults: sourced_delta_u64(&io_end.major_faults, &start.major_faults),
                },
                IoEvidenceV2 {
                    version: SYSTEM_EVIDENCE_V2_VERSION,
                    read_bytes: sourced_delta_u64(&io_end.read_bytes, &start.read_bytes),
                    write_bytes: sourced_delta_u64(&io_end.write_bytes, &start.write_bytes),
                    read_syscalls: sourced_delta_u64(&io_end.read_syscalls, &start.read_syscalls),
                    write_syscalls: sourced_delta_u64(
                        &io_end.write_syscalls,
                        &start.write_syscalls,
                    ),
                    cancelled_write_bytes: sourced_delta_u64(
                        &io_end.cancelled_write_bytes,
                        &start.cancelled_write_bytes,
                    ),
                },
            ),
            None => {
                // No start sample means we cannot form a session delta. Publishing
                // absolute /proc lifetime counters here used to fail open and
                // misattribute process-lifetime IO as run IO.
                let reason = match io_end.minor_faults.value {
                    Evidence::Unavailable { reason } => reason,
                    Evidence::Recorded { .. } => EvidenceGap::Unavailable,
                };
                let io_reason = match io_end.read_bytes.value {
                    Evidence::Unavailable { reason } => reason,
                    Evidence::Recorded { .. } => EvidenceGap::Unavailable,
                };
                (
                    FaultEvidenceV2 {
                        version: SYSTEM_EVIDENCE_V2_VERSION,
                        minor_faults: SourcedEvidenceV2::gapped(
                            HardwareFieldSourceV2::ProcSelfStat,
                            reason,
                        ),
                        major_faults: SourcedEvidenceV2::gapped(
                            HardwareFieldSourceV2::ProcSelfStat,
                            reason,
                        ),
                    },
                    IoEvidenceV2 {
                        version: SYSTEM_EVIDENCE_V2_VERSION,
                        read_bytes: SourcedEvidenceV2::gapped(
                            HardwareFieldSourceV2::ProcSelfIo,
                            io_reason,
                        ),
                        write_bytes: SourcedEvidenceV2::gapped(
                            HardwareFieldSourceV2::ProcSelfIo,
                            io_reason,
                        ),
                        read_syscalls: SourcedEvidenceV2::gapped(
                            HardwareFieldSourceV2::ProcSelfIo,
                            io_reason,
                        ),
                        write_syscalls: SourcedEvidenceV2::gapped(
                            HardwareFieldSourceV2::ProcSelfIo,
                            io_reason,
                        ),
                        cancelled_write_bytes: SourcedEvidenceV2::gapped(
                            HardwareFieldSourceV2::ProcSelfIo,
                            io_reason,
                        ),
                    },
                )
            }
        };
        let pressure = self.pressure_collector.sample();
        let allocation = self.allocation_evidence();
        let memory = memory_evidence(finish_resources);
        let retry_annotations = runtime.retry_annotation_count();
        let network = NetworkEvidenceV2 {
            version: SYSTEM_EVIDENCE_V2_VERSION,
            process_counters: platform::network_process_counters(),
            retry_annotations,
        };
        let decode = DecodeRetentionEvidenceV2 {
            version: SYSTEM_EVIDENCE_V2_VERSION,
            expansion_ratio_milli: milli_ratio(derived_decoder_bytes, input_bytes)
                .map_or_else(|| gap(EvidenceGap::Unavailable), Evidence::recorded),
            retained_bytes: runtime
                .session_gauge(crate::GaugeId::RetainedBufferBytes)
                .map_or_else(|| gap(EvidenceGap::Unavailable), Evidence::recorded),
            retained_peak_bytes: runtime
                .session_gauge(crate::GaugeId::RetainedBufferPeakBytes)
                .map_or_else(|| gap(EvidenceGap::Unavailable), Evidence::recorded),
        };
        record_system_metrics(
            runtime,
            &faults,
            &io,
            &memory,
            &allocation,
            retry_annotations,
        );
        Evidence::recorded(SystemRunEvidenceV2 {
            version: SYSTEM_EVIDENCE_V2_VERSION,
            allocation,
            faults,
            io,
            memory,
            pressure: PressureEvidenceV2 {
                version: SYSTEM_EVIDENCE_V2_VERSION,
                cpu_some_avg10_milli: pressure.cpu_some_avg10_milli.clone(),
                cpu_full_avg10_milli: pressure.cpu_full_avg10_milli.clone(),
                memory_some_avg10_milli: pressure.memory_some_avg10_milli.clone(),
                io_some_avg10_milli: pressure.io_some_avg10_milli.clone(),
            },
            thermal: ThermalEvidenceV2 {
                version: SYSTEM_EVIDENCE_V2_VERSION,
                max_zone_millicelsius: pressure.max_zone_millicelsius.clone(),
                throttle_events: pressure.throttle_events.clone(),
            },
            network,
            decode,
        })
    }

    fn allocation_evidence(&self) -> AllocationEvidenceV2 {
        let Some(start) = &self.allocation_start else {
            let reason = if cfg!(feature = "allocation-tracking") {
                EvidenceGap::Unavailable
            } else {
                EvidenceGap::CollectorDisabled
            };
            return AllocationEvidenceV2 {
                version: SYSTEM_EVIDENCE_V2_VERSION,
                totals: gap(reason),
                stages: Vec::new(),
            };
        };
        let end = allocation_snapshot();
        let totals = AllocationTotalsV2 {
            version: SYSTEM_EVIDENCE_V2_VERSION,
            allocations: end.allocations.saturating_sub(start.allocations),
            deallocations: end.deallocations.saturating_sub(start.deallocations),
            allocated_bytes: end.allocated_bytes.saturating_sub(start.allocated_bytes),
            deallocated_bytes: end
                .deallocated_bytes
                .saturating_sub(start.deallocated_bytes),
            live_bytes: end.live_bytes,
            peak_live_bytes: end.peak_live_bytes,
        };
        let stages = crate::Stage::ALL
            .into_iter()
            .map(|stage| {
                let start_slot = start.slot(stage);
                let end_slot = end.slot(stage);
                StageAllocationV2 {
                    version: SYSTEM_EVIDENCE_V2_VERSION,
                    metric_id: Some(stage.metric_id()),
                    allocations: end_slot.allocations.saturating_sub(start_slot.allocations),
                    allocated_bytes: end_slot
                        .allocated_bytes
                        .saturating_sub(start_slot.allocated_bytes),
                    live_bytes: end_slot.live_bytes,
                    peak_live_bytes: end_slot.peak_live_bytes,
                }
            })
            .chain(std::iter::once(StageAllocationV2 {
                version: SYSTEM_EVIDENCE_V2_VERSION,
                metric_id: None,
                allocations: end
                    .root()
                    .allocations
                    .saturating_sub(start.root().allocations),
                allocated_bytes: end
                    .root()
                    .allocated_bytes
                    .saturating_sub(start.root().allocated_bytes),
                live_bytes: end.root().live_bytes,
                peak_live_bytes: end.root().peak_live_bytes,
            }))
            .collect();
        AllocationEvidenceV2 {
            version: SYSTEM_EVIDENCE_V2_VERSION,
            totals: Evidence::recorded(totals),
            stages,
        }
    }
}

fn memory_evidence(finish: &ResourceSnapshot) -> MemoryEvidenceV2 {
    let sourced = |value: Option<u64>| match value {
        Some(value) => SourcedEvidenceV2::recorded(value, HardwareFieldSourceV2::ProcSelfStatus),
        None => SourcedEvidenceV2::gapped(
            HardwareFieldSourceV2::ProcSelfStatus,
            EvidenceGap::Unavailable,
        ),
    };
    MemoryEvidenceV2 {
        version: SYSTEM_EVIDENCE_V2_VERSION,
        resident_bytes: sourced(finish.resident_bytes),
        virtual_bytes: sourced(finish.virtual_bytes),
        resident_high_water_bytes: sourced(finish.resident_high_water_bytes),
        swap_bytes: sourced(finish.swap_bytes),
    }
}

fn record_system_metrics(
    runtime: &crate::Runtime,
    faults: &FaultEvidenceV2,
    io: &IoEvidenceV2,
    memory: &MemoryEvidenceV2,
    allocation: &AllocationEvidenceV2,
    retry_annotations: u64,
) {
    let counters: [(&SourcedEvidenceV2<u64>, crate::CounterId); 7] = [
        (&faults.minor_faults, crate::CounterId::MinorFaults),
        (&faults.major_faults, crate::CounterId::MajorFaults),
        (&io.read_bytes, crate::CounterId::IoReadBytes),
        (&io.write_bytes, crate::CounterId::IoWriteBytes),
        (&io.read_syscalls, crate::CounterId::IoReadSyscalls),
        (&io.write_syscalls, crate::CounterId::IoWriteSyscalls),
        (
            &io.cancelled_write_bytes,
            crate::CounterId::IoCancelledWriteBytes,
        ),
    ];
    for (field, counter) in counters {
        if let Evidence::Recorded { value } = field.value {
            if value > 0 {
                runtime.add_counter(counter, value);
            }
        }
    }
    if retry_annotations > 0 {
        runtime.add_counter(crate::CounterId::NetworkRetries, retry_annotations);
    }
    if let Evidence::Recorded { value: hwm } = memory.resident_high_water_bytes.value {
        runtime.set_gauge(crate::GaugeId::ResidentHighWaterBytes, hwm);
    }
    if let Evidence::Recorded { value: totals } = &allocation.totals {
        if totals.allocations > 0 {
            runtime.add_counter(crate::CounterId::AllocationCount, totals.allocations);
        }
        if totals.deallocations > 0 {
            runtime.add_counter(crate::CounterId::DeallocationCount, totals.deallocations);
        }
        if totals.allocated_bytes > 0 {
            runtime.add_counter(crate::CounterId::AllocationBytes, totals.allocated_bytes);
        }
        if totals.deallocated_bytes > 0 {
            runtime.add_counter(
                crate::CounterId::DeallocationBytes,
                totals.deallocated_bytes,
            );
        }
        runtime.set_gauge(crate::GaugeId::AllocationLiveBytes, totals.live_bytes);
        runtime.set_gauge(
            crate::GaugeId::AllocationPeakLiveBytes,
            totals.peak_live_bytes,
        );
    }
}
