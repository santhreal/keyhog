//! System evidence stubs: Disabled without `process-metrics`, Unsupported on
//! non-Linux hosts.

use super::{NetworkProcessCountersV2, PressureThermalSampleV2, SystemIoSampleV2};
use crate::collector::{CollectorAvailability, CollectorCapability, CollectorId};
use crate::hardware::{HardwareFieldSourceV2, SourcedEvidenceV2};
use crate::schema_v2::EvidenceGap;
use crate::system::SYSTEM_EVIDENCE_V2_VERSION;

fn availability() -> (CollectorAvailability, &'static str) {
    #[cfg(not(feature = "process-metrics"))]
    {
        (
            CollectorAvailability::Disabled,
            "enable the keyhog-profile process-metrics feature",
        )
    }
    #[cfg(feature = "process-metrics")]
    {
        (
            CollectorAvailability::Unsupported,
            "system IO evidence is implemented for Linux only",
        )
    }
}

fn reason() -> EvidenceGap {
    #[cfg(not(feature = "process-metrics"))]
    {
        EvidenceGap::CollectorDisabled
    }
    #[cfg(feature = "process-metrics")]
    {
        EvidenceGap::Unsupported
    }
}

pub(super) fn system_io_capability() -> CollectorCapability {
    let (availability, detail) = availability();
    CollectorCapability::unavailable(CollectorId::SystemIo, availability, detail)
}

pub(super) fn pressure_thermal_capability() -> CollectorCapability {
    let (availability, detail) = availability();
    CollectorCapability::unavailable(CollectorId::PressureThermal, availability, detail)
}

fn gapped(source: HardwareFieldSourceV2) -> SourcedEvidenceV2<u64> {
    SourcedEvidenceV2::gapped(source, reason())
}

pub(super) fn sample_system_io() -> SystemIoSampleV2 {
    SystemIoSampleV2 {
        version: SYSTEM_EVIDENCE_V2_VERSION,
        minor_faults: gapped(HardwareFieldSourceV2::ProcSelfStat),
        major_faults: gapped(HardwareFieldSourceV2::ProcSelfStat),
        read_bytes: gapped(HardwareFieldSourceV2::ProcSelfIo),
        write_bytes: gapped(HardwareFieldSourceV2::ProcSelfIo),
        read_syscalls: gapped(HardwareFieldSourceV2::ProcSelfIo),
        write_syscalls: gapped(HardwareFieldSourceV2::ProcSelfIo),
        cancelled_write_bytes: gapped(HardwareFieldSourceV2::ProcSelfIo),
    }
}

pub(super) fn sample_pressure_thermal() -> PressureThermalSampleV2 {
    PressureThermalSampleV2 {
        version: SYSTEM_EVIDENCE_V2_VERSION,
        cpu_some_avg10_milli: gapped(HardwareFieldSourceV2::ProcPressure),
        cpu_full_avg10_milli: gapped(HardwareFieldSourceV2::ProcPressure),
        memory_some_avg10_milli: gapped(HardwareFieldSourceV2::ProcPressure),
        io_some_avg10_milli: gapped(HardwareFieldSourceV2::ProcPressure),
        max_zone_millicelsius: gapped(HardwareFieldSourceV2::SysfsThermal),
        throttle_events: gapped(HardwareFieldSourceV2::SysfsThermal),
    }
}

pub(super) fn network_process_counters() -> SourcedEvidenceV2<NetworkProcessCountersV2> {
    SourcedEvidenceV2::gapped(HardwareFieldSourceV2::SystemCall, reason())
}
