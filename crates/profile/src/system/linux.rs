//! Linux memory, IO, pressure, and thermal evidence from procfs and sysfs.

use super::{NetworkProcessCountersV2, PressureThermalSampleV2, SystemIoSampleV2};
use crate::collector::{CollectorAvailability, CollectorCapability, CollectorId};
use crate::hardware::{HardwareFieldSourceV2, SourcedEvidenceV2};
use crate::schema_v2::EvidenceGap;
use crate::system::SYSTEM_EVIDENCE_V2_VERSION;

fn readable(path: &str) -> bool {
    std::fs::File::open(path).is_ok()
}

pub(super) fn system_io_capability() -> CollectorCapability {
    for path in ["/proc/self/io", "/proc/self/stat"] {
        if let Err(error) = std::fs::File::open(path) {
            let availability = if error.kind() == std::io::ErrorKind::PermissionDenied {
                CollectorAvailability::PermissionDenied
            } else {
                CollectorAvailability::Unavailable
            };
            return CollectorCapability::unavailable(
                CollectorId::SystemIo,
                availability,
                "Linux system IO evidence requires readable /proc/self/io and /proc/self/stat",
            );
        }
    }
    CollectorCapability::available(CollectorId::SystemIo)
}

pub(super) fn pressure_thermal_capability() -> CollectorCapability {
    if readable("/proc/pressure/cpu") {
        CollectorCapability::available(CollectorId::PressureThermal)
    } else {
        CollectorCapability::unavailable(
            CollectorId::PressureThermal,
            CollectorAvailability::Unavailable,
            "kernel pressure-stall information requires CONFIG_PSI with /proc/pressure mounted",
        )
    }
}

fn stat_field(index: usize) -> Option<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let command_end = stat.rfind(')')?;
    stat.get(command_end + 2..)?
        .split_whitespace()
        .nth(index)?
        .parse()
        .ok()
}

fn io_field(field: &str) -> Option<u64> {
    let io = std::fs::read_to_string("/proc/self/io").ok()?;
    io.lines().find_map(|line| {
        let value = line.strip_prefix(field)?.trim();
        value.parse().ok()
    })
}

fn sourced(value: Option<u64>, source: HardwareFieldSourceV2) -> SourcedEvidenceV2<u64> {
    match value {
        Some(value) => SourcedEvidenceV2::recorded(value, source),
        None => SourcedEvidenceV2::gapped(source, EvidenceGap::Unavailable),
    }
}

pub(super) fn sample_system_io() -> SystemIoSampleV2 {
    // Field indices after the command name: minflt is field 10 (index 7),
    // majflt is field 12 (index 9).
    SystemIoSampleV2 {
        version: SYSTEM_EVIDENCE_V2_VERSION,
        minor_faults: sourced(stat_field(7), HardwareFieldSourceV2::ProcSelfStat),
        major_faults: sourced(stat_field(9), HardwareFieldSourceV2::ProcSelfStat),
        read_bytes: sourced(io_field("read_bytes:"), HardwareFieldSourceV2::ProcSelfIo),
        write_bytes: sourced(io_field("write_bytes:"), HardwareFieldSourceV2::ProcSelfIo),
        read_syscalls: sourced(io_field("syscr:"), HardwareFieldSourceV2::ProcSelfIo),
        write_syscalls: sourced(io_field("syscw:"), HardwareFieldSourceV2::ProcSelfIo),
        cancelled_write_bytes: sourced(
            io_field("cancelled_write_bytes:"),
            HardwareFieldSourceV2::ProcSelfIo,
        ),
    }
}

fn psi_avg10_milli(path: &str, kind: &str) -> Option<u64> {
    let contents = std::fs::read_to_string(path).ok()?;
    for line in contents.lines() {
        let Some(rest) = line.strip_prefix(kind) else {
            continue;
        };
        for field in rest.split_whitespace() {
            if let Some(value) = field.strip_prefix("avg10=") {
                let parsed: f64 = value.parse().ok()?;
                return Some((parsed * 1_000.0) as u64);
            }
        }
    }
    None
}

fn psi_some_avg10(path: &str) -> SourcedEvidenceV2<u64> {
    sourced(
        psi_avg10_milli(path, "some"),
        HardwareFieldSourceV2::ProcPressure,
    )
}

fn thermal_max_millicelsius() -> Option<u64> {
    let entries = std::fs::read_dir("/sys/class/thermal").ok()?;
    let mut maximum: Option<u64> = None;
    for entry in entries.flatten() {
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with("thermal_zone")
        {
            continue;
        }
        let Ok(temp) = std::fs::read_to_string(entry.path().join("temp")) else {
            continue;
        };
        let Ok(value) = temp.trim().parse::<u64>() else {
            continue;
        };
        maximum = Some(maximum.map_or(value, |current: u64| current.max(value)));
    }
    maximum
}

fn thermal_throttle_events() -> Option<u64> {
    let entries = std::fs::read_dir("/sys/devices/system/cpu").ok()?;
    let mut total = 0_u64;
    let mut found = false;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("cpu") || !name[3..].chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let path = entry.path().join("thermal_throttle/core_throttle_count");
        let Ok(count) = std::fs::read_to_string(path) else {
            continue;
        };
        let Ok(count) = count.trim().parse::<u64>() else {
            continue;
        };
        total = total.saturating_add(count);
        found = true;
    }
    found.then_some(total)
}

pub(super) fn sample_pressure_thermal() -> PressureThermalSampleV2 {
    PressureThermalSampleV2 {
        version: SYSTEM_EVIDENCE_V2_VERSION,
        cpu_some_avg10_milli: psi_some_avg10("/proc/pressure/cpu"),
        cpu_full_avg10_milli: sourced(
            psi_avg10_milli("/proc/pressure/cpu", "full"),
            HardwareFieldSourceV2::ProcPressure,
        ),
        memory_some_avg10_milli: psi_some_avg10("/proc/pressure/memory"),
        io_some_avg10_milli: psi_some_avg10("/proc/pressure/io"),
        max_zone_millicelsius: sourced(
            thermal_max_millicelsius(),
            HardwareFieldSourceV2::SysfsThermal,
        ),
        throttle_events: match thermal_throttle_events() {
            Some(events) => {
                SourcedEvidenceV2::recorded(events, HardwareFieldSourceV2::SysfsThermal)
            }
            None => SourcedEvidenceV2::gapped(
                HardwareFieldSourceV2::SysfsThermal,
                EvidenceGap::Unsupported,
            ),
        },
    }
}

pub(super) fn network_process_counters() -> SourcedEvidenceV2<NetworkProcessCountersV2> {
    // Linux exposes network byte counters per interface, not per process;
    // process-level network evidence must come from caller-recorded counters.
    SourcedEvidenceV2::gapped(HardwareFieldSourceV2::ProcSelfIo, EvidenceGap::Unsupported)
}
