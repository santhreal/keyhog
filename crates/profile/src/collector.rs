use serde::{Deserialize, Serialize};

pub const COLLECTOR_CAPABILITY_VERSION: u16 = 1;

const fn legacy_collector_capability_version() -> u16 {
    1
}

/// Stable identity of a profiling data collector.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum CollectorId {
    ProcessResources,
    HardwareCounters,
    SchedulerActivity,
    ThreadUtilization,
    CpuTopology,
    AllocationTracking,
    SystemIo,
    PressureThermal,
}

impl CollectorId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessResources => "process-resources",
            Self::HardwareCounters => "hardware-counters",
            Self::SchedulerActivity => "scheduler-activity",
            Self::ThreadUtilization => "thread-utilization",
            Self::CpuTopology => "cpu-topology",
            Self::AllocationTracking => "allocation-tracking",
            Self::SystemIo => "system-io",
            Self::PressureThermal => "pressure-thermal",
        }
    }
}

/// Whether a collector can produce measurements on this host.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CollectorAvailability {
    Available,
    Disabled,
    PermissionDenied,
    Unavailable,
    Unsupported,
}

impl CollectorAvailability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Disabled => "disabled",
            Self::PermissionDenied => "permission-denied",
            Self::Unavailable => "unavailable",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Host-specific availability report for one collector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CollectorCapability {
    #[serde(default = "legacy_collector_capability_version")]
    pub version: u16,
    pub collector: CollectorId,
    pub availability: CollectorAvailability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl CollectorCapability {
    pub(crate) fn available(collector: CollectorId) -> Self {
        Self {
            version: COLLECTOR_CAPABILITY_VERSION,
            collector,
            availability: CollectorAvailability::Available,
            detail: None,
        }
    }

    pub(crate) fn unavailable(
        collector: CollectorId,
        availability: CollectorAvailability,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            version: COLLECTOR_CAPABILITY_VERSION,
            collector,
            availability,
            detail: Some(detail.into()),
        }
    }
}

/// Portable lifecycle for a collector that snapshots one metric family.
pub trait SnapshotCollector: Send {
    type Snapshot;

    /// Report whether sampling is supported and usable on this host.
    fn capability(&self) -> CollectorCapability;

    /// Capture the current values without retaining source data or labels.
    fn sample(&mut self) -> Self::Snapshot;
}
