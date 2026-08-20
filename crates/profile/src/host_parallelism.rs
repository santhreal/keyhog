//! Single canonical owner of host parallelism width and provenance resolution (Row 110).

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::LazyLock;

pub const HOST_PARALLELISM_VERSION: u16 = 1;

/// Single decision fallback when platform query fails: 1 logical core.
/// Written decision: single core is the safest fail-closed parallelism default for memory and scheduling.
pub const FALLBACK_LOGICAL_CPUS: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParallelismProvenance {
    /// Read directly from platform OS runtime (std::thread::available_parallelism).
    Platform,
    /// Configured explicitly by caller or environment override.
    Configured,
    /// Read from cgroup or container quota restriction.
    Quota,
    /// Single written fallback decision when platform query fails.
    FallbackDefault,
}

impl ParallelismProvenance {
    /// All provenance variants for exhaustive iteration.
    pub const ALL: [Self; 4] = [
        Self::Platform,
        Self::Configured,
        Self::Quota,
        Self::FallbackDefault,
    ];
}

impl ParallelismProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::Configured => "configured",
            Self::Quota => "quota",
            Self::FallbackDefault => "fallback-default",
        }
    }
}

/// Resolved host parallelism width with explicit provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostParallelism {
    pub version: u16,
    pub logical_cpus: u32,
    pub provenance: ParallelismProvenance,
}

static OVERRIDE_PARALLELISM: AtomicU32 = AtomicU32::new(0);
static FORCED_FAILURE: AtomicU32 = AtomicU32::new(0);

static RESOLVED_PARALLELISM: LazyLock<HostParallelism> =
    LazyLock::new(resolve_host_parallelism_internal);

fn resolve_host_parallelism_internal() -> HostParallelism {
    if FORCED_FAILURE.load(Ordering::Relaxed) != 0 {
        return HostParallelism {
            version: HOST_PARALLELISM_VERSION,
            logical_cpus: FALLBACK_LOGICAL_CPUS,
            provenance: ParallelismProvenance::FallbackDefault,
        };
    }
    match std::thread::available_parallelism() {
        Ok(n) => HostParallelism {
            version: HOST_PARALLELISM_VERSION,
            logical_cpus: u32::try_from(n.get()).unwrap_or(u32::MAX),
            provenance: ParallelismProvenance::Platform,
        },
        Err(_) => HostParallelism {
            version: HOST_PARALLELISM_VERSION,
            logical_cpus: FALLBACK_LOGICAL_CPUS,
            provenance: ParallelismProvenance::FallbackDefault,
        },
    }
}

/// Resolve host parallelism with explicit provenance.
pub fn host_parallelism() -> HostParallelism {
    let override_val = OVERRIDE_PARALLELISM.load(Ordering::Relaxed);
    if override_val > 0 {
        return HostParallelism {
            version: HOST_PARALLELISM_VERSION,
            logical_cpus: override_val,
            provenance: ParallelismProvenance::Configured,
        };
    }
    if FORCED_FAILURE.load(Ordering::Relaxed) != 0 {
        return HostParallelism {
            version: HOST_PARALLELISM_VERSION,
            logical_cpus: FALLBACK_LOGICAL_CPUS,
            provenance: ParallelismProvenance::FallbackDefault,
        };
    }
    *RESOLVED_PARALLELISM
}

/// Convenience helper returning resolved logical cpu count as u32.
#[inline]
pub fn logical_cpus() -> u32 {
    host_parallelism().logical_cpus
}

/// Convenience helper returning resolved logical cpu count as usize.
#[inline]
pub fn logical_cpu_count() -> usize {
    host_parallelism().logical_cpus as usize
}

/// Set an explicit host parallelism override (e.g. from configuration or CLI).
pub fn set_host_parallelism_override(width: u32) {
    OVERRIDE_PARALLELISM.store(width, Ordering::SeqCst);
}

/// Clear any active host parallelism override.
pub fn clear_host_parallelism_override() {
    OVERRIDE_PARALLELISM.store(0, Ordering::SeqCst);
}

/// Force simulated probe failure path for testing failure resilience.
pub fn set_forced_probe_failure(forced: bool) {
    FORCED_FAILURE.store(if forced { 1 } else { 0 }, Ordering::SeqCst);
}
