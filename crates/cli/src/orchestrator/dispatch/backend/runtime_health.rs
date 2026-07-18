//! Durable runtime faults kept separate from immutable calibration evidence.

use super::workload::{validate_workload_source_mixture, WorkloadKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const RUNTIME_HEALTH_VERSION: u32 = 1;
const RUNTIME_HEALTH_MAX_BYTES: u64 = 1024 * 1024;
const RUNTIME_HEALTH_MAX_FAULTS: usize = 4096;
const RUNTIME_HEALTH_MAX_REASON_BYTES: usize = 4096;

#[derive(Debug, Clone)]
pub(super) struct RuntimeHealthIdentity {
    path: PathBuf,
    config_digest: u64,
    host_digest: String,
}

impl RuntimeHealthIdentity {
    pub(super) fn new(cache_path: &Path, config_digest: u64, host_digest: String) -> Self {
        Self {
            path: runtime_health_path(cache_path),
            config_digest,
            host_digest,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct InspectedRuntimeFault {
    pub(super) config_digest: u64,
    pub(super) host_digest: String,
    pub(super) workload: WorkloadKey,
    pub(super) backend: String,
    pub(super) reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LoadedRuntimeFault {
    pub(super) backend: String,
    pub(super) reason: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeHealthArtifact {
    version: u32,
    faults: Vec<PersistedRuntimeFault>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedRuntimeFault {
    config_digest: u64,
    host_digest: String,
    workload: WorkloadKey,
    backend: String,
    reason: String,
}

pub(super) fn load_runtime_route_faults(
    identity: &RuntimeHealthIdentity,
) -> Result<HashMap<WorkloadKey, LoadedRuntimeFault>, String> {
    let artifact = read_artifact(&identity.path)?;
    let mut faults = HashMap::new();
    for fault in artifact.faults {
        if fault.config_digest == identity.config_digest
            && fault.host_digest == identity.host_digest
        {
            faults.insert(
                fault.workload,
                LoadedRuntimeFault {
                    backend: fault.backend,
                    reason: fault.reason,
                },
            );
        }
    }
    Ok(faults)
}

pub(super) fn inspect_runtime_route_faults(
    cache_path: &Path,
) -> Result<Vec<InspectedRuntimeFault>, String> {
    Ok(read_artifact(&runtime_health_path(cache_path))?
        .faults
        .into_iter()
        .map(|fault| InspectedRuntimeFault {
            config_digest: fault.config_digest,
            host_digest: fault.host_digest,
            workload: fault.workload,
            backend: fault.backend,
            reason: fault.reason,
        })
        .collect())
}

pub(super) fn persist_runtime_route_fault(
    identity: &RuntimeHealthIdentity,
    workload: &WorkloadKey,
    backend: &str,
    reason: &str,
) -> Result<(), String> {
    validate_backend_and_reason(backend, reason)?;
    if let Some(parent) = identity.path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            format!(
                "cannot create runtime route-health directory '{}': {error}",
                parent.display()
            )
        })?;
    }
    let _lock = keyhog_core::StateFileWriteLock::acquire(&identity.path)
        .map_err(|error| format!("cannot lock runtime route health: {error}"))?;
    let mut artifact = read_artifact(&identity.path)?;
    artifact.faults.retain(|fault| {
        fault.config_digest != identity.config_digest
            || fault.host_digest != identity.host_digest
            || fault.workload != *workload
    });
    if artifact.faults.len() >= RUNTIME_HEALTH_MAX_FAULTS {
        return Err(format!(
            "runtime route-health artifact already contains the maximum {RUNTIME_HEALTH_MAX_FAULTS} fault records; recalibrate or remove it before retrying"
        ));
    }
    artifact.faults.push(PersistedRuntimeFault {
        config_digest: identity.config_digest,
        host_digest: identity.host_digest.clone(),
        workload: workload.clone(),
        backend: backend.to_string(),
        reason: reason.to_string(),
    });
    write_artifact(&identity.path, artifact)
}

pub(super) fn clear_runtime_route_faults<'a>(
    identity: &RuntimeHealthIdentity,
    workloads: impl IntoIterator<Item = &'a WorkloadKey>,
) -> Result<(), String> {
    if !identity.path.exists() {
        return Ok(());
    }
    let workloads = workloads
        .into_iter()
        .cloned()
        .collect::<std::collections::HashSet<_>>();
    let _lock = keyhog_core::StateFileWriteLock::acquire(&identity.path)
        .map_err(|error| format!("cannot lock runtime route health: {error}"))?;
    let mut artifact = read_artifact(&identity.path)?;
    artifact.faults.retain(|fault| {
        fault.config_digest != identity.config_digest
            || fault.host_digest != identity.host_digest
            || !workloads.contains(&fault.workload)
    });
    write_artifact(&identity.path, artifact)
}

fn read_artifact(path: &Path) -> Result<RuntimeHealthArtifact, String> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RuntimeHealthArtifact {
                version: RUNTIME_HEALTH_VERSION,
                faults: Vec::new(),
            });
        }
        Err(error) => {
            return Err(format!(
                "cannot inspect runtime route-health artifact '{}': {error}",
                path.display()
            ));
        }
    };
    if !metadata.is_file() {
        return Err(format!(
            "runtime route-health path '{}' is not a regular file",
            path.display()
        ));
    }
    if metadata.len() > RUNTIME_HEALTH_MAX_BYTES {
        return Err(format!(
            "runtime route-health artifact '{}' is {} bytes, above the {} byte limit",
            path.display(),
            metadata.len(),
            RUNTIME_HEALTH_MAX_BYTES
        ));
    }
    let bytes = std::fs::read(path).map_err(|error| {
        format!(
            "cannot read runtime route-health artifact '{}': {error}",
            path.display()
        )
    })?;
    let artifact: RuntimeHealthArtifact = serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "runtime route-health artifact '{}' is invalid JSON: {error}",
            path.display()
        )
    })?;
    if artifact.version != RUNTIME_HEALTH_VERSION {
        return Err(format!(
            "runtime route-health artifact '{}' has version {}, expected {}",
            path.display(),
            artifact.version,
            RUNTIME_HEALTH_VERSION
        ));
    }
    if artifact.faults.len() > RUNTIME_HEALTH_MAX_FAULTS {
        return Err(format!(
            "runtime route-health artifact '{}' contains {} records, above the {} record limit",
            path.display(),
            artifact.faults.len(),
            RUNTIME_HEALTH_MAX_FAULTS
        ));
    }
    let mut identities = std::collections::HashSet::with_capacity(artifact.faults.len());
    for fault in &artifact.faults {
        validate_backend_and_reason(&fault.backend, &fault.reason)?;
        if fault.host_digest.len() != 64
            || !fault
                .host_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(
                "runtime route-health artifact contains an invalid host digest".to_string(),
            );
        }
        validate_workload_source_mixture(&fault.workload).map_err(|error| {
            format!("runtime route-health artifact contains an invalid workload identity: {error}")
        })?;
        if !identities.insert((
            fault.config_digest,
            fault.host_digest.clone(),
            fault.workload.clone(),
        )) {
            return Err(format!(
                "runtime route-health artifact '{}' contains a duplicate route identity",
                path.display()
            ));
        }
    }
    Ok(artifact)
}

fn validate_backend_and_reason(backend: &str, reason: &str) -> Result<(), String> {
    if keyhog_scanner::hw_probe::parse_backend_str(backend).is_none() {
        return Err(format!(
            "runtime route-health artifact names unknown backend {backend:?}"
        ));
    }
    if reason.is_empty()
        || reason.len() > RUNTIME_HEALTH_MAX_REASON_BYTES
        || reason.chars().any(char::is_control)
    {
        return Err(format!(
            "runtime route-health fault reason must contain 1..={RUNTIME_HEALTH_MAX_REASON_BYTES} printable bytes"
        ));
    }
    Ok(())
}

fn write_artifact(path: &Path, mut artifact: RuntimeHealthArtifact) -> Result<(), String> {
    artifact.version = RUNTIME_HEALTH_VERSION;
    artifact.faults.sort_by(|left, right| {
        left.config_digest
            .cmp(&right.config_digest)
            .then_with(|| left.host_digest.cmp(&right.host_digest))
            .then_with(|| left.workload.cmp(&right.workload))
    });
    let bytes = serde_json::to_vec_pretty(&artifact)
        .map_err(|error| format!("cannot serialize runtime route health: {error}"))?;
    if bytes.len() as u64 > RUNTIME_HEALTH_MAX_BYTES {
        return Err(format!(
            "runtime route-health artifact would be {} bytes, above the {} byte limit",
            bytes.len(),
            RUNTIME_HEALTH_MAX_BYTES
        ));
    }
    crate::atomic_file::write_bytes(path, &bytes).map_err(|error| {
        format!(
            "cannot persist runtime route-health artifact '{}': {error}",
            path.display()
        )
    })
}

fn runtime_health_path(cache_path: &Path) -> PathBuf {
    let mut path = cache_path.as_os_str().to_os_string();
    path.push(".runtime-health.json");
    PathBuf::from(path)
}
