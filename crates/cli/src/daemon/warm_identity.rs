use crate::daemon::protocol::{WarmBackendIdentity, WarmBackendStatus};
use anyhow::Result;
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::atomic::{AtomicU64, Ordering};

const REPAIR_COMMAND: &str = "keyhog daemon stop && keyhog daemon start";
static DAEMON_GENERATION_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) struct WarmBackendReadiness {
    daemon_generation: String,
    startup_identity: WarmBackendIdentity,
    required_backends: Vec<ScanBackend>,
}

impl WarmBackendReadiness {
    pub(crate) fn capture(
        scanner: &CompiledScanner,
        detector_rules_digest: &str,
        required_backends: Vec<ScanBackend>,
    ) -> Result<Self> {
        let mut required_backends = required_backends;
        required_backends.sort_by_key(|backend| backend.label());
        required_backends.dedup();
        Ok(Self {
            daemon_generation: new_daemon_generation(),
            startup_identity: current_identity(scanner, detector_rules_digest)?,
            required_backends,
        })
    }

    /// The generation string that anchors per-request profile identities.
    pub(crate) fn daemon_generation(&self) -> &str {
        &self.daemon_generation
    }

    pub(crate) fn status(&self, scanner: &CompiledScanner) -> WarmBackendStatus {
        let current_identity =
            current_identity(scanner, &self.startup_identity.detector_rules_digest);
        let initialized_backends = initialized_backends(scanner, &self.required_backends);
        evaluate_status(
            self.daemon_generation.clone(),
            self.startup_identity.clone(),
            current_identity,
            backend_labels(&self.required_backends),
            initialized_backends,
        )
    }
}

pub(crate) fn client_identity(detector_rules_digest: String) -> Result<WarmBackendIdentity> {
    Ok(WarmBackendIdentity {
        engine: crate::orchestrator::autoroute_engine_identity(),
        // The daemon owns the compiled scanner and is the only side that can
        // attest the acquired GPU artifact without compiling a second scanner.
        // `validate_for_client` requires the daemon's self-check to be ready;
        // it compares every client-owned identity below.
        gpu_artifact: None,
        binary_sha256: crate::orchestrator::autoroute_executable_identity()
            .map_err(|error| {
                anyhow::anyhow!("daemon client: identify running executable: {error}")
            })?
            .to_string(),
        detector_rules_digest,
        config_digest: crate::orchestrator::autoroute_default_config_identity(),
    })
}

pub(crate) fn client_control_identity(
    detector_rules_digest: String,
    daemon_binary_sha256: &str,
) -> WarmBackendIdentity {
    WarmBackendIdentity {
        engine: crate::orchestrator::autoroute_engine_identity(),
        gpu_artifact: None,
        // Status/stop never route a scan. Reuse the daemon value during the
        // control handshake so exact executable hashing does not consume the
        // five-second Health/Shutdown control budget. A successful status
        // request performs the full binary comparison after Health returns;
        // scan connections always use `client_identity` before routing.
        binary_sha256: daemon_binary_sha256.to_string(),
        detector_rules_digest,
        config_digest: crate::orchestrator::autoroute_default_config_identity(),
    }
}

pub(crate) fn validate_for_client(
    status: &WarmBackendStatus,
    expected: &WarmBackendIdentity,
) -> Vec<String> {
    let mut mismatches = Vec::new();
    if !status.ready {
        let reason = match status.reason.as_deref() {
            Some(reason) => reason,
            None => {
                mismatches.push(
                    "warm backend status is inconsistent: ready=false without an exact reason"
                        .to_string(),
                );
                ""
            }
        };
        if !reason.is_empty() {
            mismatches.push(format!("warm backend not ready: {reason}"));
        }
    }
    compare_field(
        &mut mismatches,
        "engine",
        &status.identity.engine,
        &expected.engine,
    );
    compare_field(
        &mut mismatches,
        "binary artifact",
        &status.identity.binary_sha256,
        &expected.binary_sha256,
    );
    compare_field(
        &mut mismatches,
        "detector rules",
        &status.identity.detector_rules_digest,
        &expected.detector_rules_digest,
    );
    compare_field(
        &mut mismatches,
        "resolved config",
        &status.identity.config_digest,
        &expected.config_digest,
    );
    mismatches
}

fn current_identity(
    scanner: &CompiledScanner,
    detector_rules_digest: &str,
) -> Result<WarmBackendIdentity> {
    Ok(WarmBackendIdentity {
        engine: crate::orchestrator::autoroute_engine_identity(),
        gpu_artifact: crate::orchestrator::autoroute_gpu_artifact_identity(scanner),
        binary_sha256: crate::orchestrator::autoroute_executable_identity()
            .map_err(|error| {
                anyhow::anyhow!("daemon server: identify running executable: {error}")
            })?
            .to_string(),
        detector_rules_digest: detector_rules_digest.to_string(),
        config_digest: crate::orchestrator::autoroute_default_config_identity(),
    })
}

fn initialized_backends(scanner: &CompiledScanner, required: &[ScanBackend]) -> Vec<String> {
    required
        .iter()
        .copied()
        .filter(|backend| match backend {
            ScanBackend::CpuFallback => true,
            ScanBackend::SimdCpu => scanner.simd_backend_initialized(),
            ScanBackend::GpuCuda | ScanBackend::GpuMetal | ScanBackend::GpuWgpu => scanner
                .gpu_backend_candidates()
                .iter()
                .any(|candidate| candidate.backend == *backend && candidate.is_acquired_eligible()),
            _ => false,
        })
        .map(|backend| backend.label().to_string())
        .collect()
}

fn backend_labels(backends: &[ScanBackend]) -> Vec<String> {
    backends
        .iter()
        .map(|backend| backend.label().to_string())
        .collect()
}

pub(crate) fn evaluate_status(
    daemon_generation: String,
    startup_identity: WarmBackendIdentity,
    current_identity: Result<WarmBackendIdentity>,
    required_backends: Vec<String>,
    initialized_backends: Vec<String>,
) -> WarmBackendStatus {
    let missing: Vec<_> = required_backends
        .iter()
        .filter(|backend| !initialized_backends.contains(backend))
        .cloned()
        .collect();
    let reason = if !missing.is_empty() {
        Some(format!(
            "warm backend initialization incomplete: missing [{}] from required [{}]",
            missing.join(","),
            required_backends.join(",")
        ))
    } else if let Some(reason) = incomplete_identity_reason(&startup_identity, &required_backends) {
        Some(reason)
    } else {
        match current_identity {
            Err(error) => Some(format!("warm backend identity unavailable: {error:#}")),
            Ok(current) => identity_drift_reason(&startup_identity, &current),
        }
    };
    let ready = reason.is_none();
    WarmBackendStatus {
        ready,
        daemon_generation,
        identity: startup_identity,
        required_backends,
        initialized_backends,
        reason,
        repair_command: (!ready).then(|| REPAIR_COMMAND.to_string()),
    }
}

fn incomplete_identity_reason(
    identity: &WarmBackendIdentity,
    required_backends: &[String],
) -> Option<String> {
    let mut missing = Vec::new();
    if identity.engine.trim().is_empty() {
        missing.push("engine");
    }
    if identity.binary_sha256.trim().is_empty() {
        missing.push("binary artifact");
    }
    if identity.detector_rules_digest.trim().is_empty() {
        missing.push("detector rules");
    }
    if identity.config_digest.trim().is_empty() {
        missing.push("resolved config");
    }
    let gpu_required = required_backends
        .iter()
        .any(|backend| backend.starts_with("gpu"));
    let gpu_identity_invalid = match identity.gpu_artifact.as_deref() {
        Some(artifact) => artifact.trim().is_empty(),
        None => gpu_required,
    };
    if gpu_identity_invalid {
        missing.push("GPU artifact");
    }
    (!missing.is_empty()).then(|| {
        format!(
            "warm backend identity incomplete: missing [{}]",
            missing.join(",")
        )
    })
}

pub(crate) fn identity_drift_reason(
    startup: &WarmBackendIdentity,
    current: &WarmBackendIdentity,
) -> Option<String> {
    let mut drift = Vec::new();
    collect_drift(&mut drift, "engine", &startup.engine, &current.engine);
    if startup.gpu_artifact != current.gpu_artifact {
        drift.push(format!(
            "GPU artifact expected={:?} current={:?}",
            startup.gpu_artifact, current.gpu_artifact
        ));
    }
    collect_drift(
        &mut drift,
        "binary artifact",
        &startup.binary_sha256,
        &current.binary_sha256,
    );
    collect_drift(
        &mut drift,
        "detector rules",
        &startup.detector_rules_digest,
        &current.detector_rules_digest,
    );
    collect_drift(
        &mut drift,
        "resolved config",
        &startup.config_digest,
        &current.config_digest,
    );
    (!drift.is_empty()).then(|| format!("warm backend identity drift: {}", drift.join("; ")))
}

fn collect_drift(out: &mut Vec<String>, label: &str, expected: &str, current: &str) {
    if expected != current {
        out.push(format!("{label} expected={expected} current={current}"));
    }
}

fn compare_field(out: &mut Vec<String>, label: &str, daemon: &str, client: &str) {
    if daemon != client {
        out.push(format!("{label} daemon={daemon}, client={client}"));
    }
}

fn new_daemon_generation() -> String {
    let sequence = DAEMON_GENERATION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let now = std::time::SystemTime::now();
    let (clock_side, started_ns) = match now.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => ("after", duration.as_nanos()),
        Err(error) => ("before", error.duration().as_nanos()),
    };
    format!(
        "{}-{clock_side}-{started_ns:032x}-{sequence:016x}",
        std::process::id()
    )
}
