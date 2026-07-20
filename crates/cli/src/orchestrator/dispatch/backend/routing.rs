//! Route selection values, recovery plans, and operator-facing routing errors.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

use keyhog_core::Chunk;
use keyhog_scanner::hw_probe::ScanBackend;
use keyhog_scanner::{CompiledScanner, Phase1AdmissionPlan};

use super::evidence::{AutorouteDecision, MeasuredRoute};
use super::store::autoroute_cache_file_presence;
use super::workload::{
    differing_workload_dimensions, render_workload_key, WorkloadClassificationError, WorkloadKey,
};

#[derive(Debug, Clone)]
pub(super) struct RuntimeRouteFault {
    pub(super) backend: ScanBackend,
    pub(super) reason: String,
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeRouteIdentity {
    pub(super) key: WorkloadKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AutorouteRuntimeClass {
    OneShot,
    Persistent,
}

#[derive(Debug)]
pub(crate) struct BackendSelection {
    pub(crate) backend: ScanBackend,
    pub(crate) phase1_plan: Option<Phase1AdmissionPlan>,
    pub(crate) execution_route: keyhog_scanner::ScanExecutionRoute,
    pub(crate) recovery_plan: Option<BackendRecoveryPlan>,
    pub(crate) runtime_route: Option<RuntimeRouteIdentity>,
    pub(crate) autoroute_recovery: Option<AutorouteStateRecovery>,
}

#[derive(Debug)]
pub(crate) struct AutorouteStateRecovery {
    pub(crate) reason: String,
    pub(crate) announce: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct BackendRecoveryPlan {
    pub(crate) backend: ScanBackend,
    pub(crate) execution_route: keyhog_scanner::ScanExecutionRoute,
}

impl AutorouteRuntimeClass {
    fn label(self) -> &'static str {
        match self {
            Self::OneShot => "one-shot",
            Self::Persistent => "persistent-runtime",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AutorouteRoutingError {
    message: String,
}

impl AutorouteRoutingError {
    fn missing_decision(
        key: WorkloadKey,
        decisions: &HashMap<WorkloadKey, AutorouteDecision>,
        runtime_class: AutorouteRuntimeClass,
        cache_path: &Option<PathBuf>,
        cache_load_error: &Option<String>,
    ) -> Self {
        let cache_state = autoroute_cache_state(cache_path, cache_load_error);
        let coverage = if decisions.contains_key(&key) {
            "the exact workload bucket exists, but it lacks the required runtime-class route evidence"
                .to_string()
        } else {
            let nearest = decisions
                .keys()
                .map(|candidate| (differing_workload_dimensions(&key, candidate), candidate))
                .min_by(
                    |(left_dimensions, left_key), (right_dimensions, right_key)| {
                        left_dimensions
                            .len()
                            .cmp(&right_dimensions.len())
                            .then_with(|| left_key.cmp(right_key))
                    },
                )
                .map(|(dimensions, _)| dimensions.join(", "));
            match nearest {
                Some(dimensions) => format!(
                    "nearest calibrated bucket differs in: {dimensions}; this is not reusable evidence"
                ),
                None => "the cache has no calibrated workload buckets".to_string(),
            }
        };
        Self {
            message: format!(
                "autoroute calibration required: this workload has no persisted \
                 fastest-correct backend decision.\n  \
                 fix: rerun this same scan once with `--autoroute-calibrate --autoroute-gpu` \
                 to measure its actual source/config/workload class, or run \
                 `keyhog calibrate-autoroute` for the core ladder; installers can use `install.sh --calibrate` or `install.ps1 -Calibrate`.\n  \
                 workload bucket: [{}], runtime={}\n  \
                 coverage: {coverage}.\n  \
                 cache: {cache_state}.\n  \
                 Decisions are scoped to this exact binary, host, detector corpus, resolved \
                 scan config, and source class. Normal auto scans never benchmark or guess: \
                 they report invalid autoroute state and complete through scalar correctness \
                 recovery, which is not an autoroute decision. Pass an explicit \
                 `--backend <{}>` for a one-off diagnostic scan.",
                render_workload_key(&key),
                runtime_class.label(),
                backend_override_hint(),
            ),
        }
    }

    pub(super) fn calibration_not_persisted(error: impl fmt::Display) -> Self {
        Self {
            message: format!(
                "autoroute calibration did not persist a routing decision: {error}. \
                 Calibration records must be durable before auto routing can be trusted. \
                 Fix the cache path/permissions and rerun `install.sh --calibrate` or \
                 `install.ps1 -Calibrate`."
            ),
        }
    }

    pub(super) fn measurement_observer_unavailable() -> Self {
        Self {
            message: "autoroute calibration persisted its routing decision, but the current-run measured-route observer lock was poisoned; the command cannot report a truthful measured class count. Rerun `keyhog calibrate-autoroute`.".to_string(),
        }
    }

    pub(super) fn insufficient_calibration_sample(sample_chunks: usize, sample_bytes: u64) -> Self {
        Self {
            message: format!(
                "autoroute calibration sample is insufficient: sample_chunks={sample_chunks}, \
                 sample_bytes={sample_bytes}. Autoroute cannot prove fastest-correct routing \
                 from an empty or zero-byte calibration sample. Fix the calibration workload so \
                 it produces non-empty scan bytes, then rerun `install.sh --calibrate` or \
                 `install.ps1 -Calibrate`."
            ),
        }
    }

    pub(super) fn host_identity_unavailable(error: impl fmt::Display) -> Self {
        Self {
            message: format!(
                "autoroute host identity unavailable: {error}. Autoroute calibration must be \
                 tied to an exact host profile before it can prove fastest-correct routing. \
                 Fix host hardware probing and rerun `install.sh --calibrate` or \
                 `install.ps1 -Calibrate`; or pass an explicit `--backend <{}>` \
                 for diagnostics.",
                backend_override_hint()
            ),
        }
    }

    pub(super) fn incomplete_workload_evidence(error: WorkloadClassificationError) -> Self {
        Self {
            message: format!(
                "autoroute workload evidence incomplete: {error}. Autoroute requires exact \
                 source-class evidence before it can trust a persisted fastest-correct backend \
                 decision. Fix the source implementation so it populates ChunkMetadata.source_type, \
                 rerun `install.sh --calibrate` or `install.ps1 -Calibrate`, or pass an explicit \
                 `--backend <{}>` for diagnostics.",
                backend_override_hint()
            ),
        }
    }

    pub(super) fn inconsistent_reference_backend(trial: usize) -> Self {
        Self {
            message: format!(
                "autoroute calibration reference backend produced inconsistent findings on trial \
                 {trial}. Autoroute cannot prove fastest-correct routing when the scalar reference \
                 is unstable, so no backend decision was persisted. Fix scanner nondeterminism or \
                 run an explicit `--backend <{}>` diagnostic scan.",
                backend_override_hint()
            ),
        }
    }

    pub(super) fn candidate_backend_rejected(
        backend: ScanBackend,
        reason: impl fmt::Display,
    ) -> Self {
        Self {
            message: format!(
                "autoroute calibration rejected eligible backend {}: {reason}. Autoroute cannot \
                 prove fastest-correct routing while skipping an eligible backend candidate, so \
                 no routing decision was persisted. Fix the backend correctness/degradation \
                 failure and rerun `install.sh --calibrate` or `install.ps1 -Calibrate`; or pass \
                 an explicit `--backend <{}>` diagnostic override.",
                backend.label(),
                backend_override_hint()
            ),
        }
    }

    pub(in crate::orchestrator::dispatch) fn selected_backend_dispatch_failed(
        backend: ScanBackend,
        error: impl fmt::Display,
    ) -> Self {
        Self {
            message: format!(
                "selected backend {} failed during dispatch ({error}); an explicit backend request or calibration candidate cannot be substituted. Repair the backend, rerun calibration, or select another diagnostic backend",
                backend.label(),
            ),
        }
    }

    pub(in crate::orchestrator::dispatch) fn unsupported_backend(backend: ScanBackend) -> Self {
        Self {
            message: format!(
                "autoroute selected unsupported scan backend {backend:?}. This binary cannot prove \
                 fastest-correct routing for a backend variant it does not implement in the \
                 coalesced scanner worker. Recalibrate with a matching keyhog/scanner build or pass \
                 an explicit supported `--backend <{}>` diagnostic override.",
                backend_override_hint()
            ),
        }
    }

    pub(super) fn runtime_route_unhealthy(
        key: &WorkloadKey,
        runtime_class: AutorouteRuntimeClass,
        fault: &RuntimeRouteFault,
    ) -> Self {
        Self {
            message: format!(
                "autoroute decision is quarantined after backend {} faulted and the prior request completed through visible recovery.\n  fix: repair the backend and rerun `keyhog calibrate-autoroute`; this process will not silently substitute another route.\n  workload bucket: [{}], runtime={}\n  fault: {}",
                fault.backend.label(),
                render_workload_key(key),
                runtime_class.label(),
                fault.reason,
            ),
        }
    }

    pub(super) fn recovery_receipt_backend_mismatch(
        failed_backend: ScanBackend,
        selected_backend: ScanBackend,
    ) -> Self {
        Self {
            message: format!(
                "autoroute recovery receipt names failed backend {}, but the selected route was {}; refusing to quarantine the wrong route identity",
                failed_backend.label(),
                selected_backend.label(),
            ),
        }
    }
}

impl fmt::Display for AutorouteRoutingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AutorouteRoutingError {}

pub(super) fn direct_backend_selection(
    scanner: &CompiledScanner,
    explicit: Option<ScanBackend>,
    batch: &[Chunk],
) -> Option<BackendSelection> {
    let backend = explicit.or_else(sole_compiled_backend)?;
    Some(BackendSelection {
        backend,
        phase1_plan: (!backend.is_gpu()).then(|| scanner.phase1_admission_plan(batch)),
        execution_route: scanner.execution_route_for_backend(backend),
        recovery_plan: None,
        runtime_route: None,
        autoroute_recovery: None,
    })
}

pub(super) fn autoroute_required() -> bool {
    keyhog_scanner::hw_probe::multiple_backends_compiled()
}

pub(super) fn autoroute_state_recovery_selection(
    scanner: &CompiledScanner,
    phase1_plan: Phase1AdmissionPlan,
    reason: String,
    announce: bool,
) -> BackendSelection {
    let backend = ScanBackend::CpuFallback;
    BackendSelection {
        backend,
        phase1_plan: Some(phase1_plan),
        execution_route: scanner.execution_route_for_backend(backend),
        recovery_plan: None,
        runtime_route: None,
        autoroute_recovery: Some(AutorouteStateRecovery { reason, announce }),
    }
}

pub(super) fn resolve_persisted_route(
    decisions: &HashMap<WorkloadKey, AutorouteDecision>,
    key: WorkloadKey,
    runtime_class: AutorouteRuntimeClass,
    cache_path: &Option<PathBuf>,
    cache_load_error: &Option<String>,
) -> Result<MeasuredRoute, AutorouteRoutingError> {
    let route = decisions
        .get(&key)
        .and_then(|decision| match runtime_class {
            AutorouteRuntimeClass::OneShot => decision.measured_route(),
            AutorouteRuntimeClass::Persistent => decision.resolved_persistent_route(),
        });
    route.ok_or_else(|| {
        AutorouteRoutingError::missing_decision(
            key,
            decisions,
            runtime_class,
            cache_path,
            cache_load_error,
        )
    })
}

pub(super) fn automatic_recovery_plan(
    decision: Option<&AutorouteDecision>,
    selected_backend: ScanBackend,
    runtime_class: AutorouteRuntimeClass,
) -> Result<Option<BackendRecoveryPlan>, AutorouteRoutingError> {
    if selected_backend == ScanBackend::CpuFallback {
        return Ok(None);
    }
    let persistent_runtime = runtime_class == AutorouteRuntimeClass::Persistent;
    let route = decision
        .and_then(|decision| {
            decision.resolved_recovery_route(selected_backend, persistent_runtime)
        })
        .ok_or_else(|| {
            AutorouteRoutingError::calibration_not_persisted(format!(
                "autoroute selected accelerated backend {}, but its workload evidence does not resolve one confidence-supported remaining measured-correct recovery peer across every calibration point; rerun `keyhog calibrate-autoroute` after repairing or splitting this workload class",
                selected_backend.label()
            ))
        })?;
    Ok(Some(BackendRecoveryPlan {
        backend: route.backend,
        execution_route: route.execution_route(),
    }))
}

fn backend_override_hint() -> String {
    keyhog_scanner::hw_probe::BACKEND_OVERRIDE_VALUES
        .into_iter()
        .filter(|value| *value != "auto")
        .collect::<Vec<_>>()
        .join("|")
}

pub(super) fn sole_compiled_backend() -> Option<ScanBackend> {
    (!autoroute_required()).then_some(ScanBackend::CpuFallback)
}

fn autoroute_cache_state(
    cache_path: &Option<PathBuf>,
    cache_load_error: &Option<String>,
) -> String {
    if let Some(error) = cache_load_error {
        return format!("The autoroute cache or host identity was rejected: {error}");
    }
    match cache_path {
        Some(path) => match autoroute_cache_file_presence(path) {
            Ok(true) => format!(
                "The autoroute cache at {} is valid for this binary/host/config but does not cover \
                 this workload bucket",
                path.display()
            ),
            Ok(false) => format!("No autoroute cache file exists at {}", path.display()),
            Err(error) => format!(
                "The autoroute cache path {} cannot be inspected: {error}. Fix the path permissions or parent storage and retry",
                path.display()
            ),
        },
        None => "--autoroute-cache off / [system].autoroute_cache = \"off\" disables the autoroute cache".to_string(),
    }
}
