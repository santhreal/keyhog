//! Route selection values, recovery plans, and operator-facing routing errors.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

use keyhog_core::Chunk;
use keyhog_scanner::hw_probe::ScanBackend;
use keyhog_scanner::{CompiledScanner, Phase1AdmissionPlan};

use super::evidence::{reconcile_route_across_decisions, AutorouteDecision, MeasuredRoute};
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

impl RuntimeRouteIdentity {
    pub(crate) fn workload_key_digest(&self) -> String {
        keyhog_core::hex_encode(&super::workload::workload_evidence_digest(&self.key))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AutorouteRuntimeClass {
    OneShot,
    Persistent,
}

#[cfg(feature = "gpu")]
#[derive(Clone, Debug)]
pub(crate) struct OrderedGpuSelection {
    pub(crate) route: std::sync::Arc<keyhog_scanner::gpu::device_set::OrderedGpuDeviceRoute>,
    pub(crate) acquired: std::sync::Arc<keyhog_scanner::gpu::AcquiredGpuDeviceSet>,
}

#[derive(Debug)]
pub(crate) struct BackendSelection {
    pub(crate) backend: ScanBackend,
    pub(crate) phase1_plan: Option<Phase1AdmissionPlan>,
    pub(crate) execution_route: keyhog_scanner::ScanExecutionRoute,
    pub(crate) recovery_plan: Option<BackendRecoveryPlan>,
    pub(crate) runtime_route: Option<RuntimeRouteIdentity>,
    #[cfg(feature = "gpu")]
    pub(crate) ordered_gpu: Option<std::sync::Arc<OrderedGpuSelection>>,
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

/// Classify the operational consequence of a routing failure.
///
/// Invalid autoroute state never selects a substitute backend. The caller
/// records the affected batch as unscanned and returns non-success status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AutorouteRoutingErrorKind {
    /// No authenticated route exists for this workload and runtime class. The
    /// affected batch was not scanned.
    RoutingUnavailable,
    /// The batch never reached a scanner: no worker could take it. This is a
    /// COVERAGE fact, not a trust fact, and it is enumerable (we know exactly
    /// which batch). Measured, not assumed: `scan_nonempty_batch` appends to
    /// its finding vector only AFTER the fallible dispatch, so a failure here
    /// contributes exactly zero findings and cannot leave us holding partial
    /// output from a peer that died mid-flight. It therefore keeps the other
    /// batches' findings on a production scan and records a `BatchNotRouted`
    /// gap, and stays fatal under `--autoroute-calibrate`, where the artifact
    /// is a decision and an unscanned batch voids the measurement.
    BatchNotScanned,
    /// The scan's own output is in doubt: two backends disagreed about what the
    /// matches ARE, or the scalar reference was itself unstable. We do not know
    /// which finding set we are holding, so there is nothing safe to report.
    /// Stays fatal everywhere.
    FindingsUntrustworthy,
}

#[derive(Debug, Clone)]
pub(crate) struct AutorouteRoutingError {
    message: String,
    kind: AutorouteRoutingErrorKind,
}

impl AutorouteRoutingError {
    /// Whether this failure means the findings cannot be trusted.
    pub(crate) fn kind(&self) -> AutorouteRoutingErrorKind {
        self.kind
    }

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
            // A cache miss means no authenticated backend was selected, so the
            // affected batch was not scanned.
            kind: AutorouteRoutingErrorKind::RoutingUnavailable,
            message: format!(
                "autoroute calibration required: this workload has no persisted \
                 fastest-correct backend decision.\n  \
                 fix: rerun this same scan once with `--autoroute-calibrate --autoroute-gpu` \
                 to measure its actual source/config/workload class, or run \
                 `keyhog calibrate-autoroute` for the core ladder; installers can use `install.sh --calibrate` or `install.ps1 -Calibrate`.\n  \
                 workload bucket: [{}], runtime={}\n  \
                 coverage: {coverage}.\n  \
                 cache: {cache_state}.\n  \
                 No backend was selected and this batch was not scanned. Decisions are scoped \
                 to this exact binary, host, detector corpus, resolved scan config, and source \
                 class. Normal auto scans never benchmark, guess, or substitute scalar execution. \
                 Pass an explicit `--backend <{}>` for a one-off diagnostic scan.",
                render_workload_key(&key),
                runtime_class.label(),
                backend_override_hint(),
            ),
        }
    }

    pub(super) fn calibration_not_persisted(error: impl fmt::Display) -> Self {
        Self {
            // A measurement was not made durable. Says nothing about matches.
            kind: AutorouteRoutingErrorKind::RoutingUnavailable,
            message: format!(
                "autoroute calibration did not persist a routing decision: {error}. \
                 Calibration records must be durable before auto routing can be trusted. \
                 Fix the cache path or permissions and rerun `keyhog calibrate-autoroute`. \
                 Use an explicit `--backend` only for a diagnostic scan; it does not replace \
                 autoroute evidence."
            ),
        }
    }

    pub(super) fn measurement_observer_unavailable() -> Self {
        Self {
            // A reporting lock, not a scan result.
            kind: AutorouteRoutingErrorKind::RoutingUnavailable,
            message: "autoroute calibration persisted its routing decision, but the current-run measured-route observer lock was poisoned; the command cannot report a truthful measured class count. Rerun `keyhog calibrate-autoroute`.".to_string(),
        }
    }

    pub(super) fn insufficient_calibration_sample(sample_chunks: usize, sample_bytes: u64) -> Self {
        Self {
            // Too little sample to decide a route. The scan is unaffected.
            kind: AutorouteRoutingErrorKind::RoutingUnavailable,
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
            // Host probing failed, so no route can be tied to this machine.
            kind: AutorouteRoutingErrorKind::RoutingUnavailable,
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
            // The workload could not be classified, so no bucket applies.
            kind: AutorouteRoutingErrorKind::RoutingUnavailable,
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
            // The scalar REFERENCE disagreed with itself across trials, so we
            // cannot say which finding set is the true one.
            kind: AutorouteRoutingErrorKind::FindingsUntrustworthy,
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
            // An eligible accelerator did not come up (initialization, missing
            // timing or route evidence, a degraded trial). The route is absent;
            // the matches are not in question. Divergence in what a candidate
            // FOUND uses `candidate_findings_diverged` instead.
            kind: AutorouteRoutingErrorKind::RoutingUnavailable,
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

    /// A candidate backend's OUTPUT differed from the scalar reference.
    ///
    /// The one case in this whole enum where the findings themselves are in
    /// doubt: two backends disagree about what the matches are and we do not
    /// know which set we are holding. Stays fatal and discarding, on purpose.
    pub(super) fn candidate_findings_diverged(
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
            kind: AutorouteRoutingErrorKind::FindingsUntrustworthy,
        }
    }

    pub(in crate::orchestrator::dispatch) fn selected_backend_dispatch_failed(
        backend: ScanBackend,
        error: impl fmt::Display,
    ) -> Self {
        Self {
            // The batch never ran, so this is COVERAGE, not trust. Verified
            // rather than defaulted: `scan_nonempty_batch` appends to its
            // finding vector only after this call's `?`, so a failure here
            // contributes exactly zero findings and leaves no partial output
            // from a peer that died mid-flight.
            kind: AutorouteRoutingErrorKind::BatchNotScanned,
            message: format!(
                "selected backend {} failed during dispatch ({error}); an explicit backend request or calibration candidate cannot be substituted. Repair the backend, rerun calibration, or select another diagnostic backend",
                backend.label(),
            ),
        }
    }

    pub(in crate::orchestrator::dispatch) fn unsupported_backend(backend: ScanBackend) -> Self {
        Self {
            // As above: no worker could scan this batch at all, and nothing was
            // emitted for it.
            kind: AutorouteRoutingErrorKind::BatchNotScanned,
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
            // The prior request completed through visible recovery, so its
            // output stands; only the route is quarantined.
            kind: AutorouteRoutingErrorKind::RoutingUnavailable,
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
            // Confused route identity. Conservative: do not vouch for output
            // produced under a route we cannot name.
            kind: AutorouteRoutingErrorKind::FindingsUntrustworthy,
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
        phase1_plan: (!backend.is_gpu())
            .then(|| scanner.phase1_admission_plan_for_backend(batch, backend)),
        execution_route: scanner.execution_route_for_backend(backend),
        recovery_plan: None,
        runtime_route: None,
        #[cfg(feature = "gpu")]
        ordered_gpu: None,
    })
}

pub(super) fn autoroute_required() -> bool {
    keyhog_scanner::hw_probe::multiple_backends_compiled()
}
/// Attach a phase-one plan for a known backend, filling deferred CPU trigger
/// hints when the automatic route lands on scalar execution.
pub(super) fn phase1_plan_for_selected_backend(
    scanner: &CompiledScanner,
    backend: ScanBackend,
    mut plan: Phase1AdmissionPlan,
    batch: &[Chunk],
) -> Phase1AdmissionPlan {
    if matches!(backend, ScanBackend::CpuFallback) {
        scanner.fill_cpu_trigger_hints_for_plan(&mut plan, batch);
    }
    plan
}

/// The route this workload's measured family reconciles to.
///
/// A sibling shares this workload's detector corpus, decode state, and set of
/// source classes, and differs only in size band.
///
/// The workload key is a conjunction of enumerable bands. The reachable grid
/// is about 1.45 million cells (13,685 valid byte/chunk/max-file triples, two
/// decode states, 53 source classes); the probe ladder measures a few hundred
/// of them, and enumerating the rest would take hundreds of hours. Exact
/// lookup therefore missed nearly every real scan: a freshly calibrated
/// install exited 2 on a two-file directory, and adding one file to a
/// directory that had just scanned broke it again.
///
/// The family's bands are pooled and reconciled by
/// [`reconcile_route_across_decisions`], which is the same rule that
/// reconciles the repeated points inside one band. Serving its result is not a
/// guess, a benchmark, a heuristic, or a substituted backend: the backend it
/// returns was measured at every band of the family and proved slower at none,
/// and where the bands split on the phase-2 plan it returns the compiled
/// default plan every band measured. A real crossover, where one band proves a
/// peer faster and another proves the reverse, leaves no route non-inferior
/// everywhere, and the scan fails closed exactly as before rather than picking
/// a side.
fn family_agreed_route<'a>(
    decisions: &'a HashMap<WorkloadKey, AutorouteDecision>,
    key: &WorkloadKey,
    runtime_class: AutorouteRuntimeClass,
) -> Option<(MeasuredRoute, &'a AutorouteDecision)> {
    let persistent = runtime_class == AutorouteRuntimeClass::Persistent;
    let mut family: Vec<(&WorkloadKey, &AutorouteDecision)> = decisions
        .iter()
        .filter(|(candidate, _)| {
            candidate.pattern_bucket == key.pattern_bucket
                && candidate.decode_admitted == key.decode_admitted
                && candidate.source_mixture == key.source_mixture
        })
        .collect();
    // HashMap order is not stable across runs and the reconciled plan reads the
    // compiled default off the first pooled point, so order by band.
    family.sort_unstable_by_key(|(candidate, _)| {
        (
            candidate.bytes_bucket,
            candidate.chunks_bucket,
            candidate.max_file_bucket,
        )
    });
    for (_, decision) in &family {
        // A sibling that resolves no route leaves the family incompletely
        // measured, so it withdraws the whole reuse instead of being skipped.
        let route = match runtime_class {
            AutorouteRuntimeClass::OneShot => decision.measured_route()?,
            AutorouteRuntimeClass::Persistent => decision.resolved_persistent_route()?,
        };
        // GPU correctness, not merely GPU speed, varies with input size: batch
        // input limits and slot capacities are bound to the measured shape, and
        // a parity receipt proves that shape and no other. A GPU route is
        // therefore never reused for a band nobody measured, however unanimous
        // its neighbours are.
        if route.backend.is_gpu() {
            return None;
        }
    }
    // One measured band says nothing about whether the winner depends on size.
    // Invariance needs at least two bands.
    if family.len() < 2 {
        return None;
    }
    let members: Vec<&AutorouteDecision> = family.iter().map(|(_, decision)| *decision).collect();
    let route = reconcile_route_across_decisions(&members, persistent)?;
    if route.backend.is_gpu() {
        return None;
    }
    // An accelerated route is only usable with a recovery peer, so the family
    // must agree on that too. Serving a route whose bands recover differently
    // would hand the scan a recovery peer nothing measured for this band.
    if route.backend != ScanBackend::CpuFallback {
        let mut agreed_recovery: Option<MeasuredRoute> = None;
        for decision in &members {
            let recovery = decision.resolved_recovery_route(route.backend, persistent)?;
            match agreed_recovery {
                None => agreed_recovery = Some(recovery),
                Some(existing) if existing == recovery => {}
                Some(_) => return None,
            }
        }
    }
    Some((route, members[0]))
}

/// A route plus the calibrated decision that authorizes it. For an exact hit
/// that is the workload's own row; for a reused route it is the family member
/// whose evidence every measured sibling reproduced.
#[derive(Debug)]
pub(super) struct ResolvedRoute<'a> {
    pub(super) route: MeasuredRoute,
    pub(super) decision: &'a AutorouteDecision,
}

pub(super) fn resolve_persisted_route<'a>(
    decisions: &'a HashMap<WorkloadKey, AutorouteDecision>,
    key: WorkloadKey,
    runtime_class: AutorouteRuntimeClass,
    cache_path: &Option<PathBuf>,
    cache_load_error: &Option<String>,
) -> Result<ResolvedRoute<'a>, AutorouteRoutingError> {
    let resolved = decisions
        .get(&key)
        .and_then(|decision| {
            match runtime_class {
                AutorouteRuntimeClass::OneShot => decision.measured_route(),
                AutorouteRuntimeClass::Persistent => decision.resolved_persistent_route(),
            }
            .map(|route| (route, decision))
        })
        .or_else(|| family_agreed_route(decisions, &key, runtime_class));
    resolved
        .map(|(route, decision)| ResolvedRoute { route, decision })
        .ok_or_else(|| {
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
