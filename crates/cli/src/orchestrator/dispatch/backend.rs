//! Backend override parsing and calibrated batch backend selection.
//!
//! # Two routers, one decision source
//!
//! Backend choice splits by *when* it runs, never by guessing:
//!
//! - [`CachedBackendRouter`] drives normal scans. It only reads install-time
//!   calibration evidence, zero benchmarks, zero writes. Invalid evidence is
//!   never called autoroute: the scan visibly replays through the scalar
//!   correctness oracle and reports complete recovery with a repair command.
//! - [`MeasuredBackendRouter`] drives explicit calibration (installer / backend
//!   maintenance). It probes candidate backends, proves output parity against a
//!   reference, times the survivors, and persists the fastest correct choice.
//!
//! Both honour an explicit `--backend` first; only then does
//! [`sole_compiled_backend`] resolve a build that compiled exactly one backend
//! (portable / single-feature). Neither path silently substitutes.
//!
//! # Submodule map (one-way dependency DAG)
//!
//! ```text
//! backend.rs ── routers, override parsing, single-backend resolution
//!   ├─ calibration ── install-time probe/parity/timing measurement
//!   ├─ evidence ───── decision policy
//!   │    ├─ timing ─────── measured trials and confidence intervals
//!   │    └─ match_identity ─ secret-safe semantic parity proof
//!   ├─ store ──────── cache facade (schema v44)
//!   │    ├─ schema / artifact_identity / build_identity
//!   │    └─ codec / validation / persistence / inspection
//!   ├─ host ───────── host identity captured in each calibration record
//!   └─ workload ───── workload bucketing + source-shape fingerprints
//! ```
//!
//! Low-level evidence, identity, and codec modules never import routers; only
//! [`inspect_autoroute_cache`] crosses the package boundary outward.

mod calibration;
mod evidence;
mod host;
mod runtime_health;
mod store;
mod workload;

use self::calibration::calibrate_fastest_correct_backend;
use self::evidence::AutorouteDecision;
use self::host::{host_identity_digest, AutorouteHostProfile};
use self::runtime_health::{
    clear_runtime_route_faults, load_runtime_route_faults, persist_runtime_route_fault,
    RuntimeHealthIdentity,
};
use self::store::{
    autoroute_cache_file_presence, load_autoroute_cache, save_autoroute_cache,
    AutorouteCacheSaveOutcome,
};
pub(crate) use self::store::{inspect_autoroute_cache, AutorouteReadiness};
pub(crate) use self::workload::source_route_class;
use self::workload::{
    differing_workload_dimensions, measurement_shape_evidence, render_workload_key, workload_key,
    WorkloadClassificationError, WorkloadKey,
};
use keyhog_core::Chunk;
use keyhog_scanner::hw_probe::{HardwareCaps, ScanBackend};
use keyhog_scanner::{CompiledScanner, Phase1AdmissionPlan};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Canonical `(config digest, exact host digest, rendered workload key)`
/// receipts persisted by this calibration command. The host dimension prevents
/// a shared cache's older generation from proving this host's calibration.
pub(crate) type AutorouteMeasurementObserver = Arc<Mutex<BTreeSet<(String, String, String)>>>;

// v44: every timing point carries a content-addressed measurement-shape
// receipt, so equal byte/chunk counts cannot overwrite different payloads.
// v43: source identity retains the canonical execution subtype instead of
// truncating at the first ':' or '/'. Dynamic binary section names collapse to
// their format class so route identity changes with preprocessing, not labels.
// v42: calibration trials are interleaved across peers and resolve only when
// one route's 95% confidence interval is wholly faster than every peer backend.
// Older sequential-trial rows could encode host drift as backend performance.
// v41: phase-two Hyperscan is owned only by the measured SIMD route. Older
// scalar and GPU rows included unreported SIMD work and are not comparable.
// v40: SIMD timing adopts the same first-materialization plus warm-trial model
// as GPU. Older rows measured only warm Hyperscan execution and would make a
// lazy one-shot route look faster than the operator-observed path.
// v34: route generations are keyed by exact `(config digest, host)` identity,
// so shared caches preserve independent evidence for every calibrated host.
// v33: each resolved config host persists the exact live eligible-backend
// census, and every decision must carry timing and parity evidence for it.
// v32: projected host and accelerator-peer identity moves from the cache root
// into each resolved config generation so distinct GPU policies can coexist.
// v31: every timing decision carries a digest of its complete workload key.
// v30: workload identity preserves exact reduced, raw-family-free source mixtures so
// different source-family proportions cannot alias one calibration decision.
// v29: workload identity includes scanner-owned phase-1 admission classes so
// raw-prefilter rejects cannot reuse full-literal-scan timing evidence.
// v28: each measured backend has an explicit parity receipt binding its
// canonical identity, correctness digest, and completed trial count.
// v27: CUDA and WGPU are independent GPU candidates with distinct route labels
// and timing evidence. v26 collapsed both drivers into one GPU timing slot.
// v26: scanner-owned decoder-family and bounded candidate-work evidence
// replaces the CLI-local decode-density estimate. Workload keys changed.
// v25: decode-density evidence uses bounded order-independent stratified
// sampling. Earlier workload bucket ids do not carry the same meaning.
// v24: exact running-executable SHA-256 joins the cache identity. Two artifacts
// with the same package/git/features but different codegen or native linkage
// can no longer reuse one another's performance evidence.
// v23: timing evidence persists only the measured trial vector. Min/max/mean,
// best-trial, confidence intervals, and medians are derived on demand, so the
// cache cannot contain a summary that disagrees with its primary evidence.
// v22: one-power-of-two workload bands replace the old paired bands. Numeric
// bucket ids changed meaning, so v21 caches must be rejected rather than risk a
// small new workload aliasing a much larger old calibration row.
// v21: primary-evidence-only decision schema. `AutorouteDecision` persists just
// the measured timing evidence (simd/cpu/gpu) plus backend/sample/digest; every
// derived value (per-backend ms, GPU cold/warm/route, selected margin) is computed
// on load via accessors instead of stored, so a cache can never hold a value
// inconsistent with its own evidence (the whole cross-field-mismatch validation
// class is gone). v20 caches carry the now-removed denormalized fields and are
// rejected on the version gate and recalibrated.
// v20: multi-config cache schema, shared binary/host/corpus identity once at
// the top, per-resolved-config routing decisions under `configs` keyed by
// config_digest, merge-on-save. Old single-config (v19 and earlier) caches are
// rejected on the version gate and recalibrated.
pub(super) const AUTOROUTE_CACHE_VERSION: u32 = 44;
pub(super) const AUTOROUTE_CALIBRATION_TRIALS: usize = 7;
pub(super) const AUTOROUTE_ACCELERATOR_WARM_TRIALS: usize = AUTOROUTE_CALIBRATION_TRIALS - 1;

fn backend_override_hint() -> String {
    keyhog_scanner::hw_probe::BACKEND_OVERRIDE_VALUES
        .into_iter()
        .filter(|value| *value != "auto")
        .collect::<Vec<_>>()
        .join("|")
}

/// Persistent calibrated backend router.
///
/// Autoroute probes only in explicit calibration mode (installer / backend
/// maintenance). Cache hits are zero-benchmark table lookups; invalid state in
/// normal scans is reported as scalar correctness recovery, never autoroute.
pub(super) struct MeasuredBackendRouter {
    pattern_count: usize,
    decode_workload_plan: keyhog_scanner::decode::DecodeWorkloadPlan,
    detector_digest: u64,
    rules_digest: String,
    config_digest: u64,
    gpu_participates: bool,
    calibration_mode: bool,
    host_profile: AutorouteHostProfile,
    decisions: HashMap<WorkloadKey, AutorouteDecision>,
    measured_this_run: HashSet<WorkloadKey>,
    runtime_faults: HashMap<WorkloadKey, RuntimeRouteFault>,
    measurement_observer: Option<AutorouteMeasurementObserver>,
    cache_path: Option<PathBuf>,
    cache_load_error: Option<String>,
    cache_dirty: bool,
    runtime_health: Option<RuntimeHealthIdentity>,
    recovery_announced: bool,
}

/// Cache-only backend router for fused filesystem scans.
///
/// This never benchmarks or writes decisions; it only consumes install-time
/// calibration evidence. Missing buckets use a visible scalar recovery, keeping
/// normal scans free of runtime probes and backend guesses while preserving
/// complete byte coverage.
pub(crate) struct CachedBackendRouter {
    pattern_count: usize,
    decode_workload_plan: keyhog_scanner::decode::DecodeWorkloadPlan,
    decisions: HashMap<WorkloadKey, AutorouteDecision>,
    cache_path: Option<PathBuf>,
    cache_load_error: Option<String>,
    runtime_class: AutorouteRuntimeClass,
    runtime_faults: Mutex<HashMap<WorkloadKey, RuntimeRouteFault>>,
    runtime_health: Option<RuntimeHealthIdentity>,
    recovery_announced: AtomicBool,
}

#[derive(Debug, Clone)]
struct RuntimeRouteFault {
    backend: ScanBackend,
    reason: String,
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeRouteIdentity {
    key: WorkloadKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AutorouteRuntimeClass {
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
        // Inverted pyramid: what happened, then the fix, then the forensics.
        // The bucket is rendered by `workload::render_workload_key`: the ONE
        // rendering shared with `keyhog backend --autoroute`, so an operator can
        // match this refused bucket against calibrated buckets field-for-field.
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

    fn calibration_not_persisted(error: impl fmt::Display) -> Self {
        Self {
            message: format!(
                "autoroute calibration did not persist a routing decision: {error}. \
                 Calibration records must be durable before auto routing can be trusted. \
                 Fix the cache path/permissions and rerun `install.sh --calibrate` or \
                 `install.ps1 -Calibrate`."
            ),
        }
    }

    fn measurement_observer_unavailable() -> Self {
        Self {
            message: "autoroute calibration persisted its routing decision, but the current-run measured-route observer lock was poisoned; the command cannot report a truthful measured class count. Rerun `keyhog calibrate-autoroute`.".to_string(),
        }
    }

    fn insufficient_calibration_sample(sample_chunks: usize, sample_bytes: u64) -> Self {
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

    fn host_identity_unavailable(error: impl fmt::Display) -> Self {
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

    fn incomplete_workload_evidence(error: WorkloadClassificationError) -> Self {
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

    fn inconsistent_reference_backend(trial: usize) -> Self {
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

    fn candidate_backend_rejected(backend: ScanBackend, reason: impl fmt::Display) -> Self {
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

    pub(super) fn selected_backend_dispatch_failed(
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

    pub(super) fn unsupported_backend(backend: ScanBackend) -> Self {
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

    fn runtime_route_unhealthy(
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
}

impl fmt::Display for AutorouteRoutingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AutorouteRoutingError {}

/// The sole scan backend when this build compiled no backend *choice*.
///
/// `SimdCpu` is gated by the `simd` (Hyperscan) feature and `Gpu` by
/// `gpu`; a build with neither (e.g. `--features portable`) can only ever run
/// `CpuFallback`. There is nothing to route, and autoroute calibration could never
/// produce a decision such a build would request, so resolving the lone backend
/// here keeps single-backend builds from failing closed (exit 2) on a workload
/// they have no way to calibrate. This is NOT a silent fallback: it is the only
/// backend that exists, and it is reached only AFTER the explicit `--backend`
/// override, so it never substitutes for a backend the operator actually asked for.
///
/// The compiled-backend fact is owned by the scanner, not asked via the CLI's own
/// `cfg!`: the CLI's features diverge from the scanner's (e.g. `ci-lean` turns on
/// `keyhog-scanner/simd` without the CLI's `simd`), so a CLI-local `cfg!` would
/// wrongly bypass calibration on a build that DOES compile Hyperscan.
fn sole_compiled_backend() -> Option<ScanBackend> {
    if keyhog_scanner::hw_probe::multiple_backends_compiled() {
        None
    } else {
        Some(ScanBackend::CpuFallback)
    }
}

fn autoroute_state_recovery_selection(
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

impl CachedBackendRouter {
    pub(crate) fn new(
        hw_caps: HardwareCaps,
        pattern_count: usize,
        rules_digest: String,
        config_digest: u64,
        gpu_participates: bool,
        autoroute_cache_path: Result<Option<PathBuf>, String>,
        scanner: &CompiledScanner,
    ) -> Self {
        let runtime_status = scanner.runtime_status();
        let detector_digest = runtime_status.detector_digest;
        let gpu_participates = gpu_participates && keyhog_scanner::hw_probe::gpu_backend_compiled();
        let gpu_peer_identity = gpu_participates
            .then(|| gpu_peer_identity(scanner))
            .flatten();
        let eligible_backends = eligible_backend_labels(scanner, gpu_participates);
        let host_profile = AutorouteHostProfile::from_caps(
            &hw_caps,
            gpu_peer_identity.as_deref(),
            gpu_participates,
            eligible_backends,
        )
        .with_live_hyperscan(scanner.simd_backend_available());
        let (cache_path, mut decisions, mut cache_load_error) = load_persistent_autoroute_decisions(
            detector_digest,
            &rules_digest,
            config_digest,
            &host_profile,
            autoroute_cache_path,
        );
        let runtime_health = cache_path.as_deref().map(|path| {
            RuntimeHealthIdentity::new(path, config_digest, host_identity_digest(&host_profile))
        });
        let runtime_faults = match runtime_health.as_ref() {
            Some(identity) if cache_load_error.is_none() && !decisions.is_empty() => {
                match load_runtime_fault_map(identity, &decisions) {
                    Ok(faults) => faults,
                    Err(error) => {
                        decisions.clear();
                        cache_load_error = Some(error);
                        HashMap::new()
                    }
                }
            }
            _ => HashMap::new(),
        };

        Self {
            pattern_count,
            decode_workload_plan: scanner.decode_workload_plan(),
            decisions,
            cache_path,
            cache_load_error,
            runtime_class: AutorouteRuntimeClass::OneShot,
            runtime_faults: Mutex::new(runtime_faults),
            runtime_health,
            recovery_announced: AtomicBool::new(false),
        }
    }

    pub(crate) fn for_persistent_runtime(mut self) -> Self {
        self.runtime_class = AutorouteRuntimeClass::Persistent;
        self
    }

    pub(crate) fn autoroute_state_is_invalid(&self) -> bool {
        sole_compiled_backend().is_none() && self.decisions.is_empty()
    }

    pub(crate) fn autoroute_has_quarantined_routes(&self) -> bool {
        self.runtime_faults
            .lock()
            .map(|faults| !faults.is_empty())
            .unwrap_or(true)
    }

    /// Exact peers selected by at least one validated persistent-runtime
    /// decision. Invalid autoroute state initializes only scalar recovery so a
    /// daemon or watcher can become ready and report degraded routing per request.
    pub(crate) fn persistent_routes(&self) -> Result<Vec<ScanBackend>, AutorouteRoutingError> {
        if self.autoroute_state_is_invalid() {
            return Ok(vec![ScanBackend::CpuFallback]);
        }
        let mut routes = Vec::new();
        for decision in self.decisions.values() {
            let backend = decision.resolved_persistent_backend().ok_or_else(|| {
                AutorouteRoutingError::calibration_not_persisted(
                    "persisted autoroute decision has no complete persistent-runtime route evidence",
                )
            })?;
            if !routes.contains(&backend) {
                routes.push(backend);
            }
        }
        routes.sort_by_key(|backend| backend.label());
        Ok(routes)
    }

    #[cfg(test)]
    pub(crate) fn persistent_gpu_routes(&self) -> Result<Vec<ScanBackend>, AutorouteRoutingError> {
        Ok(self
            .persistent_routes()?
            .into_iter()
            .filter(|backend| backend.is_gpu())
            .collect())
    }

    pub(crate) fn choose_with_plan(
        &self,
        scanner: &CompiledScanner,
        explicit: Option<ScanBackend>,
        batch: &[Chunk],
    ) -> Result<BackendSelection, AutorouteRoutingError> {
        if let Some(forced) = explicit {
            return Ok(BackendSelection {
                backend: forced,
                phase1_plan: (!forced.is_gpu()).then(|| scanner.phase1_admission_plan(batch)),
                execution_route: scanner.execution_route_for_backend(forced),
                recovery_plan: None,
                runtime_route: None,
                autoroute_recovery: None,
            });
        }
        if let Some(only) = sole_compiled_backend() {
            return Ok(BackendSelection {
                backend: only,
                phase1_plan: (!only.is_gpu()).then(|| scanner.phase1_admission_plan(batch)),
                execution_route: scanner.execution_route_for_backend(only),
                recovery_plan: None,
                runtime_route: None,
                autoroute_recovery: None,
            });
        }
        let phase1_plan = scanner.phase1_admission_plan(batch);
        let key = match workload_key(
            batch,
            self.pattern_count,
            phase1_plan.summary(),
            self.decode_workload_plan,
        ) {
            Ok(key) => key,
            Err(error) => {
                let reason = AutorouteRoutingError::incomplete_workload_evidence(error).to_string();
                let announce = !self.recovery_announced.swap(true, Ordering::Relaxed);
                return Ok(autoroute_state_recovery_selection(
                    scanner,
                    phase1_plan,
                    reason,
                    announce,
                ));
            }
        };
        if let Some(fault) = self
            .runtime_faults
            .lock()
            .map_err(|_| AutorouteRoutingError {
                message: "autoroute runtime route-health lock is poisoned; restart KeyHog before scanning again".to_string(),
            })?
            .get(&key)
            .cloned()
        {
            let reason = AutorouteRoutingError::runtime_route_unhealthy(
                &key,
                self.runtime_class,
                &fault,
            )
            .to_string();
            let announce = !self.recovery_announced.swap(true, Ordering::Relaxed);
            return Ok(autoroute_state_recovery_selection(
                scanner,
                phase1_plan,
                reason,
                announce,
            ));
        }
        let route = match resolve_persisted_route(
            &self.decisions,
            key.clone(),
            self.runtime_class,
            &self.cache_path,
            &self.cache_load_error,
        ) {
            Ok(route) => route,
            Err(error) => {
                let announce = !self.recovery_announced.swap(true, Ordering::Relaxed);
                return Ok(autoroute_state_recovery_selection(
                    scanner,
                    phase1_plan,
                    error.to_string(),
                    announce,
                ));
            }
        };
        Ok(BackendSelection {
            backend: route.backend,
            phase1_plan: Some(phase1_plan),
            execution_route: route.execution_route(),
            recovery_plan: automatic_recovery_plan(
                self.decisions.get(&key),
                route.backend,
                self.runtime_class,
            )?,
            runtime_route: Some(RuntimeRouteIdentity { key }),
            autoroute_recovery: None,
        })
    }

    pub(crate) fn quarantine_recovered_route(
        &self,
        selection: &BackendSelection,
        recovery: &keyhog_scanner::BackendRecoveryReceipt,
    ) -> Result<(), AutorouteRoutingError> {
        let Some(identity) = selection.runtime_route.as_ref() else {
            return Ok(());
        };
        if recovery.failed_backend != selection.backend {
            return Err(AutorouteRoutingError {
                message: format!(
                    "autoroute recovery receipt names failed backend {}, but the selected route was {}; refusing to quarantine the wrong route identity",
                    recovery.failed_backend.label(),
                    selection.backend.label(),
                ),
            });
        }
        self.runtime_faults
            .lock()
            .map_err(|_| AutorouteRoutingError {
                message: "autoroute recovered the request, but the runtime route-health lock is poisoned; restart KeyHog before scanning again".to_string(),
            })?
            .insert(
                identity.key.clone(),
                RuntimeRouteFault {
                    backend: recovery.failed_backend,
                    reason: recovery.reason.clone(),
                },
            );
        if let Some(runtime_health) = self.runtime_health.as_ref() {
            if let Err(error) = persist_runtime_route_fault(
                runtime_health,
                &identity.key,
                recovery.failed_backend.label(),
                &recovery.reason,
            ) {
                eprintln!(
                    "keyhog: WARNING: recovered scan coverage is complete, but durable autoroute quarantine could not be persisted ({error}); do not restart before recalibrating"
                );
                tracing::warn!(
                    target: "keyhog::routing",
                    %error,
                    "durable autoroute quarantine persistence failed",
                );
            }
        }
        Ok(())
    }
}

/// Resolve an exact workload bucket against the persisted decision table.
/// A miss becomes visible scalar recovery at the router boundary. ONE owner for
/// the lookup contract shared by
/// [`CachedBackendRouter::choose`] and the non-calibration branch of
/// [`MeasuredBackendRouter::choose`], neither router may infer a backend from
/// neighbouring measurements.
fn resolve_persisted_route(
    decisions: &HashMap<WorkloadKey, AutorouteDecision>,
    key: WorkloadKey,
    runtime_class: AutorouteRuntimeClass,
    cache_path: &Option<PathBuf>,
    cache_load_error: &Option<String>,
) -> Result<evidence::MeasuredRoute, AutorouteRoutingError> {
    let route = decisions
        .get(&key)
        .and_then(|decision| match runtime_class {
            AutorouteRuntimeClass::OneShot => decision.measured_route(),
            AutorouteRuntimeClass::Persistent => decision.resolved_persistent_route(),
        });
    match route {
        Some(route) => Ok(route),
        None => Err(AutorouteRoutingError::missing_decision(
            key,
            decisions,
            runtime_class,
            cache_path,
            cache_load_error,
        )),
    }
}

fn automatic_recovery_plan(
    decision: Option<&AutorouteDecision>,
    selected_backend: ScanBackend,
    runtime_class: AutorouteRuntimeClass,
) -> Result<Option<BackendRecoveryPlan>, AutorouteRoutingError> {
    if !selected_backend.is_gpu() {
        return Ok(None);
    }
    let persistent_runtime = runtime_class == AutorouteRuntimeClass::Persistent;
    let route = decision
        .and_then(|decision| {
            decision.resolved_recovery_route(selected_backend, persistent_runtime)
        })
        .ok_or_else(|| {
            AutorouteRoutingError::calibration_not_persisted(format!(
                "autoroute selected {}, but its workload evidence does not resolve one fastest remaining measured-correct recovery peer across every calibration point; rerun `keyhog calibrate-autoroute` after repairing or splitting this workload class",
                selected_backend.label()
            ))
        })?;
    Ok(Some(BackendRecoveryPlan {
        backend: route.backend,
        execution_route: route.execution_route(),
    }))
}

impl MeasuredBackendRouter {
    pub(super) fn new(
        hw_caps: HardwareCaps,
        pattern_count: usize,
        rules_digest: String,
        config_digest: u64,
        gpu_runtime_participates: bool,
        autoroute_gpu: bool,
        calibration_mode: bool,
        autoroute_cache_path: Result<Option<PathBuf>, String>,
        measurement_observer: Option<AutorouteMeasurementObserver>,
        scanner: &CompiledScanner,
    ) -> Self {
        let runtime_status = scanner.runtime_status();
        let detector_digest = runtime_status.detector_digest;
        // A GPU-excluded runtime or diagnostic calibration neither measures nor
        // persists a GPU route, so physical GPU identity is not part of that
        // cache. Eligible normal routing and all-candidate calibration retain
        // the exact device/runtime/driver identity.
        let gpu_participates = gpu_runtime_participates
            && keyhog_scanner::hw_probe::gpu_backend_compiled()
            && (!calibration_mode || autoroute_gpu);
        let gpu_peer_identity = gpu_participates
            .then(|| gpu_peer_identity(scanner))
            .flatten();
        let eligible_backends = eligible_backend_labels(scanner, gpu_participates);
        let host_profile = AutorouteHostProfile::from_caps(
            &hw_caps,
            gpu_peer_identity.as_deref(),
            gpu_participates,
            eligible_backends,
        )
        .with_live_hyperscan(scanner.simd_backend_available());
        let (cache_path, mut decisions, mut cache_load_error) = load_persistent_autoroute_decisions(
            detector_digest,
            &rules_digest,
            config_digest,
            &host_profile,
            autoroute_cache_path,
        );
        let runtime_health = cache_path.as_deref().map(|path| {
            RuntimeHealthIdentity::new(path, config_digest, host_identity_digest(&host_profile))
        });
        let runtime_faults = match runtime_health.as_ref() {
            Some(identity) if cache_load_error.is_none() && !decisions.is_empty() => {
                match load_runtime_fault_map(identity, &decisions) {
                    Ok(faults) => faults,
                    Err(error) if calibration_mode => {
                        eprintln!(
                            "warning: autoroute runtime health is invalid ({error}); calibration will not trust it and must repair or remove the artifact before commit"
                        );
                        HashMap::new()
                    }
                    Err(error) => {
                        decisions.clear();
                        cache_load_error = Some(error);
                        HashMap::new()
                    }
                }
            }
            _ => HashMap::new(),
        };

        Self {
            pattern_count,
            decode_workload_plan: scanner.decode_workload_plan(),
            detector_digest,
            rules_digest,
            config_digest,
            gpu_participates,
            calibration_mode,
            host_profile,
            decisions,
            measured_this_run: HashSet::new(),
            runtime_faults,
            measurement_observer,
            cache_path,
            cache_load_error,
            cache_dirty: false,
            runtime_health,
            recovery_announced: false,
        }
    }

    pub(super) fn choose_with_plan(
        &mut self,
        scanner: &CompiledScanner,
        explicit: Option<ScanBackend>,
        batch: &[Chunk],
    ) -> Result<BackendSelection, AutorouteRoutingError> {
        if let Some(forced) = explicit {
            return Ok(BackendSelection {
                backend: forced,
                phase1_plan: (!forced.is_gpu()).then(|| scanner.phase1_admission_plan(batch)),
                execution_route: scanner.execution_route_for_backend(forced),
                recovery_plan: None,
                runtime_route: None,
                autoroute_recovery: None,
            });
        }
        if let Some(only) = sole_compiled_backend() {
            return Ok(BackendSelection {
                backend: only,
                phase1_plan: (!only.is_gpu()).then(|| scanner.phase1_admission_plan(batch)),
                execution_route: scanner.execution_route_for_backend(only),
                recovery_plan: None,
                runtime_route: None,
                autoroute_recovery: None,
            });
        }
        let phase1_plan = scanner.phase1_admission_plan(batch);
        let key = match workload_key(
            batch,
            self.pattern_count,
            phase1_plan.summary(),
            self.decode_workload_plan,
        ) {
            Ok(key) => key,
            Err(error) if !self.calibration_mode => {
                let reason = AutorouteRoutingError::incomplete_workload_evidence(error).to_string();
                let announce = !std::mem::replace(&mut self.recovery_announced, true);
                return Ok(autoroute_state_recovery_selection(
                    scanner,
                    phase1_plan,
                    reason,
                    announce,
                ));
            }
            Err(error) => {
                return Err(AutorouteRoutingError::incomplete_workload_evidence(error));
            }
        };
        if !self.calibration_mode {
            if let Some(fault) = self.runtime_faults.get(&key) {
                let reason = AutorouteRoutingError::runtime_route_unhealthy(
                    &key,
                    AutorouteRuntimeClass::OneShot,
                    fault,
                )
                .to_string();
                let announce = !std::mem::replace(&mut self.recovery_announced, true);
                return Ok(autoroute_state_recovery_selection(
                    scanner,
                    phase1_plan,
                    reason,
                    announce,
                ));
            }
        }
        let measurement_shape = if self.calibration_mode {
            Some(
                measurement_shape_evidence(batch)
                    .map_err(AutorouteRoutingError::incomplete_workload_evidence)?,
            )
        } else {
            None
        };
        if let Some(route) = self.reusable_decision_route(&key, measurement_shape.as_ref()) {
            return Ok(BackendSelection {
                backend: route.backend,
                phase1_plan: Some(phase1_plan),
                execution_route: route.execution_route(),
                recovery_plan: if self.calibration_mode {
                    None
                } else {
                    automatic_recovery_plan(
                        self.decisions.get(&key),
                        route.backend,
                        AutorouteRuntimeClass::OneShot,
                    )?
                },
                runtime_route: Some(RuntimeRouteIdentity { key: key.clone() }),
                autoroute_recovery: None,
            });
        }

        if !self.calibration_mode {
            // A miss remains an invalid autoroute state: neighbouring evidence
            // is never reused. The caller receives an explicitly marked scalar
            // recovery so every byte is scanned without disguising it as a
            // fastest-route decision.
            let route = match resolve_persisted_route(
                &self.decisions,
                key.clone(),
                AutorouteRuntimeClass::OneShot,
                &self.cache_path,
                &self.cache_load_error,
            ) {
                Ok(route) => route,
                Err(error) => {
                    let announce = !std::mem::replace(&mut self.recovery_announced, true);
                    return Ok(autoroute_state_recovery_selection(
                        scanner,
                        phase1_plan,
                        error.to_string(),
                        announce,
                    ));
                }
            };
            return Ok(BackendSelection {
                backend: route.backend,
                phase1_plan: Some(phase1_plan),
                execution_route: route.execution_route(),
                recovery_plan: automatic_recovery_plan(
                    self.decisions.get(&key),
                    route.backend,
                    AutorouteRuntimeClass::OneShot,
                )?,
                runtime_route: Some(RuntimeRouteIdentity { key }),
                autoroute_recovery: None,
            });
        }
        self.host_profile
            .require_exact_identity()
            .map_err(AutorouteRoutingError::host_identity_unavailable)?;
        self.persist_cache_path()?;

        let live_eligible_backends = eligible_backend_labels(scanner, self.gpu_participates);
        if live_eligible_backends != self.host_profile.eligible_backends {
            return Err(AutorouteRoutingError::calibration_not_persisted(
                "eligible backend set changed after calibration started; rerun calibration so every candidate is measured under one stable peer census",
            ));
        }
        let decision = calibrate_fastest_correct_backend(
            scanner,
            self.pattern_count,
            batch,
            measurement_shape.ok_or_else(|| {
                AutorouteRoutingError::calibration_not_persisted(
                    "calibration measurement identity was not constructed",
                )
            })?,
            &live_eligible_backends,
            Some(&phase1_plan),
        )?;
        let route = match decision.measured_route() {
            Some(route) => route,
            None => {
                return Err(AutorouteRoutingError::calibration_not_persisted(
                    "calibration produced an unsupported backend label",
                ));
            }
        };
        if self.measured_this_run.contains(&key) {
            self.decisions
                .get_mut(&key)
                .ok_or_else(|| {
                    AutorouteRoutingError::calibration_not_persisted(
                        "autoroute measured-point state lost its workload decision",
                    )
                })?
                .merge_calibration_point(decision)
                .map_err(AutorouteRoutingError::calibration_not_persisted)?;
        } else {
            self.decisions.insert(key.clone(), decision);
            self.measured_this_run.insert(key);
        }
        self.cache_dirty = true;
        Ok(BackendSelection {
            backend: route.backend,
            phase1_plan: Some(phase1_plan),
            execution_route: route.execution_route(),
            recovery_plan: None,
            runtime_route: None,
            autoroute_recovery: None,
        })
    }

    pub(super) fn quarantine_recovered_route(
        &mut self,
        selection: &BackendSelection,
        recovery: &keyhog_scanner::BackendRecoveryReceipt,
    ) -> Result<(), AutorouteRoutingError> {
        let Some(identity) = selection.runtime_route.as_ref() else {
            return Ok(());
        };
        if recovery.failed_backend != selection.backend {
            return Err(AutorouteRoutingError {
                message: format!(
                    "autoroute recovery receipt names failed backend {}, but the selected route was {}; refusing to quarantine the wrong route identity",
                    recovery.failed_backend.label(),
                    selection.backend.label(),
                ),
            });
        }
        self.runtime_faults.insert(
            identity.key.clone(),
            RuntimeRouteFault {
                backend: recovery.failed_backend,
                reason: recovery.reason.clone(),
            },
        );
        if let Some(runtime_health) = self.runtime_health.as_ref() {
            if let Err(error) = persist_runtime_route_fault(
                runtime_health,
                &identity.key,
                recovery.failed_backend.label(),
                &recovery.reason,
            ) {
                eprintln!(
                    "keyhog: WARNING: recovered scan coverage is complete, but durable autoroute quarantine could not be persisted ({error}); do not restart before recalibrating"
                );
                tracing::warn!(
                    target: "keyhog::routing",
                    %error,
                    "durable autoroute quarantine persistence failed",
                );
            }
        }
        Ok(())
    }

    fn reusable_decision_route(
        &self,
        key: &WorkloadKey,
        measurement_shape: Option<&workload::MeasurementShapeEvidence>,
    ) -> Option<evidence::MeasuredRoute> {
        if self.calibration_mode && !self.measured_this_run.contains(key) {
            return None;
        }
        let decision = self.decisions.get(key)?;
        if self.calibration_mode {
            let measurement_shape = measurement_shape?;
            if !decision.contains_measurement(measurement_shape) {
                return None;
            }
        }
        decision.measured_route()
    }

    pub(super) fn commit(&mut self) -> Result<(), AutorouteRoutingError> {
        self.save_cache()
    }

    fn save_cache(&mut self) -> Result<(), AutorouteRoutingError> {
        if !self.cache_dirty {
            return Ok(());
        }
        let path = self.persist_cache_path()?;
        let measured_decisions;
        let decisions = if self.calibration_mode {
            measured_decisions = self
                .decisions
                .iter()
                .filter(|(key, _)| self.measured_this_run.contains(key))
                .map(|(key, decision)| (key.clone(), decision.clone()))
                .collect::<HashMap<_, _>>();
            &measured_decisions
        } else {
            &self.decisions
        };
        let save_outcome = save_autoroute_cache(
            path,
            self.detector_digest,
            &self.rules_digest,
            self.config_digest,
            &self.host_profile,
            decisions,
        )
        .map_err(AutorouteRoutingError::calibration_not_persisted)?;
        match save_outcome {
            AutorouteCacheSaveOutcome::Replaced { reason } => eprintln!(
                "warning: replaced existing autoroute cache {}: {reason}",
                path.display()
            ),
            AutorouteCacheSaveOutcome::Fresh | AutorouteCacheSaveOutcome::Merged => {}
        }
        if self.calibration_mode {
            if let Some(runtime_health) = self.runtime_health.as_ref() {
                clear_runtime_route_faults(runtime_health, self.measured_this_run.iter())
                    .map_err(AutorouteRoutingError::calibration_not_persisted)?;
                self.runtime_faults
                    .retain(|key, _| !self.measured_this_run.contains(key));
            }
        }
        if let Some(observer) = self.measurement_observer.as_ref() {
            let mut observed = observer
                .lock()
                .map_err(|_| AutorouteRoutingError::measurement_observer_unavailable())?;
            observed.extend(self.measured_this_run.iter().map(|key| {
                (
                    format!("{:016x}", self.config_digest),
                    host_identity_digest(&self.host_profile),
                    render_workload_key(key),
                )
            }));
        }
        self.cache_dirty = false;
        Ok(())
    }

    fn persist_cache_path(&self) -> Result<&std::path::Path, AutorouteRoutingError> {
        let Some(path) = self.cache_path.as_deref() else {
            let reason = match self.cache_load_error.as_deref() {
                Some(error) => error,
                None => {
                    "--autoroute-cache off / [system].autoroute_cache = \"off\" disables the autoroute cache"
                }
            };
            return Err(AutorouteRoutingError::calibration_not_persisted(reason));
        };
        Ok(path)
    }
}

fn load_persistent_autoroute_decisions(
    detector_digest: u64,
    rules_digest: &str,
    config_digest: u64,
    host_profile: &AutorouteHostProfile,
    cache_path: Result<Option<PathBuf>, String>,
) -> (
    Option<PathBuf>,
    HashMap<WorkloadKey, AutorouteDecision>,
    Option<String>,
) {
    let cache_path = match cache_path {
        Ok(cache_path) => cache_path,
        Err(error) => {
            return (None, HashMap::new(), Some(error));
        }
    };
    // Disabled cache (None) or a genuinely absent path: cold start, no error.
    let Some(configured_path) = cache_path.as_deref() else {
        return (cache_path, HashMap::new(), None);
    };
    let existing_path = match autoroute_cache_file_presence(configured_path) {
        Ok(true) => configured_path,
        Ok(false) => return (cache_path, HashMap::new(), None),
        Err(error) => {
            let message = format!(
                "cannot inspect autoroute cache path '{}': {error}. Fix the path permissions or parent storage and retry",
                configured_path.display()
            );
            return (cache_path, HashMap::new(), Some(message));
        }
    };
    if let Err(error) = host_profile.require_exact_identity() {
        let error = error.to_string();
        return (cache_path, HashMap::new(), Some(error));
    }
    let mut cache_load_error = None;
    let decisions = match load_autoroute_cache(
        existing_path,
        detector_digest,
        rules_digest,
        config_digest,
        host_profile,
    ) {
        Ok(decisions) => decisions,
        Err(error) => {
            let message = error.to_string();
            tracing::warn!(
                target: "keyhog::routing",
                path = %existing_path.display(),
                error = %message,
                "autoroute cache ignored"
            );
            cache_load_error = Some(message);
            HashMap::new()
        }
    };

    if !decisions.is_empty() {
        tracing::info!(
            target: "keyhog::routing",
            entries = decisions.len(),
            "loaded persistent autoroute cache"
        );
    }

    (cache_path, decisions, cache_load_error)
}

fn load_runtime_fault_map(
    identity: &RuntimeHealthIdentity,
    decisions: &HashMap<WorkloadKey, AutorouteDecision>,
) -> Result<HashMap<WorkloadKey, RuntimeRouteFault>, String> {
    let loaded = load_runtime_route_faults(identity)?;
    let mut faults = HashMap::with_capacity(loaded.len());
    for (key, fault) in loaded {
        let backend =
            keyhog_scanner::hw_probe::parse_backend_str(&fault.backend).ok_or_else(|| {
                format!(
                    "runtime route-health artifact names unknown backend {:?}",
                    fault.backend
                )
            })?;
        let decision_backend = decisions.get(&key).and_then(AutorouteDecision::backend);
        if decision_backend != Some(backend) {
            return Err(format!(
                "runtime route-health fault for [{}] names backend {}, but the current calibration decision names {}; recalibrate before scanning",
                render_workload_key(&key),
                backend.label(),
                decision_backend.map_or("no route", |backend| backend.label()),
            ));
        }
        faults.insert(
            key,
            RuntimeRouteFault {
                backend,
                reason: fault.reason,
            },
        );
    }
    Ok(faults)
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

pub(super) fn is_gpu_backend(backend: ScanBackend) -> bool {
    backend.is_gpu()
}

fn gpu_peer_identity(scanner: &CompiledScanner) -> Option<String> {
    let candidates = scanner.gpu_backend_candidates();
    if candidates
        .iter()
        .any(|candidate| candidate.available && !candidate.is_software && !candidate.is_eligible())
    {
        // An executable hardware peer with incomplete identity is an invalid
        // autoroute state. Preserve it as an invalid identity instead of
        // silently treating the peer as absent and trusting CPU-only evidence.
        return Some(String::new());
    }
    let acquired: Vec<_> = candidates
        .into_iter()
        .filter(|candidate| candidate.is_eligible())
        .collect();
    if acquired.is_empty() {
        return None;
    }
    let peers = acquired
        .into_iter()
        .map(|candidate| {
            Some((
                candidate.backend.label().to_string(),
                candidate.driver_id?.to_string(),
                candidate.driver_version?.to_string(),
                candidate.device_identity?,
                candidate.runtime_identity?,
            ))
        })
        .collect::<Option<Vec<(String, String, String, String, String)>>>();
    let Some(mut peers) = peers else {
        // An eligibility contract drift is an invalid identity, never evidence
        // that the GPU is absent. Host identity validation rejects this value.
        return Some(String::new());
    };
    peers.sort_unstable();
    (!peers.is_empty()).then(|| {
        serde_json::to_string(&peers)
            .expect("GPU peer identity contains only serializable string fields")
    })
}

fn eligible_backend_labels(scanner: &CompiledScanner, gpu_participates: bool) -> Vec<String> {
    let mut labels = vec![ScanBackend::CpuFallback.label().to_string()];
    if scanner.simd_backend_available() {
        labels.push(ScanBackend::SimdCpu.label().to_string());
    }
    if gpu_participates {
        labels.extend(
            scanner
                .gpu_backend_candidates()
                .into_iter()
                .filter(|candidate| candidate.is_eligible())
                .map(|candidate| candidate.backend.label().to_string()),
        );
    }
    labels.sort_unstable();
    labels.dedup();
    labels
}

pub(super) fn backend_requires_coalesced_batch_pipeline(
    explicit: Option<keyhog_scanner::hw_probe::ScanBackend>,
) -> bool {
    match explicit {
        Some(
            keyhog_scanner::hw_probe::ScanBackend::GpuCuda
            | keyhog_scanner::hw_probe::ScanBackend::GpuWgpu,
        ) => true,
        Some(keyhog_scanner::hw_probe::ScanBackend::SimdCpu)
        | Some(keyhog_scanner::hw_probe::ScanBackend::CpuFallback) => false,
        // `ScanBackend` is #[non_exhaustive]: an unknown future backend stays
        // on the coalesced batch pipeline, which selects/handles every backend,
        // rather than silently forcing the CPU fused filesystem path.
        Some(_) => true,
        None => false,
    }
}

#[doc(hidden)]
pub(crate) fn backend_requires_coalesced_batch_pipeline_for_test(
    explicit: Option<keyhog_scanner::hw_probe::ScanBackend>,
) -> bool {
    backend_requires_coalesced_batch_pipeline(explicit)
}

#[cfg(test)]
mod tests;
