//! Backend override parsing and calibrated batch backend selection.
//!
//! # Two routers, one decision source
//!
//! Backend choice splits by *when* it runs, never by guessing:
//!
//! - [`CachedBackendRouter`] drives normal scans. It reads install-time
//!   calibration evidence without benchmarking or writing. Invalid evidence
//!   returns an operator-visible routing error and leaves the batch unscanned.
//! - [`MeasuredBackendRouter`] drives explicit calibration (installer / backend
//!   maintenance). It probes candidate backends, proves output parity against a
//!   reference, times the survivors, and persists the fastest correct choice.
//!
//! Both honour an explicit `--backend` first; only then does the routing module
//! resolve a build that compiled exactly one backend (portable / single-feature).
//! Neither path silently substitutes.
//!
//! # Submodule map (one-way dependency DAG)
//!
//! ```text
//! backend.rs ── cached/measured routers, cache wiring, route quarantine
//!   ├─ calibration ── install-time probe/parity/timing measurement
//!   ├─ evidence ───── decision policy
//!   │    ├─ timing ─────── measured trials and confidence intervals
//!   │    └─ match_identity ─ secret-safe semantic parity proof
//!   ├─ routing ─────── selection values, recovery planning, operator errors
//!   ├─ store ──────── cache facade (schema v56)
//!   │    ├─ schema / artifact_identity / build_identity
//!   │    └─ codec / validation / persistence / inspection
//!   ├─ runtime_health ─ durable route quarantine and transactional snapshots
//!   ├─ host ───────── host identity captured in each calibration record
//!   └─ workload ───── workload bucketing + source-shape fingerprints
//! ```
//!
//! Low-level evidence, identity, and codec modules never import routers; only
//! [`inspect_autoroute_cache`] crosses the package boundary outward.

mod calibration;
mod evidence;
mod host;
mod routing;
mod runtime_health;
mod store;
mod workload;

use self::calibration::calibrate_fastest_correct_backend;
use self::evidence::AutorouteDecision;
use self::host::{host_identity_digest, AutorouteHostProfile};
#[cfg(test)]
use self::routing::sole_compiled_backend;
#[cfg(feature = "gpu")]
pub(crate) use self::routing::OrderedGpuSelection;
use self::routing::{
    automatic_recovery_plan, autoroute_required, direct_backend_selection,
    phase1_plan_for_selected_backend, resolve_persisted_route, AutorouteRuntimeClass,
    RuntimeRouteFault,
};
pub(crate) use self::routing::{
    AutorouteRoutingError, AutorouteRoutingErrorKind, BackendRecoveryPlan, BackendSelection,
    RuntimeRouteIdentity,
};
use self::runtime_health::{
    clear_runtime_route_faults, load_runtime_route_faults, persist_runtime_route_fault,
    RuntimeHealthIdentity,
};
use self::store::{
    autoroute_cache_file_presence, load_autoroute_cache, record_bucket_miss,
    record_calibration_reuse, record_hit, record_miss, save_autoroute_cache, AutorouteCacheMiss,
    AutorouteCacheSaveOutcome,
};
pub(crate) use self::store::{
    bind_autoroute_cache_to_execution_packs, inspect_autoroute_cache,
    load_execution_pack_generation_binding, render_missing_buckets,
    render_summary as render_cache_summary, snapshot as autoroute_cache_stats, AutorouteReadiness,
    StagedAutorouteCache,
};
pub(crate) use self::workload::{canonical_source_classes, source_route_class, SourceRouteClass};
use self::workload::{measurement_shape_evidence, render_workload_key, workload_key, WorkloadKey};
use keyhog_core::Chunk;
use keyhog_scanner::hw_probe::{HardwareCaps, ScanBackend};
use keyhog_scanner::CompiledScanner;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Canonical persisted receipt for one exact calibration representative. The
/// host dimension prevents an older shared-cache generation from proving this
/// host's calibration, and the shape digest prevents one retained point from
/// standing in for a different representative in the same workload class.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct AutorouteMeasurementReceipt {
    pub(crate) config_digest: String,
    pub(crate) host_identity: String,
    pub(crate) workload: String,
    pub(crate) measurement_shape_digest: String,
}

pub(crate) type AutorouteMeasurementObserver = Arc<Mutex<BTreeSet<AutorouteMeasurementReceipt>>>;

pub(crate) fn autoroute_engine_identity() -> String {
    store::current_engine_identity()
}

pub(crate) fn autoroute_executable_identity(
) -> Result<&'static str, Box<dyn std::error::Error + Send + Sync>> {
    store::current_executable_identity()
}

pub(crate) fn autoroute_gpu_artifact_identity(scanner: &CompiledScanner) -> Option<String> {
    gpu_peer_identity(scanner)
}

fn autoroute_detector_digest(rules_digest: &str) -> u64 {
    let mut hasher = crate::stable_hash::StableHasher::new("autoroute-detector-corpus");
    hasher.field_str("rules_digest", rules_digest);
    hasher.finish_u64()
}

// v57: GPU cache evidence distinguishes runtime-compiled programs, bound to
// the exact executable and detector corpus, from installer-owned sidecars
// bound to their authenticated manifest digest.
// v56: ordered device-set evidence authenticates the complete device identity,
// including name and PCI vendor/device ids, and rejects orphaned, partial, or
// mixed route bodies before selection.
// v54: GPU timing rows bind bounded resident pipeline depth, capability, and
// per-slot input/match capacities. Older rows cannot prove async slot parity.
// v53: GPU timing rows can authenticate a calibrated ordered physical-device
// set with exact topology, driver/runtime, capacity, workload weights, timing,
// and bounded resident budgets. Older rows cannot prove multi-device replay.
// v51: the resolved-config digest no longer hashes whether a calibration
// excluded an eligible GPU. The persisted host generation already carries that
// exactly, through `eligible_backends` and the full GPU device/runtime/driver
// identity, so hashing it again could only produce false misses, and on any
// host or build with no GPU candidate it produced one on every single run: a
// calibration wrote under a digest no scan would ever request. v50 caches hold
// decisions keyed by the old digest and are superseded on the version gate,
// which gives a clear "older schema" message instead of a config mismatch.
// v50: workload identity records exact phase-2 keyword-trigger density
// (triggered chunks, bytes, and hit count) so calibration rows cannot alias
// batches with equal byte/chunk/source buckets but radically different
// localized regex work. v49 caches lack these fields and are recalibrated.
// v49: the cache-level detector identity projects the canonical, pre-policy
// rules digest. Per-preset detector mutations remain isolated by config_digest,
// so all documented scan policies can coexist in one multi-config cache.
// v47: short warm trials use bounded repeated execution, and paired same-backend
// rounds retain shared host drift instead of requiring independent intervals.
// v46: every GPU timing and parity receipt binds the exact acquired execution
// peer, and replay materializes the selected route and rejects identity drift.
// v45: confidence separation and reported margins compare complete execution
// routes, including localization variants on the same backend. v44 could select
// a same-backend median without proving that exact plan fastest.
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
// v53: GPU-capable decisions bind the exact installer-owned artifact manifest
// and reject stale one-shot, persistent, receipt, or calibration-point routes.
// v52: every calibration generation can bind the authenticated manifest plus exact
// policy/backend pack identities. Pack replacement now invalidates routing evidence.
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
// v56: authenticated ordered-device routes include adapter name and PCI
// vendor/device identity. v55 routes lack those live-census bindings.
// v58: the workload key drops the content-derived dimensions (phase-1
// admission counts, phase-2 keyword trigger counts, decode candidate counts,
// per-source chunk/payload ratios and span buckets). Those are measurements of
// the scanned bytes, not properties of the workload class, so lookup, which is
// exact-match, missed on every real scan and failed closed with exit 2. v57
// keys carry them and cannot be compared against v58 keys.
pub(super) const AUTOROUTE_CACHE_VERSION: u32 = 58;
pub(super) const AUTOROUTE_CALIBRATION_TRIALS: usize = 7;
pub(super) const AUTOROUTE_ACCELERATOR_WARM_TRIALS: usize = AUTOROUTE_CALIBRATION_TRIALS - 1;

/// Persistent calibrated backend router.
///
/// Autoroute probes only in explicit calibration mode (installer or backend
/// maintenance). Cache hits are table lookups; invalid state fails closed.
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
    #[cfg(feature = "gpu")]
    ordered_device_sets: Mutex<HashMap<String, Arc<keyhog_scanner::gpu::AcquiredGpuDeviceSet>>>,
    runtime_health: Option<RuntimeHealthIdentity>,
}

/// Cache-only backend router for fused filesystem scans.
///
/// This never benchmarks or writes decisions; it only consumes install-time
/// calibration evidence. Missing or invalid buckets return a routing error.
pub(crate) struct CachedBackendRouter {
    pattern_count: usize,
    decode_workload_plan: keyhog_scanner::decode::DecodeWorkloadPlan,
    decisions: HashMap<WorkloadKey, AutorouteDecision>,
    cache_path: Option<PathBuf>,
    cache_load_error: Option<String>,
    runtime_class: AutorouteRuntimeClass,
    runtime_faults: Mutex<HashMap<WorkloadKey, RuntimeRouteFault>>,
    runtime_health: Option<RuntimeHealthIdentity>,
    #[cfg(feature = "gpu")]
    ordered_device_sets: Mutex<HashMap<String, Arc<keyhog_scanner::gpu::AcquiredGpuDeviceSet>>>,
}

/// Name why a bucket lookup could not be answered, in the order an operator has
/// to fix the causes in.
///
/// A rejected cache and an uncalibrated bucket both end in the same scalar
/// recovery, and before this distinction existed they were indistinguishable in
/// aggregate. They call for opposite actions: a rejected cache means the
/// persisted evidence does not belong to this binary, host, corpus or config
/// and recalibrating the bucket would not help, while an absent bucket means
/// the cache is valid and simply does not cover this workload yet.
fn lookup_miss_cause(
    cache_path: &Option<PathBuf>,
    cache_load_error: &Option<String>,
    bucket_present: bool,
) -> AutorouteCacheMiss {
    if cache_load_error.is_some() {
        return AutorouteCacheMiss::CacheRejected;
    }
    if cache_path.is_none() {
        return AutorouteCacheMiss::NoCacheConfigured;
    }
    if bucket_present {
        return AutorouteCacheMiss::RuntimeClassUnproved;
    }
    AutorouteCacheMiss::BucketAbsent
}

#[cfg(feature = "gpu")]
fn materialize_ordered_gpu_selection(
    cache: &Mutex<HashMap<String, Arc<keyhog_scanner::gpu::AcquiredGpuDeviceSet>>>,
    decision: &AutorouteDecision,
    measured_route: self::evidence::MeasuredRoute,
) -> Result<Option<Arc<OrderedGpuSelection>>, String> {
    let Some(route) = decision.ordered_device_route_for_route(measured_route) else {
        return Ok(None);
    };
    route.validate()?;
    if route
        .devices
        .iter()
        .any(|device| device.api.scan_backend() != measured_route.backend)
    {
        return Err(format!(
            "ordered GPU device set does not match selected {} route",
            measured_route.backend.label()
        ));
    }
    let identity = route.device_set_identity_digest();
    let mut cache = cache
        .lock()
        .map_err(|_| "ordered GPU device-set cache is unavailable after an internal panic")?;
    let acquired = if let Some(existing) = cache.get(&identity).cloned() {
        existing
    } else {
        if !cache.is_empty() {
            return Err(
                "autoroute decision names more than one resident GPU device set".to_string(),
            );
        }
        let acquired = Arc::new(keyhog_scanner::gpu::acquire_ordered_gpu_device_set(route)?);
        if acquired.device_set_identity_digest() != identity {
            return Err(
                "acquired GPU device set does not match its stable cache identity".to_string(),
            );
        }
        cache.insert(identity, acquired.clone());
        acquired
    };
    drop(cache);
    Ok(Some(Arc::new(OrderedGpuSelection {
        route: Arc::new(route.clone()),
        acquired,
    })))
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
        let detector_digest = autoroute_detector_digest(&rules_digest);
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
            #[cfg(feature = "gpu")]
            ordered_device_sets: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn for_persistent_runtime(mut self) -> Self {
        self.runtime_class = AutorouteRuntimeClass::Persistent;
        self
    }

    pub(crate) fn autoroute_state_is_invalid(&self) -> bool {
        autoroute_required() && (self.decisions.is_empty() || self.runtime_faults.is_poisoned())
    }

    pub(crate) fn autoroute_has_quarantined_routes(&self) -> bool {
        self.runtime_faults
            .lock()
            .map(|faults| !faults.is_empty())
            // LAW10: unavailable quarantine state is treated as invalid, the conservative state that blocks persisted routing rather than trusting it.
            .unwrap_or(true)
    }

    /// Exact peers selected by at least one validated persistent-runtime
    /// decision. Invalid autoroute state prevents daemon or watcher startup:
    /// no backend may be initialized as a substitute for missing evidence.
    pub(crate) fn persistent_routes(&self) -> Result<Vec<ScanBackend>, AutorouteRoutingError> {
        if self.autoroute_state_is_invalid() {
            let reason = self.cache_load_error.as_deref().unwrap_or_else(|| {
                if self.runtime_faults.is_poisoned() {
                    "autoroute runtime route-health state is unavailable after an internal panic"
                } else {
                    "no persisted autoroute decisions are available for persistent runtime startup"
                }
            });
            return Err(AutorouteRoutingError::calibration_not_persisted(reason));
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
        if let Some(selection) = direct_backend_selection(scanner, explicit, batch) {
            return Ok(selection);
        }
        let phase1_plan = scanner.phase1_admission_plan(batch);
        let key = match workload_key(
            batch,
            self.pattern_count,
            self.decode_workload_plan.clone(),
        ) {
            Ok(key) => key,
            Err(error) => {
                record_miss(AutorouteCacheMiss::WorkloadUnclassified);
                return Err(AutorouteRoutingError::incomplete_workload_evidence(error));
            }
        };
        let fault = match self.runtime_faults.lock() {
            Ok(faults) => faults.get(&key).cloned(),
            // LAW10: fails closed: poisoned route-health state invalidates autoroute until restart and recalibration.
            Err(_) => {
                record_miss(AutorouteCacheMiss::HealthUnavailable);
                return Err(AutorouteRoutingError::calibration_not_persisted(
                    "autoroute runtime route-health state is unavailable after an internal panic; restart KeyHog and rerun `keyhog calibrate-autoroute`",
                ));
            }
        };
        if let Some(fault) = fault {
            record_bucket_miss(AutorouteCacheMiss::RouteQuarantined, &key);
            return Err(AutorouteRoutingError::runtime_route_unhealthy(
                &key,
                self.runtime_class,
                &fault,
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
                record_bucket_miss(
                    lookup_miss_cause(
                        &self.cache_path,
                        &self.cache_load_error,
                        self.decisions.contains_key(&key),
                    ),
                    &key,
                );
                return Err(error);
            }
        };
        #[cfg(feature = "gpu")]
        let ordered_gpu = match self
            .decisions
            .get(&key)
            .ok_or_else(|| "persisted autoroute decision disappeared".to_string())
            .and_then(|decision| {
                materialize_ordered_gpu_selection(&self.ordered_device_sets, decision, route)
            }) {
            Ok(selection) => selection,
            Err(reason) => {
                record_bucket_miss(AutorouteCacheMiss::PeerIdentityChanged, &key);
                return Err(AutorouteRoutingError::calibration_not_persisted(reason));
            }
        };
        if route.backend.is_gpu() {
            #[cfg(feature = "gpu")]
            let identity_check = if ordered_gpu.is_some() {
                Ok(())
            } else {
                self.decisions
                    .get(&key)
                    .and_then(|decision| decision.peer_identity_for_route(route))
                    .ok_or_else(|| {
                        format!(
                            "persisted {} route has no single acquired GPU peer identity",
                            route.backend.label()
                        )
                    })
                    .and_then(|expected| {
                        scanner
                            .acquired_gpu_peer_identity(route.backend)
                            .map_err(|error| {
                                format!(
                                    "could not acquire persisted {} route peer: {error}",
                                    route.backend.label()
                                )
                            })
                            .and_then(|actual| {
                                (actual == expected).then_some(()).ok_or_else(|| {
                                    format!(
                                        "persisted {} route peer identity changed; expected {expected:?}, acquired {actual:?}",
                                        route.backend.label()
                                    )
                                })
                            })
                    })
            };
            #[cfg(not(feature = "gpu"))]
            let identity_check: Result<(), String> =
                Err("persisted GPU route cannot run without the CLI GPU feature".to_string());
            let pipeline_check: Result<(), String> = self
                .decisions
                .get(&key)
                .and_then(|decision| decision.gpu_pipeline_identity_for_route(route))
                .ok_or_else(|| {
                    format!(
                        "persisted {} route has no complete pipeline depth/capability evidence",
                        route.backend.label()
                    )
                })
                .and_then(|(expected_capability, expected_input, expected_matches)| {
                    #[cfg(feature = "gpu")]
                    {
                        let actual_capability = scanner
                            .gpu_resident_dispatch_capability(route.backend)
                            .map_err(|error| {
                                format!(
                                    "could not validate persisted {} pipeline capability: {error}",
                                    route.backend.label()
                                )
                            })?;
                        let (actual_input, actual_matches) = scanner
                            .gpu_resident_pipeline_slot_capacities(route.gpu_pipeline_depth)
                            .map_err(|error| {
                                format!(
                                    "could not validate persisted {} pipeline capacities: {error}",
                                    route.backend.label()
                                )
                            })?;
                        let actual_input = u64::try_from(actual_input).map_err(|_| {
                            "live GPU resident input capacity exceeds u64".to_string()
                        })?;
                        if actual_capability != expected_capability
                            || actual_input != expected_input
                            || actual_matches != expected_matches
                        {
                            return Err(format!(
                                "persisted {} pipeline evidence is stale; expected capability={expected_capability} input={expected_input} matches={expected_matches}, live capability={actual_capability} input={actual_input} matches={actual_matches}",
                                route.backend.label()
                            ));
                        }
                        Ok(())
                    }
                    #[cfg(not(feature = "gpu"))]
                    {
                        let _ = (
                            scanner,
                            expected_capability,
                            expected_input,
                            expected_matches,
                        );
                        Err("persisted GPU route cannot run without the CLI GPU feature".to_string())
                    }
                });
            let identity_check = identity_check.and(pipeline_check);
            if let Err(reason) = identity_check {
                record_bucket_miss(AutorouteCacheMiss::PeerIdentityChanged, &key);
                return Err(AutorouteRoutingError::calibration_not_persisted(reason));
            }
        }
        record_hit();
        Ok(BackendSelection {
            backend: route.backend,
            phase1_plan: Some(phase1_plan_for_selected_backend(
                scanner,
                route.backend,
                phase1_plan,
                batch,
            )),
            execution_route: route.execution_route(),
            recovery_plan: automatic_recovery_plan(
                self.decisions.get(&key),
                route.backend,
                self.runtime_class,
            )?,
            runtime_route: Some(RuntimeRouteIdentity { key }),
            #[cfg(feature = "gpu")]
            ordered_gpu,
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
            return Err(AutorouteRoutingError::recovery_receipt_backend_mismatch(
                recovery.failed_backend,
                selection.backend,
            ));
        }
        match self.runtime_faults.lock() {
            Ok(mut faults) => {
                faults.insert(
                    identity.key.clone(),
                    RuntimeRouteFault {
                        backend: recovery.failed_backend,
                        reason: recovery.reason.clone(),
                    },
                );
            }
            // LAW10: recovery remains recall-complete and this state loss is emitted unconditionally to stderr before execution continues.
            Err(_) => {
                eprintln!(
                    "keyhog: WARNING: recovered scan coverage is complete, but the in-process autoroute quarantine state is unavailable after an internal panic; restart KeyHog and run `keyhog calibrate-autoroute` before the next scan"
                );
                tracing::warn!(
                    target: "keyhog::routing",
                    "recovered findings retained without in-process autoroute quarantine"
                );
            }
        }
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
        let detector_digest = autoroute_detector_digest(&rules_digest);
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
            #[cfg(feature = "gpu")]
            ordered_device_sets: Mutex::new(HashMap::new()),
        }
    }

    pub(super) fn choose_with_plan(
        &mut self,
        scanner: &CompiledScanner,
        explicit: Option<ScanBackend>,
        batch: &[Chunk],
    ) -> Result<BackendSelection, AutorouteRoutingError> {
        if let Some(selection) = direct_backend_selection(scanner, explicit, batch) {
            return Ok(selection);
        }
        let phase1_plan = scanner.phase1_admission_plan(batch);
        let key = match workload_key(
            batch,
            self.pattern_count,
            self.decode_workload_plan.clone(),
        ) {
            Ok(key) => key,

            Err(error) => {
                if !self.calibration_mode {
                    record_miss(AutorouteCacheMiss::WorkloadUnclassified);
                }
                return Err(AutorouteRoutingError::incomplete_workload_evidence(error));
            }
        };
        if !self.calibration_mode {
            if let Some(fault) = self.runtime_faults.get(&key) {
                record_bucket_miss(AutorouteCacheMiss::RouteQuarantined, &key);
                return Err(AutorouteRoutingError::runtime_route_unhealthy(
                    &key,
                    AutorouteRuntimeClass::OneShot,
                    fault,
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
            if self.calibration_mode {
                record_calibration_reuse();
            } else {
                record_hit();
            }
            #[cfg(feature = "gpu")]
            let ordered_gpu = materialize_ordered_gpu_selection(
                &self.ordered_device_sets,
                self.decisions.get(&key).ok_or_else(|| {
                    AutorouteRoutingError::calibration_not_persisted(
                        "reusable autoroute decision disappeared",
                    )
                })?,
                route,
            )
            .map_err(AutorouteRoutingError::calibration_not_persisted)?;
            return Ok(BackendSelection {
                backend: route.backend,
                phase1_plan: Some(phase1_plan_for_selected_backend(
                    scanner,
                    route.backend,
                    phase1_plan,
                    batch,
                )),
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
                #[cfg(feature = "gpu")]
                ordered_gpu,
            });
        }

        if !self.calibration_mode {
            // A miss is invalid autoroute state. Neighbouring evidence and
            // scalar execution are not substitutes for the missing decision.
            let route = match resolve_persisted_route(
                &self.decisions,
                key.clone(),
                AutorouteRuntimeClass::OneShot,
                &self.cache_path,
                &self.cache_load_error,
            ) {
                Ok(route) => route,
                Err(error) => {
                    record_bucket_miss(
                        lookup_miss_cause(
                            &self.cache_path,
                            &self.cache_load_error,
                            self.decisions.contains_key(&key),
                        ),
                        &key,
                    );
                    return Err(error);
                }
            };
            #[cfg(feature = "gpu")]
            let ordered_gpu = materialize_ordered_gpu_selection(
                &self.ordered_device_sets,
                self.decisions.get(&key).ok_or_else(|| {
                    AutorouteRoutingError::calibration_not_persisted(
                        "persisted autoroute decision disappeared",
                    )
                })?,
                route,
            )
            .map_err(AutorouteRoutingError::calibration_not_persisted)?;
            record_hit();
            return Ok(BackendSelection {
                backend: route.backend,
                phase1_plan: Some(phase1_plan_for_selected_backend(
                    scanner,
                    route.backend,
                    phase1_plan,
                    batch,
                )),
                execution_route: route.execution_route(),
                recovery_plan: automatic_recovery_plan(
                    self.decisions.get(&key),
                    route.backend,
                    AutorouteRuntimeClass::OneShot,
                )?,
                runtime_route: Some(RuntimeRouteIdentity { key }),
                #[cfg(feature = "gpu")]
                ordered_gpu,
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
        let workload_identity = render_workload_key(&key);
        let config_digest = format!("{:016x}", self.config_digest);
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
            &workload_identity,
            &self.rules_digest,
            &config_digest,
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
            self.measured_this_run.insert(key.clone());
        }
        #[cfg(feature = "gpu")]
        let ordered_gpu = materialize_ordered_gpu_selection(
            &self.ordered_device_sets,
            self.decisions.get(&key).ok_or_else(|| {
                AutorouteRoutingError::calibration_not_persisted(
                    "newly calibrated autoroute decision disappeared",
                )
            })?,
            route,
        )
        .map_err(AutorouteRoutingError::calibration_not_persisted)?;
        self.cache_dirty = true;
        Ok(BackendSelection {
            backend: route.backend,
            phase1_plan: Some(phase1_plan_for_selected_backend(
                scanner,
                route.backend,
                phase1_plan,
                batch,
            )),
            execution_route: route.execution_route(),
            recovery_plan: None,
            runtime_route: None,
            #[cfg(feature = "gpu")]
            ordered_gpu,
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
            return Err(AutorouteRoutingError::recovery_receipt_backend_mismatch(
                recovery.failed_backend,
                selection.backend,
            ));
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
            let config_digest = format!("{:016x}", self.config_digest);
            let host_identity = host_identity_digest(&self.host_profile);
            for key in &self.measured_this_run {
                let decision = self.decisions.get(key).ok_or_else(|| {
                    AutorouteRoutingError::calibration_not_persisted(
                        "autoroute measurement observer could not find a measured workload decision",
                    )
                })?;
                let workload = render_workload_key(key);
                observed.retain(|receipt| {
                    receipt.config_digest != config_digest
                        || receipt.host_identity != host_identity
                        || receipt.workload != workload
                });
                for point in &decision.calibration_points {
                    observed.insert(AutorouteMeasurementReceipt {
                        config_digest: config_digest.clone(),
                        host_identity: host_identity.clone(),
                        workload: workload.clone(),
                        measurement_shape_digest: keyhog_core::hex_encode(
                            &point.measurement_shape.shape_digest,
                        ),
                    });
                }
            }
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
        // LAW10: fail-closed; impossible peer-identity serialization failure aborts instead of persisting an unbound route key.
        serde_json::to_string(&peers).unwrap_or_else(|e| {
            panic!("GPU peer identity contains only serializable string fields: {e}")
        })
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
            | keyhog_scanner::hw_probe::ScanBackend::GpuMetal
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
#[path = "../../../tests/unit/orchestrator_dispatch_backend/mod.rs"]
mod tests;
