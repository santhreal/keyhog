//! Backend override parsing and calibrated batch backend selection.
//!
//! # Two routers, one decision source
//!
//! Backend choice splits by *when* it runs, never by guessing:
//!
//! - [`CachedBackendRouter`] drives normal scans. It only reads install-time
//!   calibration evidence — zero benchmarks, zero writes. A bucket the
//!   installer never measured is an [`AutorouteRoutingError`], not a runtime
//!   probe or a substitute backend.
//! - [`MeasuredBackendRouter`] drives explicit calibration (installer / backend
//!   maintenance). It probes candidate backends, proves output parity against a
//!   reference, times the survivors, and persists the fastest correct choice.
//!
//! Both honour an explicit `--backend` first; only then does
//! [`sole_compiled_backend`] resolve a build that compiled exactly one backend
//! (portable / single-feature). Neither path silently substitutes — a miss
//! fails closed (Law 10).
//!
//! # Submodule map (one-way dependency DAG)
//!
//! ```text
//! backend.rs ── routers, override parsing, single-backend resolution
//!   ├─ calibration ── install-time probe/parity/timing measurement
//!   └─ store ──────── on-disk cache schema (v20), load/validate/merge-save
//!        depend on ↓
//!   ├─ evidence ───── timing records, AutorouteDecision, correctness digests
//!   ├─ host ───────── host identity captured in each calibration record
//!   └─ workload ───── workload bucketing + source-shape fingerprints
//! ```
//!
//! Leaves (`evidence`, `host`, `workload`) never import upward; only
//! [`inspect_autoroute_cache`] crosses the module boundary outward.

mod calibration;
mod evidence;
mod host;
mod store;
mod workload;

use self::calibration::calibrate_fastest_correct_backend;
use self::evidence::AutorouteDecision;
use self::host::AutorouteHostProfile;
pub(crate) use self::store::inspect_autoroute_cache;
use self::store::{load_autoroute_cache, save_autoroute_cache};
use self::workload::{workload_key, WorkloadClassificationError, WorkloadKey};
use keyhog_core::Chunk;
use keyhog_scanner::hw_probe::{HardwareCaps, ScanBackend};
use keyhog_scanner::CompiledScanner;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;

// v21: primary-evidence-only decision schema — `AutorouteDecision` persists just
// the measured timing evidence (simd/cpu/gpu) plus backend/sample/digest; every
// derived value (per-backend ms, GPU cold/warm/route, selected margin) is computed
// on load via accessors instead of stored, so a cache can never hold a value
// inconsistent with its own evidence (the whole cross-field-mismatch validation
// class is gone). v20 caches carry the now-removed denormalized fields and are
// rejected on the version gate and recalibrated.
// v20: multi-config cache schema — shared binary/host/corpus identity once at
// the top, per-resolved-config routing decisions under `configs` keyed by
// config_digest, merge-on-save. Old single-config (v19 and earlier) caches are
// rejected on the version gate and recalibrated.
pub(super) const AUTOROUTE_CACHE_VERSION: u32 = 21;
pub(super) const AUTOROUTE_CALIBRATION_TRIALS: usize = 7;
pub(super) const AUTOROUTE_GPU_WARM_TRIALS: usize = AUTOROUTE_CALIBRATION_TRIALS - 1;

fn backend_override_hint() -> String {
    keyhog_scanner::hw_probe::BACKEND_OVERRIDE_VALUES.join("|")
}

/// Persistent calibrated backend router.
///
/// Autoroute probes only in explicit calibration mode (installer / backend
/// maintenance). Cache hits are zero-benchmark table lookups; cache misses in
/// normal scans fail before scanning instead of guessing a substitute backend.
pub(super) struct MeasuredBackendRouter {
    hw_caps: HardwareCaps,
    pattern_count: usize,
    detector_digest: u64,
    rules_digest: String,
    config_digest: u64,
    autoroute_gpu: bool,
    calibration_mode: bool,
    host_profile: AutorouteHostProfile,
    decisions: HashMap<WorkloadKey, AutorouteDecision>,
    measured_this_run: HashSet<WorkloadKey>,
    cache_path: Option<PathBuf>,
    cache_load_error: Option<String>,
    cache_dirty: bool,
}

/// Cache-only backend router for fused filesystem scans.
///
/// This never benchmarks or writes decisions; it only consumes install-time
/// calibration evidence. Missing buckets return an autoroute configuration
/// error, keeping normal scans free of runtime probes and backend guesses.
pub(crate) struct CachedBackendRouter {
    pattern_count: usize,
    decisions: HashMap<WorkloadKey, AutorouteDecision>,
    cache_path: Option<PathBuf>,
    cache_load_error: Option<String>,
    runtime_class: AutorouteRuntimeClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AutorouteRuntimeClass {
    OneShot,
    PersistentDaemon,
}

impl AutorouteRuntimeClass {
    fn label(self) -> &'static str {
        match self {
            Self::OneShot => "one-shot",
            Self::PersistentDaemon => "persistent-daemon",
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
        runtime_class: AutorouteRuntimeClass,
        cache_path: &Option<PathBuf>,
        cache_load_error: &Option<String>,
    ) -> Self {
        // Inverted pyramid: what happened, then the fix, then the forensics.
        // The bucket is rendered by `store::render_workload_key` — the ONE
        // rendering shared with `keyhog backend --autoroute`, so an operator can
        // match this refused bucket against calibrated buckets field-for-field.
        let cache_state = autoroute_cache_state(cache_path, cache_load_error);
        Self {
            message: format!(
                "autoroute calibration required: this workload has no persisted \
                 fastest-correct backend decision.\n  \
                 fix: run `keyhog calibrate-autoroute` (primes every scan-policy preset and \
                 workload bucket for this binary in place), or rerun `install.sh --calibrate` \
                 on Unix / `install.ps1 -Calibrate` on Windows.\n  \
                 workload bucket: [{}], runtime={}\n  \
                 cache: {cache_state}.\n  \
                 Decisions are scoped to this exact binary, host, detector corpus, resolved \
                 scan config, and source class. Normal auto scans never benchmark, guess, or \
                 substitute CPU/SIMD/GPU for a missing decision; pass an explicit \
                 `--backend <{}>` for a one-off diagnostic scan.",
                store::render_workload_key(&key),
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
                 {trial}. Autoroute cannot prove fastest-correct routing when the SIMD reference \
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
/// produce a decision such a build would request — so resolving the lone backend
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

impl CachedBackendRouter {
    pub(crate) fn new(
        hw_caps: HardwareCaps,
        pattern_count: usize,
        rules_digest: String,
        config_digest: u64,
        autoroute_cache_path: Result<Option<PathBuf>, String>,
        scanner: &CompiledScanner,
    ) -> Self {
        let runtime_status = scanner.runtime_status();
        let detector_digest = runtime_status.detector_digest;
        let host_profile = AutorouteHostProfile::from_caps(
            &hw_caps,
            runtime_status.gpu_backend,
            keyhog_scanner::hw_probe::gpu_backend_compiled(),
        );
        let (cache_path, decisions, cache_load_error) = load_persistent_autoroute_decisions(
            detector_digest,
            &rules_digest,
            config_digest,
            &host_profile,
            autoroute_cache_path,
        );

        Self {
            pattern_count,
            decisions,
            cache_path,
            cache_load_error,
            runtime_class: AutorouteRuntimeClass::OneShot,
        }
    }

    pub(crate) fn for_persistent_daemon(mut self) -> Self {
        self.runtime_class = AutorouteRuntimeClass::PersistentDaemon;
        self
    }

    pub(crate) fn choose(
        &self,
        explicit: Option<ScanBackend>,
        batch: &[Chunk],
    ) -> Result<ScanBackend, AutorouteRoutingError> {
        if let Some(forced) = explicit {
            return Ok(forced);
        }
        if let Some(only) = sole_compiled_backend() {
            return Ok(only);
        }
        let key = workload_key(batch, self.pattern_count)
            .map_err(AutorouteRoutingError::incomplete_workload_evidence)?;
        resolve_persisted_backend(
            &self.decisions,
            key,
            self.runtime_class,
            &self.cache_path,
            &self.cache_load_error,
        )
    }
}

/// Resolve an exact workload bucket against the persisted decision table and
/// fail closed on any miss. ONE owner for the lookup contract shared by
/// [`CachedBackendRouter::choose`] and the non-calibration branch of
/// [`MeasuredBackendRouter::choose`] — neither router may infer a backend from
/// neighbouring measurements.
fn resolve_persisted_backend(
    decisions: &HashMap<WorkloadKey, AutorouteDecision>,
    key: WorkloadKey,
    runtime_class: AutorouteRuntimeClass,
    cache_path: &Option<PathBuf>,
    cache_load_error: &Option<String>,
) -> Result<ScanBackend, AutorouteRoutingError> {
    let backend = decisions
        .get(&key)
        .and_then(|decision| match runtime_class {
            AutorouteRuntimeClass::OneShot => decision.backend(),
            AutorouteRuntimeClass::PersistentDaemon => decision.resolved_persistent_backend(),
        });
    match backend {
        Some(backend) => Ok(backend),
        None => Err(AutorouteRoutingError::missing_decision(
            key,
            runtime_class,
            cache_path,
            cache_load_error,
        )),
    }
}

impl MeasuredBackendRouter {
    pub(super) fn new(
        hw_caps: HardwareCaps,
        pattern_count: usize,
        rules_digest: String,
        config_digest: u64,
        autoroute_gpu: bool,
        calibration_mode: bool,
        autoroute_cache_path: Result<Option<PathBuf>, String>,
        scanner: &CompiledScanner,
    ) -> Self {
        let runtime_status = scanner.runtime_status();
        let detector_digest = runtime_status.detector_digest;
        let host_profile = AutorouteHostProfile::from_caps(
            &hw_caps,
            runtime_status.gpu_backend,
            keyhog_scanner::hw_probe::gpu_backend_compiled(),
        );
        let (cache_path, decisions, cache_load_error) = load_persistent_autoroute_decisions(
            detector_digest,
            &rules_digest,
            config_digest,
            &host_profile,
            autoroute_cache_path,
        );

        Self {
            hw_caps,
            pattern_count,
            detector_digest,
            rules_digest,
            config_digest,
            autoroute_gpu,
            calibration_mode,
            host_profile,
            decisions,
            measured_this_run: HashSet::new(),
            cache_path,
            cache_load_error,
            cache_dirty: false,
        }
    }

    pub(super) fn choose(
        &mut self,
        scanner: &CompiledScanner,
        explicit: Option<ScanBackend>,
        batch: &[Chunk],
    ) -> Result<ScanBackend, AutorouteRoutingError> {
        if let Some(forced) = explicit {
            return Ok(forced);
        }
        if let Some(only) = sole_compiled_backend() {
            return Ok(only);
        }
        let key = workload_key(batch, self.pattern_count)
            .map_err(AutorouteRoutingError::incomplete_workload_evidence)?;
        if let Some(backend) = self.reusable_decision_backend(&key) {
            return Ok(backend);
        }

        if !self.calibration_mode {
            // Not calibrating: behave like the cache-only router. Every miss is
            // an invalid autoroute state; neighbouring measurements are not
            // evidence for this workload identity.
            return resolve_persisted_backend(
                &self.decisions,
                key,
                AutorouteRuntimeClass::OneShot,
                &self.cache_path,
                &self.cache_load_error,
            );
        }
        self.host_profile
            .require_exact_identity()
            .map_err(AutorouteRoutingError::host_identity_unavailable)?;
        self.persist_cache_path()?;

        let decision = calibrate_fastest_correct_backend(
            scanner,
            &self.hw_caps,
            self.pattern_count,
            batch,
            self.autoroute_gpu,
        )?;
        let backend = match decision.backend() {
            Some(backend) => backend,
            None => {
                return Err(AutorouteRoutingError::calibration_not_persisted(
                    "calibration produced an unsupported backend label",
                ));
            }
        };
        self.decisions.insert(key, decision);
        self.measured_this_run.insert(key);
        self.cache_dirty = true;
        Ok(backend)
    }

    fn reusable_decision_backend(&self, key: &WorkloadKey) -> Option<ScanBackend> {
        if self.calibration_mode && !self.measured_this_run.contains(key) {
            return None;
        }
        self.decisions.get(key).and_then(AutorouteDecision::backend)
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
                .map(|(key, decision)| (*key, decision.clone()))
                .collect::<HashMap<_, _>>();
            &measured_decisions
        } else {
            &self.decisions
        };
        save_autoroute_cache(
            path,
            self.detector_digest,
            &self.rules_digest,
            self.config_digest,
            &self.host_profile,
            decisions,
        )
        .map_err(AutorouteRoutingError::calibration_not_persisted)?;
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
    // Disabled cache (None) or a not-yet-calibrated path: cold start, no error.
    let Some(existing_path) = cache_path.as_deref().filter(|path| path.exists()) else {
        return (cache_path, HashMap::new(), None);
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

fn autoroute_cache_state(
    cache_path: &Option<PathBuf>,
    cache_load_error: &Option<String>,
) -> String {
    if let Some(error) = cache_load_error {
        return format!("The autoroute cache or host identity was rejected: {error}");
    }
    match cache_path {
        Some(path) if path.exists() => format!(
            "The autoroute cache at {} is valid for this binary/host/config but does not cover \
             this workload bucket",
            path.display()
        ),
        Some(path) => format!("No autoroute cache file exists at {}", path.display()),
        None => "--autoroute-cache off / [system].autoroute_cache = \"off\" disables the autoroute cache".to_string(),
    }
}

pub(super) fn is_gpu_backend(backend: ScanBackend) -> bool {
    matches!(backend, ScanBackend::Gpu)
}

pub(super) fn backend_requires_coalesced_batch_pipeline(
    explicit: Option<keyhog_scanner::hw_probe::ScanBackend>,
) -> bool {
    match explicit {
        Some(keyhog_scanner::hw_probe::ScanBackend::Gpu) => true,
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
