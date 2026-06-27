//! Backend override parsing and calibrated batch backend selection.

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

// v20: multi-config cache schema — shared binary/host/corpus identity once at
// the top, per-resolved-config routing decisions under `configs` keyed by
// config_digest, merge-on-save. Old single-config (v19 and earlier) caches are
// rejected on the version gate and recalibrated.
pub(super) const AUTOROUTE_CACHE_VERSION: u32 = 20;
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
}

#[derive(Debug, Clone)]
pub(crate) struct AutorouteRoutingError {
    message: String,
}

impl AutorouteRoutingError {
    fn missing_decision(
        key: WorkloadKey,
        cache_path: &Option<PathBuf>,
        cache_load_error: &Option<String>,
    ) -> Self {
        let cache_state = autoroute_cache_state(cache_path, cache_load_error);
        Self {
            message: format!(
                "autoroute calibration required: no persisted fastest-correct backend decision \
                 exists for workload bucket bytes_log2={} chunks_log2={} max_file_log2={} \
                 patterns_log2={} decode_density_log2={} source_hash={:016x}. {cache_state}. \
                 Normal auto scans never benchmark, guess, or substitute CPU/SIMD/GPU for a \
                 missing decision. Run \
                 `install.sh --calibrate` on Unix or `install.ps1 -Calibrate` on Windows for \
                 this binary, host, detector corpus, resolved scan config, source class, and \
                 explicit scan controls; or pass an explicit `--backend <{}>` \
                 for diagnostics.",
                key.bytes_bucket,
                key.chunks_bucket,
                key.max_file_bucket,
                key.pattern_bucket,
                key.decode_density_bucket,
                key.source_class_hash,
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
        let host_profile = AutorouteHostProfile::from_caps(&hw_caps, runtime_status.gpu_backend);
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
        }
    }

    pub(crate) fn choose(
        &self,
        explicit: Option<ScanBackend>,
        batch: &[Chunk],
    ) -> Result<ScanBackend, AutorouteRoutingError> {
        if let Some(forced) = explicit {
            return Ok(forced);
        }
        let key = workload_key(batch, self.pattern_count)
            .map_err(AutorouteRoutingError::incomplete_workload_evidence)?;
        match store::resolve_bucket(&self.decisions, &key) {
            store::BucketResolution::Exact(backend) => Ok(backend),
            store::BucketResolution::Interpolated { backend, lo, hi } => {
                note_interpolated_route(&key, backend, &lo, &hi);
                Ok(backend)
            }
            store::BucketResolution::Unresolved => Err(AutorouteRoutingError::missing_decision(
                key,
                &self.cache_path,
                &self.cache_load_error,
            )),
        }
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
        let host_profile = AutorouteHostProfile::from_caps(&hw_caps, runtime_status.gpu_backend);
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
        let key = workload_key(batch, self.pattern_count)
            .map_err(AutorouteRoutingError::incomplete_workload_evidence)?;
        if let Some(backend) = self.reusable_decision_backend(&key) {
            return Ok(backend);
        }

        if !self.calibration_mode {
            // Not calibrating: behave like the cache-only router — an exact miss
            // may still resolve by sound CPU-class interpolation before failing
            // closed (the exact lookup above already missed).
            if let store::BucketResolution::Interpolated { backend, lo, hi } =
                store::resolve_bucket(&self.decisions, &key)
            {
                note_interpolated_route(&key, backend, &lo, &hi);
                return Ok(backend);
            }
            return Err(AutorouteRoutingError::missing_decision(
                key,
                &self.cache_path,
                &self.cache_load_error,
            ));
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
    let mut cache_load_error = None;
    if !matches!(cache_path.as_ref(), Some(path) if path.exists()) {
        return (cache_path, HashMap::new(), None);
    }
    if let Err(error) = host_profile.require_exact_identity() {
        cache_load_error = Some(error.to_string());
        return (cache_path, HashMap::new(), cache_load_error);
    }
    let decisions = match cache_path.as_ref() {
        Some(path) if path.exists() => {
            match load_autoroute_cache(
                path,
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
                        path = %path.display(),
                        error = %message,
                        "autoroute cache ignored"
                    );
                    cache_load_error = Some(message);
                    HashMap::new()
                }
            }
        }
        _ => HashMap::new(),
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

/// Surface a sound CPU-class bucket interpolation LOUDLY (Law 10): the route was
/// not directly calibrated but resolved from two agreeing calibrated neighbours.
/// Recall-safe (CPU backends return identical findings at any input size) and
/// recorded — never a silent fallback. Fires once per process so a many-file or
/// daemon scan does not spam stderr per batch.
fn note_interpolated_route(
    key: &WorkloadKey,
    backend: ScanBackend,
    lo: &WorkloadKey,
    hi: &WorkloadKey,
) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static WARNED: AtomicBool = AtomicBool::new(false);
    if WARNED.swap(true, Ordering::Relaxed) {
        return;
    }
    eprintln!(
        "keyhog: autoroute workload bucket [{}] was not directly calibrated; resolved to {} by \
         interpolation between two agreeing calibrated CPU-class buckets [{}] and [{}]. This is \
         recall-safe (CPU backends return identical findings at any input size) but run \
         `install.sh --calibrate` / `install.ps1 -Calibrate` for an exact decision. (Further \
         interpolations this run are not repeated.)",
        store::render_workload_key(key),
        backend.label(),
        store::render_workload_key(lo),
        store::render_workload_key(hi),
    );
}

pub(super) fn is_gpu_backend(backend: ScanBackend) -> bool {
    matches!(backend, ScanBackend::Gpu | ScanBackend::MegaScan)
}

pub(super) fn backend_requires_coalesced_batch_pipeline(
    explicit: Option<keyhog_scanner::hw_probe::ScanBackend>,
) -> bool {
    match explicit {
        Some(keyhog_scanner::hw_probe::ScanBackend::Gpu)
        | Some(keyhog_scanner::hw_probe::ScanBackend::MegaScan) => true,
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
