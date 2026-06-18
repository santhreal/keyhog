//! Backend override parsing and calibrated batch backend selection.

mod calibration;
mod evidence;
mod host;
mod store;
mod workload;

use self::calibration::calibrate_fastest_correct_backend;
use self::evidence::AutorouteDecision;
use self::host::AutorouteHostProfile;
use self::store::{load_autoroute_cache, save_autoroute_cache};
use self::workload::{workload_key, WorkloadKey};
use keyhog_core::Chunk;
use keyhog_scanner::hw_probe::{HardwareCaps, ScanBackend};
use keyhog_scanner::CompiledScanner;
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

pub(super) const AUTOROUTE_CACHE_VERSION: u32 = 16;
pub(super) const AUTOROUTE_CALIBRATION_TRIALS: usize = 3;
pub(super) const AUTOROUTE_GPU_WARM_TRIALS: usize = AUTOROUTE_CALIBRATION_TRIALS - 1;

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
                 explicit scan controls; or pass an explicit `--backend <simd|cpu|gpu|megascan>` \
                 for diagnostics.",
                key.bytes_bucket,
                key.chunks_bucket,
                key.max_file_bucket,
                key.pattern_bucket,
                key.decode_density_bucket,
                key.source_class_hash,
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

    fn host_identity_unavailable(error: impl fmt::Display) -> Self {
        Self {
            message: format!(
                "autoroute host identity unavailable: {error}. Autoroute calibration must be \
                 tied to an exact host profile before it can prove fastest-correct routing. \
                 Fix host hardware probing and rerun `install.sh --calibrate` or \
                 `install.ps1 -Calibrate`; or pass an explicit `--backend <simd|cpu|gpu|megascan>` \
                 for diagnostics."
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
        let key = workload_key(batch, self.pattern_count);
        if let Some(backend) = self
            .decisions
            .get(&key)
            .and_then(AutorouteDecision::backend)
        {
            return Ok(backend);
        }
        Err(AutorouteRoutingError::missing_decision(
            key,
            &self.cache_path,
            &self.cache_load_error,
        ))
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
        let key = workload_key(batch, self.pattern_count);
        if let Some(decision) = self.decisions.get(&key) {
            if let Some(backend) = decision.backend() {
                return Ok(backend);
            }
        }

        if !self.calibration_mode {
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
        self.cache_dirty = true;
        self.save_cache()?;
        Ok(backend)
    }

    fn save_cache(&self) -> Result<(), AutorouteRoutingError> {
        if !self.cache_dirty {
            return Ok(());
        }
        let path = self.persist_cache_path()?;
        save_autoroute_cache(
            path,
            self.detector_digest,
            &self.rules_digest,
            self.config_digest,
            &self.host_profile,
            &self.decisions,
        )
        .map_err(AutorouteRoutingError::calibration_not_persisted)
    }

    fn persist_cache_path(&self) -> Result<&std::path::Path, AutorouteRoutingError> {
        let Some(path) = self.cache_path.as_deref() else {
            let reason = match self.cache_load_error.as_deref() {
                Some(error) => error,
                None => "--autoroute-cache off / [system].autoroute_cache = \"off\" disables the autoroute cache",
            };
            return Err(AutorouteRoutingError::calibration_not_persisted(reason));
        };
        Ok(path)
    }
}

impl Drop for MeasuredBackendRouter {
    fn drop(&mut self) {
        if let Err(error) = self.save_cache() {
            tracing::error!(
                target: "keyhog::routing",
                %error,
                "autoroute calibration cache write failed during router drop"
            );
        }
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
