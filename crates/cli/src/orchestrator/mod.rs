//! Core scanning orchestration logic for the KeyHog CLI.

mod allowlist;
pub(crate) use allowlist::load_rule_suppressor;
mod dispatch;
pub(crate) use dispatch::{
    automatic_backend_recovery_allowed, canonical_source_classes,
    record_completed_backend_recovery, record_completed_remote_autoroute_state_recovery,
    scan_selected_batch, AutorouteMeasurementReceipt, AutorouteStateRecovery, BackendRecoveryPlan,
    COALESCED_CHUNK_SCAN_CEILING_BYTES, COALESCED_CHUNK_SCAN_CEILING_MB,
};
mod postprocess;
pub(crate) mod reporting;
mod run;
mod streaming;
mod workflow_state;

use crate::args::ScanArgs;
use crate::orchestrator_config::{
    auto_discover_detectors, autoroute_config_digest, backend_override_cli_value,
    configure_threads, gpu_runtime_policy_from_args, load_effective_detector_corpus,
    parse_backend_override, resolve_scan_config, resolved_scan_config_for_scanner,
    validate_detector_mode_selection, validate_explicit_detector_path, DetectorCorpusProvenance,
    LoadedDetectorCorpus, ResolvedEngineRuntimeSettings, ResolvedScanConfig,
};
use crate::style;
use anyhow::{Context, Result};
use keyhog_core::{Chunk, DetectorSpec, MerkleLoadStatus, RawMatch, Source};
use keyhog_scanner::{CompiledScanner, GpuInitPolicy};
#[cfg(feature = "git")]
use std::path::PathBuf;
use std::sync::Arc;

fn collect_detector_signatures(detectors: &[DetectorSpec]) -> std::collections::HashSet<Arc<str>> {
    detectors
        .iter()
        .flat_map(|detector| {
            detector
                .patterns
                .iter()
                .map(|pattern| Arc::from(pattern.regex.as_str()))
        })
        .chain(detectors.iter().flat_map(|detector| {
            detector
                .companions
                .iter()
                .map(|companion| Arc::from(companion.regex.as_str()))
        }))
        .collect()
}
/// Remove explicitly disabled detectors and any detector whose `requires`
/// dependency becomes unavailable. Relations to removed detectors are pruned
/// from surviving owners because those targets cannot produce findings.
///
/// Unknown relation targets are preserved so corpus validation still rejects
/// misspelled or missing detector IDs instead of treating them as configuration.
fn filter_disabled_detectors(
    detectors: &mut Vec<DetectorSpec>,
    disabled_detectors: &std::collections::HashSet<String>,
) -> usize {
    let known_ids: std::collections::HashSet<String> = detectors
        .iter()
        .map(|detector| detector.id.clone())
        .collect();
    let mut removed: std::collections::HashSet<String> = disabled_detectors
        .intersection(&known_ids)
        .cloned()
        .collect();
    if removed.is_empty() {
        return 0;
    }

    let mut required_by: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for detector in detectors.iter() {
        for relation in &detector.detector_relations {
            if relation.kind == keyhog_core::DetectorRelationKind::Requires
                && known_ids.contains(&relation.detector_id)
            {
                required_by
                    .entry(relation.detector_id.clone())
                    .or_default()
                    .push(detector.id.clone());
            }
        }
    }

    let mut queue: std::collections::VecDeque<String> = removed.iter().cloned().collect();
    while let Some(target_id) = queue.pop_front() {
        if let Some(dependents) = required_by.get(&target_id) {
            for dependent_id in dependents {
                if removed.insert(dependent_id.clone()) {
                    queue.push_back(dependent_id.clone());
                }
            }
        }
    }

    let before = detectors.len();
    detectors.retain(|detector| !removed.contains(&detector.id));
    for detector in detectors.iter_mut() {
        detector
            .detector_relations
            .retain(|relation| !removed.contains(&relation.detector_id));
    }
    before - detectors.len()
}

/// Hosts with strictly less RAM than this are treated as low-RAM and get the
/// deep-decode scan limits below clamped down to avoid an OOM. 4 GiB, expressed
/// in MiB to compare directly against `HardwareCaps::total_memory_mb`.
const LOW_RAM_HOST_THRESHOLD_MB: u64 = 4096;
/// Low-RAM clamp for `max_matches_per_chunk`: the effective value is capped at
/// (never raised to) this on a low-RAM host.
const LOW_RAM_MAX_MATCHES_PER_CHUNK: usize = 500;
/// Low-RAM clamp for `max_decode_bytes` (256 KiB): the effective decode window
/// is capped at (never raised to) this on a low-RAM host.
const LOW_RAM_MAX_DECODE_BYTES: usize = 256 * 1024;

#[derive(Debug)]
pub(crate) struct GpuUnavailableError {
    diagnostic: String,
}

impl GpuUnavailableError {
    fn new(diagnostic: impl Into<String>) -> Self {
        Self {
            diagnostic: diagnostic.into(),
        }
    }
}

impl std::fmt::Display for GpuUnavailableError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.diagnostic)
    }
}

impl std::error::Error for GpuUnavailableError {}

const DAEMON_GPU_REMEDIATION: &str =
    "Run `keyhog backend --self-test` and repair the GPU driver/runtime, or start the daemon with `--backend simd` or `--backend cpu`.";

fn daemon_gpu_failure(diagnostic: impl std::fmt::Display) -> anyhow::Error {
    GpuUnavailableError::new(format!("{diagnostic} {DAEMON_GPU_REMEDIATION}")).into()
}

pub(crate) fn daemon_gpu_preflight_failure(diagnostic: String) -> anyhow::Error {
    let diagnostic = diagnostic.trim().trim_end_matches('.');
    daemon_gpu_failure(format_args!(
        "daemon start: required GPU preflight failed: {diagnostic}."
    ))
}

pub(crate) fn daemon_compile_failure(error: &keyhog_scanner::ScanError) -> anyhow::Error {
    match error {
        keyhog_scanner::ScanError::Gpu(diagnostic) => daemon_gpu_failure(format_args!(
            "daemon GPU initialization failed while compiling the scanner: {diagnostic}."
        )),
        _ => anyhow::anyhow!("daemon: compiling scanner from detector specs: {error}"),
    }
}

fn apply_host_runtime_limits(
    effective_config: &mut ResolvedScanConfig,
    hw: &keyhog_scanner::HardwareCaps,
) {
    effective_config.min_confidence = effective_config.scanner.min_confidence;
    effective_config.ml_enabled = effective_config.scanner.ml_enabled;

    let Some(mem_mb) = hw.total_memory_mb else {
        return;
    };
    if mem_mb >= LOW_RAM_HOST_THRESHOLD_MB {
        return;
    }

    let prev_matches = effective_config.scanner.max_matches_per_chunk;
    let prev_decode = effective_config.scanner.max_decode_bytes;
    let new_matches = prev_matches.min(LOW_RAM_MAX_MATCHES_PER_CHUNK);
    let new_decode = prev_decode.min(LOW_RAM_MAX_DECODE_BYTES);
    effective_config.scanner.max_matches_per_chunk = new_matches;
    effective_config.scanner.max_decode_bytes = new_decode;

    if new_matches != prev_matches || new_decode != prev_decode {
        static LOW_RAM_CAP_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        if LOW_RAM_CAP_WARNED.set(()).is_ok() {
            eprintln!(
                "keyhog: low-RAM host ({mem_mb} MiB < {LOW_RAM_HOST_THRESHOLD_MB}): capping scan limits to avoid OOM: max_decode_bytes {prev_decode} -> {new_decode}, max_matches_per_chunk {prev_matches} -> {new_matches}. Reduce scan scope or use a host with more memory; run `keyhog config --effective` to inspect the configured limits."
            );
        }
    }
}

fn persistent_runtime_requires_gpu(
    surface: &str,
    backend_override: Option<keyhog_scanner::ScanBackend>,
    gpu_required_by_route: bool,
) -> Result<bool> {
    match backend_override {
        None => Ok(gpu_required_by_route),
        Some(backend) if backend.is_gpu() && gpu_required_by_route => Ok(true),
        Some(backend) if backend.is_gpu() => Err(persistent_runtime_gpu_failure(
            surface,
            format!(
                "{surface} --backend {} cannot be honored: this build and host have no eligible physical GPU path.",
                backend.label()
            ),
        )),
        Some(keyhog_scanner::ScanBackend::SimdCpu | keyhog_scanner::ScanBackend::CpuFallback) => {
            Ok(false)
        }
        Some(unknown) => anyhow::bail!(
            "{surface} backend {unknown:?} is not supported by this KeyHog build; choose auto, gpu-cuda, gpu-wgpu, simd, or cpu"
        ),
    }
}

fn persistent_runtime_gpu_failure(
    surface: &str,
    diagnostic: impl std::fmt::Display,
) -> anyhow::Error {
    if surface == "daemon" {
        daemon_gpu_failure(diagnostic)
    } else {
        GpuUnavailableError::new(format!(
            "{diagnostic} Run `keyhog backend --self-test` and repair the GPU driver/runtime, or run `keyhog {surface} --backend simd` or `keyhog {surface} --backend cpu`."
        ))
        .into()
    }
}

fn validate_persistent_gpu_initialization(
    surface: &str,
    gpu_required: bool,
    gpu_ready: bool,
) -> Result<()> {
    if gpu_required && !gpu_ready {
        return Err(persistent_runtime_gpu_failure(
            surface,
            format_args!("{surface} GPU initialization failed: the detected physical GPU is unavailable or incompatible with the compiled scanner, driver, or runtime; refusing to announce readiness."),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn validate_persistent_gpu_warmup(
    surface: &str,
    gpu_required: bool,
    degrade_before: u64,
    degrade_after: u64,
) -> Result<()> {
    if gpu_required && degrade_after != degrade_before {
        return Err(persistent_runtime_gpu_failure(
            surface,
            format_args!("{surface} GPU warmup degraded before readiness; refusing to apply persistent warm autoroute evidence."),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn daemon_requires_gpu(
    backend_override: Option<keyhog_scanner::ScanBackend>,
    gpu_required_by_route: bool,
) -> Result<bool> {
    persistent_runtime_requires_gpu("daemon", backend_override, gpu_required_by_route)
}

#[cfg(test)]
fn validate_daemon_gpu_initialization(gpu_required: bool, gpu_ready: bool) -> Result<()> {
    validate_persistent_gpu_initialization("daemon", gpu_required, gpu_ready)
}

#[cfg(test)]
fn validate_daemon_gpu_warmup(
    gpu_required: bool,
    degrade_before: u64,
    degrade_after: u64,
) -> Result<()> {
    validate_persistent_gpu_warmup("daemon", gpu_required, degrade_before, degrade_after)
}

pub(crate) use postprocess::render_credential;
/// Offline (no-verify, no-network) structural metadata for a finding's
/// credential. Single source of truth shared by every scan-output route so the
/// JWT analysis and the offline-decoded AWS account ID never diverge by route.
///
/// `#[cfg(unix)]` because the sole external consumer is the daemon-socket scan
/// route (`subcommands::scan::finalize_for_report`), which is itself
/// `#[cfg(unix)]` (unix-domain sockets). Without this gate the re-export is an
/// unused import on Windows/non-unix targets. The function itself stays
/// available to `postprocess`'s own in-process routes on every platform.
#[cfg(unix)]
pub(crate) use postprocess::{
    dedup_for_report, skipped_findings_from_deduped, suppresses_allowlist_match,
    suppresses_test_fixture,
};

#[doc(hidden)]
pub(crate) use dispatch::backend_requires_coalesced_batch_pipeline_for_test;

// Test seam: the pure live-credential exit-code mapping used by `run()` to
// decide between EXIT_LIVE_CREDENTIALS (10) and EXIT_SUCCESS (0). Exposed
// crate-internally so the exit-code contract can be unit-tested via the
// `crate::testing` facade without spawning a scan.
#[doc(hidden)]
pub(crate) use run::scan_exit_code;

// Re-export the daemon request-profile renderer so the daemon scan route in
// `subcommands::scan` can surface isolated per-request measurements on the
// same operator profile surface as the in-process `--profile` report.
#[cfg(unix)]
pub(crate) use run::render_daemon_request_profile;

// Test seam: the completion-summary and progress-ticker renderers are pure
// formatting functions whose unit tests were relocated out of the `reporting`
// module (the `*_no_inline_tests` folder gates). They are exercised through the
// `crate::testing` facade, so re-export them crate-internally here under the
// established `#[doc(hidden)] pub(crate) use` seam pattern.
#[doc(hidden)]
pub(crate) use reporting::{
    fmt_secs, render_progress_bar, render_reporting_ticker_line, render_severity_line,
    render_ticker_line, render_verification_line, render_verification_ticker_line,
    verification_breakdown, TickerGuard,
};

pub(crate) use dispatch::{
    autoroute_engine_identity, autoroute_executable_identity, autoroute_gpu_artifact_identity,
    CachedBackendRouter,
};
pub(crate) use dispatch::{
    bind_autoroute_cache_to_execution_packs, inspect_autoroute_cache,
    load_execution_pack_generation_binding, AutorouteReadiness, StagedAutorouteCache,
};
pub(crate) use streaming::{scan_streaming_source, StreamingSourceEvent};

fn resolved_default_autoroute_config() -> ResolvedScanConfig {
    let mut resolved = resolved_scan_config_for_scanner(keyhog_scanner::ScannerConfig::default());
    // NOT `rayon::current_num_threads()`. That call CREATES Rayon's global
    // registry as a side effect, and this function runs on every daemon client
    // connect (warm_identity::client_identity) purely to compute an identity
    // digest. Claiming the pool there made the `--daemon=auto` in-process
    // fallback impossible: the retry could no longer build a KeyHog-owned pool,
    // so an incompatible or crashed daemon turned a scan into exit 2 with no
    // findings, right after the CLI announced the fallback. The helper reports
    // the same width without creating anything, so the digest is unchanged and
    // the `--daemon=mass` policy gate still matches the resolved scan config.
    resolved.threads = Some(crate::orchestrator_config::keyhog_worker_threads());
    resolved
}

pub(crate) fn autoroute_default_config_identity() -> String {
    format!(
        "{:016x}",
        autoroute_config_digest(&resolved_default_autoroute_config())
    )
}

fn router_gpu_participates(
    backend_override: Option<keyhog_scanner::ScanBackend>,
    runtime_policy: keyhog_scanner::gpu::GpuRuntimePolicy,
) -> bool {
    backend_override.map_or_else(
        || runtime_policy != keyhog_scanner::gpu::GpuRuntimePolicy::Disabled,
        keyhog_scanner::ScanBackend::is_gpu,
    )
}

fn select_router_hardware<T>(
    gpu_participates: bool,
    probe_gpu: impl FnOnce() -> T,
    probe_host: impl FnOnce() -> T,
) -> T {
    if gpu_participates {
        probe_gpu()
    } else {
        probe_host()
    }
}

fn probe_router_hardware(gpu_participates: bool) -> keyhog_scanner::hw_probe::HardwareCaps {
    select_router_hardware(
        gpu_participates,
        || keyhog_scanner::hw_probe::probe_hardware().clone(),
        keyhog_scanner::hw_probe::probe_host_hardware,
    )
}

pub(crate) fn probe_route_hardware(
    backend_override: Option<keyhog_scanner::ScanBackend>,
    runtime_policy: keyhog_scanner::gpu::GpuRuntimePolicy,
) -> keyhog_scanner::hw_probe::HardwareCaps {
    probe_router_hardware(router_gpu_participates(backend_override, runtime_policy))
}

pub(crate) fn cached_autoroute_router_for_default_config(
    scanner: &CompiledScanner,
    detectors: &[DetectorSpec],
    backend_override: Option<keyhog_scanner::ScanBackend>,
) -> CachedBackendRouter {
    let rules_digest = keyhog_core::hex_encode(&keyhog_core::compute_spec_hash(detectors));
    let resolved = resolved_default_autoroute_config();
    let gpu_participates = router_gpu_participates(backend_override, resolved.gpu_runtime_policy);
    cached_autoroute_router(
        scanner,
        rules_digest,
        autoroute_config_digest(&resolved),
        gpu_participates,
        crate::autoroute_cache_path::resolve_autoroute_cache_path(None),
    )
}

fn cached_autoroute_router(
    scanner: &CompiledScanner,
    rules_digest: String,
    config_digest: u64,
    gpu_participates: bool,
    autoroute_cache_path: Result<Option<std::path::PathBuf>, String>,
) -> CachedBackendRouter {
    let hw_caps = probe_router_hardware(gpu_participates);
    let pattern_count = scanner.runtime_status().pattern_count;
    CachedBackendRouter::new(
        hw_caps,
        pattern_count,
        rules_digest,
        config_digest,
        gpu_participates,
        autoroute_cache_path,
        scanner,
    )
}

/// The resolved post-scan suppression policy a [`DefaultScanRuntime`] applies so
/// `keyhog watch` honors the SAME `.keyhog.toml` / `.keyhogignore` pipeline as
/// `keyhog scan` (Law 10: watch must not silently un-suppress a finding that
/// scan would drop). Built once at setup from the resolved config plus the
/// loaded allowlist, and fed into the shared [`postprocess::MatchFilter`].
pub(crate) struct DefaultScanFilter {
    signatures: std::collections::HashSet<Arc<str>>,
    disabled_detectors: std::collections::HashSet<String>,
    detector_min_confidence: std::collections::HashMap<String, f64>,
    test_fixture_suppressions: crate::test_fixture_suppressions::TestFixtureSuppressions,
    no_suppress_test_fixtures: bool,
    min_confidence: f64,
    min_severity: Option<keyhog_core::Severity>,
    allowlist: keyhog_core::Allowlist,
}

/// Compose detector-declared confidence floors with operator overrides and
/// write the effective value back into the ACTIVE corpus before compilation.
/// The returned map is the same policy used by post-processing, so early engine
/// adjudication and final filtering cannot disagree. Operator entries win;
/// detector TOML values fill only missing ids. Both sources are validated at
/// their load boundaries, so this function never clamps or silently rewrites a
/// value.
fn compose_detector_min_confidence(
    detectors: &mut [DetectorSpec],
    mut floors: std::collections::HashMap<String, f64>,
) -> std::collections::HashMap<String, f64> {
    for detector in detectors.iter() {
        if let Some(floor) = detector.min_confidence {
            floors.entry(detector.id.clone()).or_insert(floor);
        }
    }
    for detector in detectors {
        if let Some(floor) = floors.get(&detector.id) {
            detector.min_confidence = Some(*floor);
        }
    }
    floors
}

pub(crate) struct DefaultScanRuntime {
    scanner: Arc<CompiledScanner>,
    router: CachedBackendRouter,
    detector_count: usize,
    /// Actual global Rayon worker count after fail-closed runtime
    /// configuration. Status surfaces report the observed pool instead of
    /// repeating intent.
    worker_threads: usize,
    /// Explicit backend forced by the caller (e.g. `keyhog watch --backend cpu`).
    /// `None` => use persisted autoroute evidence, with visible scalar recovery
    /// when that state is invalid. When `Some`, the per-file scan never consults
    /// the autoroute cache, so the runtime works on an uncalibrated binary.
    backend_override: Option<keyhog_scanner::ScanBackend>,
    /// True for unforced production autoroute unless GPU execution is required.
    /// Explicit, required, and calibration dispatches remain hard contracts.
    recover_automatic_backend_faults: bool,
    /// Resolved suppression filter. `None` for the daemon runtime (which does its
    /// own client-side finalize via `into_parts`); `Some` for `keyhog watch`,
    /// installed by [`setup_default_scan_runtime`].
    filter: Option<DefaultScanFilter>,
}

impl DefaultScanRuntime {
    pub(crate) fn new(
        scanner: Arc<CompiledScanner>,
        detectors: &[DetectorSpec],
        backend_override: Option<keyhog_scanner::ScanBackend>,
    ) -> Self {
        let router =
            cached_autoroute_router_for_default_config(&scanner, detectors, backend_override);
        Self::new_with_router(scanner, detectors, router).with_backend_override(backend_override)
    }

    fn new_with_router(
        scanner: Arc<CompiledScanner>,
        detectors: &[DetectorSpec],
        router: CachedBackendRouter,
    ) -> Self {
        Self {
            scanner,
            router,
            detector_count: detectors.len(),
            worker_threads: rayon::current_num_threads(),
            backend_override: None,
            recover_automatic_backend_faults: automatic_backend_recovery_allowed(
                None,
                false,
                keyhog_scanner::gpu::gpu_runtime_policy(),
            ),
            filter: None,
        }
    }

    /// Install the resolved `.keyhog.toml` / `.keyhogignore` suppression filter so
    /// `filter_and_resolve` routes matches through the exact `keyhog scan`
    /// pipeline before they are surfaced.
    pub(crate) fn with_filter(mut self, filter: DefaultScanFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Run scanner matches through the SAME filter + resolution pipeline
    /// `keyhog scan` uses (signatures, disabled detectors, test-fixture +
    /// self-scan suppression, allowlist, confidence floors, severity, match
    /// resolution, inline suppression). Fails closed if no filter was installed
    /// a missing filter is a wiring bug, never a silent "emit everything".
    pub(crate) fn filter_and_resolve(&self, matches: Vec<RawMatch>) -> Result<Vec<RawMatch>> {
        let Some(f) = self.filter.as_ref() else {
            anyhow::bail!(
                "internal: DefaultScanRuntime has no resolved suppression filter; \
                 setup_default_scan_runtime must install one before filtering matches"
            );
        };
        let filter = postprocess::MatchFilter {
            scanner: &self.scanner,
            signatures: &f.signatures,
            disabled_detectors: &f.disabled_detectors,
            test_fixture_suppressions: &f.test_fixture_suppressions,
            no_suppress_test_fixtures: f.no_suppress_test_fixtures,
            detector_min_confidence: &f.detector_min_confidence,
            min_confidence: f.min_confidence,
            min_severity: f.min_severity,
        };
        postprocess::filter_and_resolve_matches(&filter, matches, &f.allowlist)
    }

    /// Force a specific scan backend instead of the persisted autoroute decision,
    /// mirroring `keyhog scan --backend`. With an explicit backend the per-file
    /// scan never consults the autoroute calibration cache, so `keyhog watch`
    /// works on an uncalibrated binary and the autoroute error's `--backend`
    /// diagnostic advice is actionable for `watch` too.
    pub(crate) fn with_backend_override(
        mut self,
        backend: Option<keyhog_scanner::ScanBackend>,
    ) -> Self {
        self.backend_override = backend;
        self.recover_automatic_backend_faults = automatic_backend_recovery_allowed(
            backend,
            false,
            keyhog_scanner::gpu::gpu_runtime_policy(),
        );
        self
    }

    pub(crate) fn detector_count(&self) -> usize {
        self.detector_count
    }

    pub(crate) fn worker_threads(&self) -> usize {
        self.worker_threads
    }

    pub(crate) fn warm(&self) {
        self.scanner.warm();
    }

    /// Reject an explicit backend before a long-running surface announces
    /// readiness. Autoroute remains evidence-driven, while a diagnostic
    /// override must prove that its requested engine is usable now.
    fn validate_explicit_backend(&self, subcommand_name: &str) -> Result<()> {
        match self.backend_override {
            Some(backend) if backend.is_gpu() => {
                let eligible = self
                    .scanner
                    .gpu_backend_candidates()
                    .iter()
                    .any(|candidate| candidate.backend == backend && candidate.is_eligible())
                    && self.scanner.warm_backend(backend);
                if !eligible {
                    return Err(GpuUnavailableError::new(format!(
                        "{subcommand_name} --backend {} cannot be honored on this host/build; its GPU driver path is not ready. Run `keyhog backend --self-test`, use `--backend simd`, or use `--backend cpu`",
                        backend.label()
                    ))
                    .into());
                }
            }
            Some(keyhog_scanner::ScanBackend::SimdCpu) => {
                self.scanner.initialize_simd_backend().map_err(|error| {
                    anyhow::anyhow!(
                        "{subcommand_name} --backend simd cannot be honored because Hyperscan initialization failed: {error}. Run `keyhog backend --self-test` or choose --backend cpu"
                    )
                })?;
            }
            Some(keyhog_scanner::ScanBackend::CpuFallback) | None => {}
            Some(backend) => {
                anyhow::bail!(
                    "{subcommand_name} cannot validate the requested backend `{}` in this build",
                    backend.label()
                );
            }
        }
        Ok(())
    }

    /// Prepare the compile-once runtime for daemon semantics. Autoroute and an
    /// explicit GPU daemon require a proven warm accelerator before accepting
    /// requests; explicit CPU/SIMD daemons do not acquire an unused GPU route.
    pub(crate) fn prepare_persistent_daemon(
        self,
        backend_override: Option<keyhog_scanner::ScanBackend>,
    ) -> Result<Self> {
        self.prepare_persistent_runtime(backend_override, "daemon")
    }

    /// Prepare the foreground watcher as a warm compile-once runtime. Its
    /// repeated file events must consume persistent timing evidence rather than
    /// charging accelerator materialization to every save.
    pub(crate) fn prepare_persistent_watch(
        self,
        backend_override: Option<keyhog_scanner::ScanBackend>,
    ) -> Result<Self> {
        self.prepare_persistent_runtime(backend_override, "watch")
    }

    fn prepare_persistent_runtime(
        mut self,
        backend_override: Option<keyhog_scanner::ScanBackend>,
        surface: &'static str,
    ) -> Result<Self> {
        self.scanner.warm();
        let gpu_candidates = self.scanner.gpu_backend_candidates();
        let required_routes = match backend_override {
            Some(backend) => vec![backend],
            None => self
                .router
                .persistent_routes()
                .map_err(anyhow::Error::from)?,
        };
        let simd_required = required_routes.contains(&keyhog_scanner::ScanBackend::SimdCpu);
        if simd_required {
            self.scanner
                .initialize_simd_backend()
                .map_err(|error| {
                    anyhow::anyhow!(
                        "{surface} requires SIMD but Hyperscan initialization failed: {error}. Run `keyhog backend --self-test` or choose --backend cpu"
                    )
                })?;
        }
        let gpu_routes: Vec<_> = required_routes
            .iter()
            .copied()
            .filter(|backend| backend.is_gpu())
            .collect();
        let requested_gpu_is_eligible = match backend_override {
            Some(backend) if backend.is_gpu() => gpu_candidates
                .iter()
                .any(|candidate| candidate.backend == backend && candidate.is_eligible()),
            _ => !gpu_routes.is_empty(),
        };
        let gpu_must_be_ready =
            persistent_runtime_requires_gpu(surface, backend_override, requested_gpu_is_eligible)?;
        let gpu_ready = gpu_must_be_ready
            && !gpu_routes.is_empty()
            && gpu_routes
                .iter()
                .all(|backend| self.scanner.warm_backend(*backend));
        validate_persistent_gpu_initialization(surface, gpu_must_be_ready, gpu_ready)?;
        if gpu_must_be_ready {
            let warmup = keyhog_core::Chunk {
                data: format!("keyhog {surface} accelerator warmup\n").into(),
                metadata: keyhog_core::ChunkMetadata {
                    source_type: format!("{surface}-warmup").into(),
                    ..Default::default()
                },
            };
            self.scanner.clear_fragment_cache();
            for backend in &gpu_routes {
                self.scanner
                    .scan_chunks_with_backend(std::slice::from_ref(&warmup), *backend)?;
            }
            self.scanner.clear_fragment_cache();
        }
        tracing::info!(
            simd_initialized = self.scanner.simd_backend_initialized(),
            gpu_ready,
            selected_gpu_routes = ?gpu_routes,
            gpu_must_be_ready,
            surface,
            "persistent runtime backends initialized"
        );
        self.router = self.router.for_persistent_runtime();
        Ok(self)
    }

    pub(crate) fn scan_chunk(&self, chunk: &Chunk) -> Result<Vec<RawMatch>> {
        // Empty input has one exact backend-independent result. Avoid asking
        // autoroute for a workload key that cannot carry timing evidence and
        // keep empty daemon/watch chunks clean even on an uncalibrated host.
        if chunk.data.is_empty() {
            return Ok(Vec::new());
        }
        let selection = self.router.choose_with_plan(
            self.scanner.as_ref(),
            self.backend_override,
            std::slice::from_ref(chunk),
        )?;
        let backend = selection.backend;
        let batch = std::slice::from_ref(chunk);
        let outcome = scan_selected_batch(
            self.scanner.as_ref(),
            batch,
            backend,
            selection.phase1_plan.as_ref(),
            selection.execution_route,
            selection
                .recovery_plan
                .filter(|_| self.recover_automatic_backend_faults),
        )
        .with_context(|| {
            format!(
                "selected backend {} failed during single-chunk dispatch",
                backend.label()
            )
        })?;
        dispatch::record_profiled_batch_route(
            batch,
            self.backend_override
                .map_or("auto", keyhog_scanner::ScanBackend::label),
            &selection,
            &outcome,
        );
        if let Some(recovery) = outcome.recovery.as_ref() {
            self.router
                .quarantine_recovered_route(&selection, recovery)?;
        }
        if let Some(recovery) = selection.autoroute_recovery.as_ref() {
            dispatch::record_completed_autoroute_state_recovery(batch, backend, recovery);
        }
        Ok(outcome.per_chunk.into_iter().flatten().collect())
    }

    pub(crate) fn clear_fragment_cache(&self) {
        self.scanner.clear_fragment_cache();
    }

    pub(crate) fn into_parts(self) -> (Arc<CompiledScanner>, CachedBackendRouter) {
        (self.scanner, self.router)
    }
}

pub(crate) fn compile_default_scan_runtime(
    detectors: Vec<DetectorSpec>,
    backend_override: Option<keyhog_scanner::ScanBackend>,
    map_compile_error: impl FnOnce(&keyhog_scanner::ScanError) -> anyhow::Error,
) -> Result<DefaultScanRuntime> {
    let backend = backend_override.unwrap_or(keyhog_scanner::ScanBackend::CpuFallback); // LAW10: this compiler helper's absent diagnostic override means its declared CPU runtime; autoroute does not call this path.
    let detectors: Arc<[DetectorSpec]> = detectors.into();
    let scanner = Arc::new(
        CompiledScanner::compile_shared_with_gpu_policy_and_tuning(
            Arc::clone(&detectors),
            GpuInitPolicy::SelectedBackend(backend),
            &keyhog_scanner::ScannerTuningConfig::default(),
        )
        .map_err(|error| map_compile_error(&error))?,
    );
    Ok(DefaultScanRuntime::new(
        scanner,
        &detectors,
        backend_override,
    ))
}

/// Build the compile-once/scan-many runtime shared by `keyhog watch` and
/// `keyhog scan-system`, WITH the operator's `.keyhog.toml` fully resolved and
/// applied.
///
/// Historically this compiled the raw embedded corpus and never touched
/// `.keyhog.toml`, so both callers silently ignored configured exclusions,
/// confidence thresholds, and `[detector.<id>] enabled = false` toggles, a scan
/// and a watch of the same tree could disagree on what is a finding (Law 10).
/// Now it resolves the config via [`resolve_scan_config`] (rooted at
/// `filter_root`, matching scan's walk-up), drops disabled detectors before
/// compilation, and applies the resolved [`keyhog_scanner::ScannerConfig`] +
/// tuning to the scanner. When `filter_root` is `Some`, it additionally loads the
/// allowlist and installs a [`DefaultScanFilter`] so `filter_and_resolve` applies
/// the identical post-scan suppression pipeline `keyhog scan` uses.
/// `scan-system` passes `None`: it runs paranoid (ignores the local allowlist by
/// design) but still gets the resolved detector/scanner config.
pub(crate) fn setup_default_scan_runtime(
    detectors_path: &std::path::Path,
    detectors_cli_explicit: bool,
    cache_dir: Option<std::path::PathBuf>,
    threads: Option<usize>,
    backend_override: Option<keyhog_scanner::ScanBackend>,
    subcommand_name: &'static str,
    warm: bool,
    filter_root: Option<&std::path::Path>,
) -> Result<DefaultScanRuntime> {
    setup_default_scan_runtime_with_rayon_policy(
        detectors_path,
        detectors_cli_explicit,
        cache_dir,
        threads,
        backend_override,
        subcommand_name,
        warm,
        filter_root,
        RayonSetupPolicy::RequireKeyHogOwned,
    )
}

#[derive(Clone, Copy)]
enum RayonSetupPolicy {
    RequireKeyHogOwned,
    #[cfg(test)]
    ReuseTestHarnessPool,
}

#[cfg(test)]
/// Build the production persistent runtime while explicitly reusing the Rust
/// test harness pool. Production callers always require KeyHog-owned workers;
/// unit tests cannot reset Rayon's process-global pool after another test uses it.
pub(crate) fn setup_default_scan_runtime_for_test(
    detectors_path: &std::path::Path,
    detectors_cli_explicit: bool,
    cache_dir: Option<std::path::PathBuf>,
    threads: Option<usize>,
    backend_override: Option<keyhog_scanner::ScanBackend>,
    subcommand_name: &'static str,
    warm: bool,
    filter_root: Option<&std::path::Path>,
) -> Result<DefaultScanRuntime> {
    setup_default_scan_runtime_with_rayon_policy(
        detectors_path,
        detectors_cli_explicit,
        cache_dir,
        threads,
        backend_override,
        subcommand_name,
        warm,
        filter_root,
        RayonSetupPolicy::ReuseTestHarnessPool,
    )
}

fn setup_default_scan_runtime_with_rayon_policy(
    detectors_path: &std::path::Path,
    detectors_cli_explicit: bool,
    cache_dir: Option<std::path::PathBuf>,
    threads: Option<usize>,
    backend_override: Option<keyhog_scanner::ScanBackend>,
    subcommand_name: &'static str,
    warm: bool,
    filter_root: Option<&std::path::Path>,
    rayon_policy: RayonSetupPolicy,
) -> Result<DefaultScanRuntime> {
    use clap::Parser;
    crate::runtime_preflight::validate_scan_runtime_config()?;

    // Resolve `.keyhog.toml` exactly as `keyhog scan` does. A synthetic default
    // `ScanArgs` carries only what this runtime can honor (detector dir, cache
    // dir, threads, and the scan root that anchors config discovery); every other
    // field stays at its shipped default so the merge yields the same effective
    // config an equivalent `keyhog scan <root>` would. `resolve_scan_config`
    // also configures the Hyperscan cache dir and canary/trusted-dir globals.
    let mut synthetic = ScanArgs::try_parse_from(["keyhog-scan"]).context(
        "internal: constructing default ScanArgs for watch/scan-system config resolution",
    )?;
    synthetic.detectors = detectors_path.to_path_buf();
    synthetic.detectors_cli_explicit = detectors_cli_explicit;
    synthetic.cache_dir = cache_dir;
    synthetic.threads = threads;
    synthetic.backend = backend_override.map(|backend| backend_override_cli_value(backend).into());
    synthetic.path = filter_root.map(std::path::Path::to_path_buf);
    let mut effective_config = resolve_scan_config(&mut synthetic)?;
    let requested_detector_mode = synthetic.detectors_mode.map(Into::into);
    validate_detector_mode_selection(synthetic.detectors_cli_explicit, requested_detector_mode)?;
    validate_explicit_detector_path(&synthetic.detectors, synthetic.detectors_cli_explicit)?;
    let detectors_path = auto_discover_detectors(&synthetic.detectors)?;
    let detectors_path_for_compile = detectors_path.clone();
    ResolvedEngineRuntimeSettings::from(&effective_config).apply();

    let hw = keyhog_scanner::hw_probe::probe_hardware();
    let worker_threads = match rayon_policy {
        RayonSetupPolicy::RequireKeyHogOwned => {
            configure_threads(effective_config.threads, hw.physical_cores)?
        }
        #[cfg(test)]
        RayonSetupPolicy::ReuseTestHarnessPool => {
            let current = rayon::current_num_threads();
            if let Some(requested) = effective_config.threads {
                if requested != current {
                    anyhow::bail!(
                        "test harness Rayon pool has {current} threads, but the isolated runtime requested {requested}"
                    );
                }
            }
            current
        }
    };
    effective_config.threads = Some(worker_threads);
    apply_host_runtime_limits(&mut effective_config, &hw);
    keyhog_scanner::gpu::require_gpu_preflight().map_err(|diagnostic| {
        GpuUnavailableError::new(format!(
            "cannot start `{subcommand_name}` with the resolved GPU policy: {diagnostic}"
        ))
    })?;

    let mut detectors = load_effective_detector_corpus(
        &detectors_path,
        requested_detector_mode,
        !synthetic.lockdown,
    )
    .context("loading effective detector corpus")?
    .detectors;

    // Apply `[detector.<id>] enabled = false`: drop the disabled detectors before
    // compilation so they never fire (mirrors `ScanOrchestrator::new`).
    let disabled_detectors = effective_config.disabled_detectors.clone();
    if !disabled_detectors.is_empty() {
        let before = detectors.len();
        filter_disabled_detectors(&mut detectors, &disabled_detectors);
        if detectors.is_empty() && before > 0 {
            anyhow::bail!(
                "all {before} loaded detector(s) were disabled by .keyhog.toml \
                 [detector.<id>] enabled = false. Leave at least one detector enabled to run \
                 `{subcommand_name}`, or remove the config."
            );
        }
    }

    // Performance identity describes the active corpus before per-invocation
    // confidence floors are composed. The effective config digest below owns
    // those overrides, keeping detector identity stable across scan profiles.
    let rules_digest = keyhog_core::hex_encode(&keyhog_core::compute_spec_hash(&detectors));

    // Compose detector TOML defaults and operator overrides BEFORE compilation.
    // `watch` and `scan-system` use this runtime; compiling first would let the
    // engine irreversibly drop a finding under the old floor before the shared
    // post-scan filter could apply a lower operator override.
    let mut detector_min_confidence = compose_detector_min_confidence(
        &mut detectors,
        effective_config.detector_min_confidence.clone(),
    );
    if synthetic.precision {
        let floor = effective_config.scanner.min_confidence;
        for detector_floor in detector_min_confidence.values_mut() {
            *detector_floor = detector_floor.max(floor);
        }
        detector_min_confidence =
            compose_detector_min_confidence(&mut detectors, detector_min_confidence);
    }

    // Compile WITH the resolved engine config + tuning so thresholds (decode
    // window, entropy, min-confidence, ml gate) take effect, not the bare
    // compiled defaults the raw `compile()` would leave.
    let gpu_init_policy = gpu_init_policy_for_args(
        &synthetic,
        effective_config.autoroute_cache_path.as_deref(),
        effective_config.autoroute_gpu,
        effective_config.autoroute_calibration,
    );
    let scanner = Arc::new(
        CompiledScanner::compile_with_gpu_policy_and_tuning(
            detectors.clone(),
            gpu_init_policy,
            &effective_config.scanner_tuning,
        )
        .map_err(|error| {
            crate::orchestrator_config::detector_compile_failed(
                subcommand_name,
                &detectors_path_for_compile,
                &error,
            )
        })?
        .with_config(effective_config.engine_scanner_config())
        .with_tuning_config(effective_config.scanner_tuning.clone()),
    );

    let gpu_participates = router_gpu_participates(
        effective_config.backend_override,
        effective_config.gpu_runtime_policy,
    );
    let router = cached_autoroute_router(
        &scanner,
        rules_digest,
        autoroute_config_digest(&effective_config),
        gpu_participates,
        Ok(effective_config.autoroute_cache_path.clone()),
    );
    let mut scan_runtime = DefaultScanRuntime::new_with_router(scanner, &detectors, router)
        .with_backend_override(effective_config.backend_override);
    scan_runtime.validate_explicit_backend(subcommand_name)?;

    if let Some(root) = filter_root {
        let signatures = collect_detector_signatures(&detectors);
        let allowlist = allowlist::load_allowlist(Some(root), &effective_config.allowlist)?;
        let test_fixture_suppressions = if effective_config.report.no_suppress_test_fixtures {
            crate::test_fixture_suppressions::TestFixtureSuppressions::empty()
        } else {
            crate::test_fixture_suppressions::TestFixtureSuppressions::bundled()
        };
        scan_runtime = scan_runtime.with_filter(DefaultScanFilter {
            signatures,
            disabled_detectors,
            detector_min_confidence,
            test_fixture_suppressions,
            no_suppress_test_fixtures: effective_config.report.no_suppress_test_fixtures,
            min_confidence: effective_config.min_confidence,
            min_severity: effective_config
                .report
                .severity
                .as_ref()
                .map(|s| s.to_severity()),
            allowlist,
        });
    }

    drop(detectors);
    run::release_allocator_arenas_after_construction();

    if warm {
        scan_runtime.warm();
    }
    Ok(scan_runtime)
}

#[doc(hidden)]
pub(crate) fn router_gpu_participates_for_test(
    backend_override: Option<keyhog_scanner::ScanBackend>,
    runtime_policy: keyhog_scanner::gpu::GpuRuntimePolicy,
) -> bool {
    router_gpu_participates(backend_override, runtime_policy)
}

#[doc(hidden)]
pub(crate) fn router_uses_gpu_probe_for_test(gpu_participates: bool) -> bool {
    select_router_hardware(gpu_participates, || true, || false)
}

#[doc(hidden)]
pub(crate) fn gpu_init_policy_for_args_for_test(args: &ScanArgs) -> GpuInitPolicy {
    gpu_init_policy_for_args(
        args,
        None,
        args.autoroute_gpu && !args.no_autoroute_gpu,
        args.autoroute_calibrate,
    )
}

#[doc(hidden)]
pub(crate) fn gpu_init_policy_for_resolved_autoroute_for_test(
    args: &ScanArgs,
    autoroute_cache_path: Option<&std::path::Path>,
    autoroute_gpu: bool,
    autoroute_calibration: bool,
) -> GpuInitPolicy {
    gpu_init_policy_for_args(
        args,
        autoroute_cache_path,
        autoroute_gpu,
        autoroute_calibration,
    )
}

#[doc(hidden)]
pub(crate) fn explicit_backend_override(
    raw: Option<&str>,
) -> Result<Option<keyhog_scanner::ScanBackend>> {
    parse_backend_override(raw)
}

#[doc(hidden)]
pub(crate) fn allowlist_root_for_test(path: &std::path::Path) -> std::path::PathBuf {
    allowlist::allowlist_root(path)
}

#[doc(hidden)]
pub(crate) fn scanner_panic_notice_for_test(panicked: bool) -> Option<String> {
    reporting::scanner_panic_notice(panicked)
}

#[doc(hidden)]
pub(crate) fn resolve_scan_exit_for_test(
    has_new_entries: bool,
    incremental_cache_failed: bool,
    source_coverage_incomplete: bool,
) -> u8 {
    run::resolve_scan_exit(run::ScanOutcome {
        has_new_entries,
        incremental_cache_failed,
        source_coverage_incomplete,
        ..run::ScanOutcome::default()
    })
}

fn execution_pack_policy_for_args(
    args: &ScanArgs,
) -> keyhog_scanner::execution_pack::ExecutionPackPolicy {
    use keyhog_scanner::execution_pack::ExecutionPackPolicy;
    if args.fast {
        ExecutionPackPolicy::Fast
    } else if args.deep {
        ExecutionPackPolicy::Deep
    } else if args.precision {
        ExecutionPackPolicy::Precision
    } else {
        ExecutionPackPolicy::Default
    }
}

pub(crate) struct ScanOrchestrator {
    pub(crate) args: ScanArgs,
    pub(crate) detector_count: usize,
    #[cfg(feature = "verify")]
    pub(crate) verifier_detectors: Option<Arc<[DetectorSpec]>>,
    pub(crate) detector_spec_hash: [u8; 32],
    pub(crate) detector_rules_digest: String,
    pub(crate) detector_corpus_digest: String,
    pub(crate) detector_corpus_provenance: DetectorCorpusProvenance,
    pub(crate) scanner: Arc<CompiledScanner>,
    pub(crate) signatures: std::collections::HashSet<Arc<str>>,
    pub(crate) test_fixture_suppressions: crate::test_fixture_suppressions::TestFixtureSuppressions,
    /// Detector ids disabled via `.keyhog.toml` `[detector.<id>] enabled = false`.
    /// Corpus detectors are dropped at load so they never compile. The shared
    /// post-filter retains the same exact-id guard for every runtime surface.
    pub(crate) disabled_detectors: std::collections::HashSet<String>,
    /// Per-detector confidence floors from `.keyhog.toml`
    /// `[detector.<id>] min_confidence = <f>`. Applied in `filter_and_resolve`:
    /// a finding from `<id>` below this threshold is dropped, overriding the
    /// global `--min-confidence`. Empty when no per-detector overrides are set.
    pub(crate) detector_min_confidence: std::collections::HashMap<String, f64>,
    /// Fully resolved scan policy used by the engine and post-processing.
    pub(crate) effective_config: ResolvedScanConfig,
    /// Optional receipt sink for the calibration command's exact persisted
    /// workload keys. Normal scans never install one.
    autoroute_measurement_observer: Option<dispatch::AutorouteMeasurementObserver>,
    /// Explicit CLI profiling starts before config resolution and scanner compilation.
    early_profile_session: Option<keyhog_profile::Session>,
    early_profile_build: Option<std::thread::JoinHandle<keyhog_profile::BuildIdentityV2>>,
}

impl ScanOrchestrator {
    pub(crate) fn new(mut args: ScanArgs) -> Result<Self> {
        let early_profile_session = if args.profile || args.profile_out.is_some() {
            let identity = keyhog_profile::RunIdentity::new(
                env!("CARGO_PKG_VERSION"),
                "pending-detector-corpus",
                "pending-config",
                "pending-source",
                "orchestrator-construction",
                "pending-backend-policy",
            );
            let session = keyhog_profile::Session::start(identity).map_err(anyhow::Error::new)?;
            crate::set_operator_profile_active(true);
            Some(session)
        } else {
            None
        };
        let early_profile_build = early_profile_session
            .as_ref()
            .map(|_| std::thread::spawn(run::profiler_build_identity));
        // Resolve the GPU runtime policy from the operator's explicit flags and
        // publish it BEFORE anything downstream can call `probe_hardware()`.
        // `probe_hardware()` is memoised and runs `gpu_probe()` on its first
        // call; with a non-Disabled policy that creates a wgpu/Vulkan instance
        // whose mesa driver worker thread SIGSEGVs during teardown if the
        // process then exits fast on an early setup error (an expired
        // `.keyhogignore`, a missing scan path) before the driver finishes
        // initialising. That turns a clean fail-closed `exit(2)` into a signal
        // death (exit 139). `--no-gpu`/`--backend cpu` never use the GPU, so
        // disabling the probe here both prevents that crash and skips a Vulkan
        // init the scan cannot use (Law 7). `resolve_scan_config` may refine the
        // policy from `.keyhog.toml`; the resolved engine-runtime settings
        // object publishes that refinement once the effective config is known.
        keyhog_scanner::gpu::set_gpu_runtime_policy(gpu_runtime_policy_from_args(&args));
        // Grep/wc/curl convention: a positional `-` means "read from
        // stdin". Some users will try `keyhog scan - --stdin <<<...`
        // and otherwise hit `error: path '-' does not exist`. Promote
        // bare `-` to `--stdin` and drop it from the path slot so the
        // existing stdin-reading source picks up. Falls through cleanly
        // when `--stdin` was already passed.
        let positional_stdin = args
            .input
            .iter()
            .any(|path| path == std::path::Path::new("-"));
        if positional_stdin && args.input.len() > 1 {
            anyhow::bail!(
                "stdin shorthand `-` cannot be combined with other positional scan roots; use either `keyhog scan -` or scan the filesystem roots without `-`"
            );
        }
        if positional_stdin || matches!(args.path.as_deref().and_then(|p| p.to_str()), Some("-")) {
            args.stdin = true;
            args.input.clear();
            args.path = None;
        }
        if args.path.is_none() {
            args.path = args.input.first().cloned();
        }
        #[cfg(feature = "git")]
        if args.git_staged && args.path.is_none() {
            args.path = Some(PathBuf::from("."));
        }
        // Fail fast on a non-existent/unreadable scan path BEFORE resolving the
        // config, which probes the GPU. A missing path validated only later
        // (inside `resolve_scan_roots`, during source construction) would have
        // already created the wgpu/Vulkan probe instance whose driver thread can
        // SIGSEGV on the fast error exit (see the GPU-policy note above). Hoisting
        // the check here makes a typo'd path fail instantly with a clean exit for
        // EVERY backend (autoroute included, where the probe is not disabled) and
        // skips a pointless hardware probe for a scan that cannot run (Law 7).
        // `resolve_scan_roots` re-validates during source construction; this runs
        // the SAME validator earlier, so the diagnostic and exit code are identical.
        if !args.stdin {
            for root in args.scan_roots() {
                crate::path_validation::validate_cli_path_arg(&root, "scan path")?;
            }
        }
        let mut effective_config = resolve_scan_config(&mut args)?;
        ResolvedEngineRuntimeSettings::from(&effective_config).apply();
        let disabled_detectors = effective_config.disabled_detectors.clone();
        // Operator `.keyhog.toml` `[detector.<id>] min_confidence` overrides;
        // detector self-declared floors (DetectorSpec::min_confidence, merged
        // below once the corpus is loaded) fill the gaps.
        let mut detector_min_confidence = effective_config.detector_min_confidence.clone();

        // `[lockdown] require = true` is a fail-closed security control: refuse
        // to run unless the operator consciously passed --lockdown. Previously
        // this config was parsed and silently ignored, so a repo that believed
        // it mandated lockdown ran unprotected (README documents it as active).
        if effective_config.require_lockdown && !args.lockdown {
            anyhow::bail!(
                ".keyhog.toml sets [lockdown] require = true, but --lockdown was not passed. \
                 Re-run with --lockdown to enforce the configured hardening, or remove the \
                 requirement from .keyhog.toml."
            );
        }

        let hw = {
            let _profile_span = keyhog_profile::span(keyhog_profile::Stage::BackendAcquire);
            keyhog_scanner::hw_probe::probe_hardware()
        };
        let worker_threads = configure_threads(args.threads, hw.physical_cores)?;
        args.threads = Some(worker_threads);
        effective_config.threads = Some(worker_threads);

        let (requested_detector_mode, detectors_path) = {
            let _profile_span = keyhog_profile::span(keyhog_profile::Stage::DetectorValidate);
            let requested_detector_mode = args.detectors_mode.map(Into::into);
            validate_detector_mode_selection(args.detectors_cli_explicit, requested_detector_mode)?;
            validate_explicit_detector_path(&args.detectors, args.detectors_cli_explicit)?;
            let detectors_path = auto_discover_detectors(&args.detectors)?;
            (requested_detector_mode, detectors_path)
        };
        let resolved_config_digest =
            crate::orchestrator_config::matcher_resolved_config_digest(&effective_config);
        let runtime_identity = keyhog_scanner::hw_probe::hyperscan_runtime_identity();
        let gpu_init_policy = {
            let _profile_span = keyhog_profile::span(keyhog_profile::Stage::ExecutionPackSelect);
            gpu_init_policy_for_args(
                &args,
                effective_config.autoroute_cache_path.as_deref(),
                effective_config.autoroute_gpu,
                effective_config.autoroute_calibration,
            )
        };
        let (mut loaded_corpus, detector_execution_pack) = {
            let _profile_span = keyhog_profile::span(keyhog_profile::Stage::DetectorLoad);
            if !detectors_path.exists() && requested_detector_mode.is_none() {
                let policy = execution_pack_policy_for_args(&args);
                let execution_pack_directory =
                    crate::execution_pack_install::installed_execution_pack_directory()
                        .context("resolving the installed execution-pack directory")?;
                let installed = match effective_config.backend_override {
                    Some(backend) => {
                        let pack_backend = match backend {
                            keyhog_scanner::hw_probe::ScanBackend::CpuFallback => {
                                keyhog_scanner::execution_pack::ExecutionPackBackend::Cpu
                            }
                            keyhog_scanner::hw_probe::ScanBackend::SimdCpu => {
                                keyhog_scanner::execution_pack::ExecutionPackBackend::Simd
                            }
                            keyhog_scanner::hw_probe::ScanBackend::GpuCuda => {
                                keyhog_scanner::execution_pack::ExecutionPackBackend::GpuCuda
                            }
                            keyhog_scanner::hw_probe::ScanBackend::GpuWgpu => {
                                keyhog_scanner::execution_pack::ExecutionPackBackend::GpuWgpu
                            }
                            keyhog_scanner::hw_probe::ScanBackend::GpuMetal => {
                                keyhog_scanner::execution_pack::ExecutionPackBackend::GpuMetal
                            }
                            _ => anyhow::bail!(
                                "the selected scan backend has no execution-pack identity"
                            ),
                        };
                        crate::execution_pack_install::
                            load_installed_detector_execution_pack_for_backend(
                                policy,
                                pack_backend,
                            )
                    }
                    None => crate::execution_pack_install::
                        load_installed_preferred_detector_execution_pack(policy),
                };
                match installed {
                    Ok(pack) => (None, Some(pack)),
                    Err(error) if !execution_pack_directory.exists() => {
                        tracing::warn!(
                            error = %error,
                            "no installed execution-pack generation; parsing embedded detectors"
                        );
                        let embedded = || -> anyhow::Result<LoadedDetectorCorpus> {
                            load_effective_detector_corpus(
                                &detectors_path,
                                requested_detector_mode,
                                !args.lockdown,
                            )
                            .context("loading effective detector corpus")
                        };
                        (Some(embedded()?), None)
                    }
                    Err(error) => {
                        return Err(error).context(
                            "loading authenticated detector execution pack; run a verified install or self-update",
                        );
                    }
                }
            } else {
                (
                    Some(
                        load_effective_detector_corpus(
                            &detectors_path,
                            requested_detector_mode,
                            !args.lockdown,
                        )
                        .context("loading effective detector corpus")?,
                    ),
                    None,
                )
            }
        };
        #[cfg(feature = "verify")]
        let verifier_enabled = effective_config.report.verify;
        #[cfg(not(feature = "verify"))]
        let verifier_enabled = false;
        let schemas_required = !disabled_detectors.is_empty() || verifier_enabled;
        if loaded_corpus.is_none() && schemas_required {
            let pack = detector_execution_pack.as_ref().context(
                "installed detector schemas are required, but the authenticated execution pack was not retained",
            )?;
            let ir_bytes = pack
                .section(keyhog_scanner::execution_pack::ExecutionPackSectionKind::DetectorIr)
                .context("installed execution pack has no detector IR section")?;
            let ir = keyhog_scanner::execution_pack::CanonicalDetectorExecutionIr::decode_runtime(
                ir_bytes,
            )
            .map_err(anyhow::Error::msg)?;
            if ir.digest() != pack.identity().detector_digest {
                anyhow::bail!(
                    "installed detector IR identity does not match its authenticated pack"
                );
            }
            let embedded_count = ir.detectors().len();
            loaded_corpus = Some(LoadedDetectorCorpus {
                detectors: ir.into_detectors(),
                schema_version: keyhog_core::DETECTOR_CORPUS_SCHEMA_VERSION,
                provenance: DetectorCorpusProvenance {
                    mode: "embedded",
                    source: format!("authenticated execution pack {}", pack.path().display()),
                    embedded_count,
                    custom_count: 0,
                },
            });
        }
        let direct_pack_hydration = loaded_corpus.is_none();
        let (detector_corpus_schema_version, mut detector_corpus_provenance, mut detectors) =
            match loaded_corpus {
                Some(loaded) => (loaded.schema_version, loaded.provenance, loaded.detectors),
                None => {
                    let pack = detector_execution_pack.as_ref().context(
                        "direct scanner hydration requires a retained authenticated execution pack",
                    )?;
                    (
                        keyhog_core::DETECTOR_CORPUS_SCHEMA_VERSION,
                        DetectorCorpusProvenance {
                            mode: "embedded",
                            source: format!(
                                "authenticated execution pack {}",
                                pack.path().display()
                            ),
                            embedded_count: 0,
                            custom_count: 0,
                        },
                        Vec::new(),
                    )
                }
            };
        let detector_validation_span =
            keyhog_profile::span(keyhog_profile::Stage::DetectorValidate);

        // Apply `[detector.<id>] enabled = false` from .keyhog.toml: drop the
        // disabled detectors from the corpus so they never compile or fire.
        // (Previously this config key was parsed and silently ignored.)
        if !disabled_detectors.is_empty() {
            let before = detectors.len();
            let dropped = filter_disabled_detectors(&mut detectors, &disabled_detectors);
            if dropped > 0 {
                if detectors.is_empty() {
                    let mut disabled_ids: Vec<&str> =
                        disabled_detectors.iter().map(String::as_str).collect();
                    disabled_ids.sort_unstable();
                    let listed = if disabled_ids.len() <= 16 {
                        disabled_ids.join(", ")
                    } else {
                        format!(
                            "{} ... ({} total)",
                            disabled_ids[..16].join(", "),
                            disabled_ids.len()
                        )
                    };
                    anyhow::bail!(
                        "all {before} loaded detector(s) were disabled by .keyhog.toml \
                         [detector.<id>] enabled = false ({listed}). Fix: leave at least \
                         one detector enabled, remove the config, or use .keyhogignore for \
                         specific finding suppressions. Refusing to scan with no detectors \
                         loaded."
                    );
                }
                tracing::info!(
                    target: "keyhog::config",
                    dropped,
                    "disabled detectors via .keyhog.toml [detector.<id>] enabled = false"
                );
            } else {
                let palette = style::for_stderr();
                eprintln!(
                    "{} .keyhog.toml disables detector id(s) {disabled_detectors:?}, but none matched the loaded corpus. \
                     Detector ids come from `keyhog detectors`; accelerated slots use the same canonical TOML id.",
                    style::warn("WARN", &palette)
                );
            }
        }

        // Autoroute's shared rules identity describes the active TOML corpus,
        // before per-invocation confidence floors are composed into it. Those
        // effective floors (including --precision clamping and operator
        // overrides) already participate in `autoroute_config_digest`; folding
        // them into this shared identity as well made calibrating one profile
        // replace every previously calibrated profile in the multi-config
        // cache. Disabled detectors remain part of corpus identity because they
        // change the compiled pattern set and backend workload materially.
        let mut detector_rules_digest =
            keyhog_core::hex_encode(&keyhog_core::compute_spec_hash(&detectors));
        let mut detector_corpus_digest = keyhog_core::hex_encode(
            &keyhog_core::compute_detector_corpus_digest_for_schema(
                &detectors,
                detector_corpus_schema_version,
            )
            .context("serializing effective detector corpus identity")?,
        );

        apply_host_runtime_limits(&mut effective_config, &hw);

        // Compose detector TOML defaults before precision clamping so low
        // self-declared floors participate in the same high-precision bar as
        // operator entries. Composing only after the clamp lets a detector's
        // recall-tuned 0.25 floor bypass --precision.
        detector_min_confidence =
            compose_detector_min_confidence(&mut detectors, detector_min_confidence);

        // High-precision mode: no detector's self-declared (or operator) floor may
        // sit below the precision bar. 47 detectors ship a low recall-tuned floor
        // (e.g. `aws-secret-access-key = 0.25`); in default mode that is intended,
        // but under `--precision` it would silently bypass the high floor and leak
        // sub-0.85 findings. Clamp every per-detector floor UP to the resolved
        // precision floor (which honours a `--min-confidence` override on top).
        // Detectors without a per-detector entry already use the global floor.
        if args.precision {
            let floor = effective_config.scanner.min_confidence;
            for v in detector_min_confidence.values_mut() {
                *v = v.max(floor);
            }
        }

        // Compile the ACTIVE detector corpus with the fully resolved floor.
        // This is the only point where detector TOML defaults, operator
        // overrides, and precision-mode clamping have all been composed.
        detector_min_confidence =
            compose_detector_min_confidence(&mut detectors, detector_min_confidence);

        // Incremental result reuse needs the fully effective spec hash: unlike
        // autoroute performance identity, a confidence-floor change can alter
        // emitted findings and must invalidate stored scan results.
        let mut detector_spec_hash = keyhog_core::compute_spec_hash(&detectors);
        drop(detector_validation_span);

        let mut detector_count = detectors.len();
        let mut signatures = collect_detector_signatures(&detectors);
        let detectors: Option<Arc<[DetectorSpec]>> =
            (!direct_pack_hydration).then(|| detectors.into());

        let scanner = {
            let _pack_span = keyhog_profile::span(keyhog_profile::Stage::ExecutionPackMap);
            let pack_generation = detector_execution_pack
                .as_ref()
                .map(|pack| keyhog_core::hex_encode(&pack.identity().digest()));
            let compiled = if disabled_detectors.is_empty() {
                match detector_execution_pack.as_ref() {
                    Some(pack) => {
                        let compiled =
                            CompiledScanner::compile_from_execution_pack_with_gpu_policy_and_tuning(
                                pack,
                                gpu_init_policy,
                                &effective_config.scanner_tuning,
                            )?;
                        // Pack hydration reuses an eager matcher graph, but only
                        // attribute it to CacheId::MatcherArtifact when the
                        // persistent matcher cache is enabled. Otherwise
                        // `--matcher-cache off` / `--lockdown` would still show
                        // a 100% MatcherArtifact hit rate in --profile.
                        if effective_config.matcher_cache_path.is_some() {
                            keyhog_scanner::record_matcher_artifact_pack_hit();
                        }
                        Ok(compiled)
                    }
                    None => {
                        let detectors = detectors.as_ref().context(
                            "embedded/debug scanner construction requires detector schemas",
                        )?;
                        keyhog_scanner::compile_shared_with_matcher_artifact_cache(
                            Arc::clone(detectors),
                            gpu_init_policy,
                            &effective_config.scanner_tuning,
                            resolved_config_digest,
                            pack_generation.as_deref(),
                            runtime_identity.as_deref(),
                        )
                        .map(|(scanner, outcome)| {
                            tracing::debug!(
                                target: "keyhog::matcher_artifact_cache",
                                outcome = outcome.as_str(),
                                "matcher artifact cache outcome"
                            );
                            scanner
                        })
                    }
                }
            } else {
                let detectors = detectors
                    .as_ref()
                    .context("disabled-detector scanner construction requires detector schemas")?;
                keyhog_scanner::compile_shared_with_matcher_artifact_cache(
                    Arc::clone(detectors),
                    gpu_init_policy,
                    &effective_config.scanner_tuning,
                    resolved_config_digest,
                    None,
                    runtime_identity.as_deref(),
                )
                .map(|(scanner, outcome)| {
                    tracing::debug!(
                        target: "keyhog::matcher_artifact_cache",
                        outcome = outcome.as_str(),
                        "matcher artifact cache outcome"
                    );
                    scanner
                })
            };
            Arc::new(
                compiled
                    .with_context(|| {
                        format!("materializing scanner for {detector_count} detectors")
                    })?
                    .with_config(effective_config.engine_scanner_config())
                    .with_tuning_config(effective_config.scanner_tuning.clone()),
            )
        };

        if direct_pack_hydration {
            detector_count = scanner.detector_count();
            signatures = scanner.detector_signature_sources();
            for (id, floor) in scanner.declared_detector_min_confidence() {
                detector_min_confidence
                    .entry(id.to_owned())
                    .or_insert(floor);
            }
            if args.precision {
                let floor = effective_config.scanner.min_confidence;
                for value in detector_min_confidence.values_mut() {
                    *value = value.max(floor);
                }
            }

            let runtime = scanner.runtime_status();
            detector_rules_digest = keyhog_core::hex_encode(&runtime.compiled_plan_digest);
            let pack = detector_execution_pack.as_ref().context(
                "direct scanner hydration requires a retained authenticated execution pack",
            )?;
            detector_corpus_digest = keyhog_core::hex_encode(&pack.identity().detector_digest);
            detector_corpus_provenance.embedded_count = detector_count;

            let mut hasher = blake3::Hasher::new();
            hasher.update(b"keyhog-effective-installed-detector-spec-v1\0");
            hasher.update(&runtime.compiled_plan_digest);
            hasher.update(&pack.identity().detector_digest);
            hasher.update(&effective_config.scanner.min_confidence.to_le_bytes());
            let mut floors: Vec<_> = detector_min_confidence.iter().collect();
            floors.sort_unstable_by(|left, right| left.0.cmp(right.0));
            for (id, floor) in floors {
                hasher.update(&(id.len() as u64).to_le_bytes());
                hasher.update(id.as_bytes());
                hasher.update(&floor.to_le_bytes());
            }
            detector_spec_hash = *hasher.finalize().as_bytes();
        }

        #[cfg(feature = "verify")]
        let verifier_detectors = if verifier_enabled { detectors } else { None };
        #[cfg(not(feature = "verify"))]
        drop(detectors);

        run::release_allocator_arenas_after_construction();

        let test_fixture_suppressions = if args.no_suppress_test_fixtures {
            crate::test_fixture_suppressions::TestFixtureSuppressions::empty()
        } else {
            crate::test_fixture_suppressions::TestFixtureSuppressions::bundled()
        };
        Ok(Self {
            args,
            detector_count,
            #[cfg(feature = "verify")]
            verifier_detectors,
            detector_spec_hash,
            detector_rules_digest,
            detector_corpus_digest,
            detector_corpus_provenance,
            scanner,
            signatures,
            test_fixture_suppressions,
            disabled_detectors,
            detector_min_confidence,
            effective_config,
            autoroute_measurement_observer: None,
            early_profile_session,
            early_profile_build,
        })
    }

    pub(crate) fn scanner(&self) -> &CompiledScanner {
        self.scanner.as_ref()
    }

    pub(crate) fn prepare_autoroute_calibration_gpu_artifact(&self) -> Result<()> {
        self.scanner
            .prepare_autoroute_calibration_gpu_artifact()
            .map_err(|error| anyhow::anyhow!(error))
    }

    pub(crate) fn observe_autoroute_calibration_measurements(
        &mut self,
        observer: dispatch::AutorouteMeasurementObserver,
    ) -> Result<()> {
        if !self.effective_config.autoroute_calibration {
            anyhow::bail!("measured-route observation requires an autoroute calibration runtime");
        }
        self.autoroute_measurement_observer = Some(observer);
        Ok(())
    }

    pub(crate) fn args(&self) -> &ScanArgs {
        &self.args
    }

    pub(crate) fn incremental_cache_path(&self) -> Result<Option<std::path::PathBuf>> {
        if !self.args.incremental {
            return Ok(None);
        }
        if self.args.lockdown {
            tracing::warn!("lockdown mode: --incremental disabled (cache writes refused)");
            eprintln!(
                "warning: --incremental disabled because --lockdown forbids cache reads/writes; scanning without the incremental cache"
            );
            return Ok(None);
        }
        match self.configured_incremental_cache_path() {
            Some(path) => Ok(Some(path)),
            None => anyhow::bail!(
                "--incremental was requested, but no default cache directory is available. \
                 Fix: set XDG_CACHE_HOME or HOME, or pass --incremental-cache <PATH>."
            ),
        }
    }

    pub(crate) fn lockdown_persistence_cache_paths(&self) -> Vec<std::path::PathBuf> {
        if !(self.args.incremental || self.args.incremental_cache.is_some()) {
            return Vec::new();
        }
        self.configured_incremental_cache_path()
            .into_iter()
            .collect()
    }

    fn configured_incremental_cache_path(&self) -> Option<std::path::PathBuf> {
        self.args
            .incremental_cache
            .clone()
            .or_else(keyhog_core::merkle_default_cache_path)
    }

    pub(crate) fn build_merkle_index(
        &self,
        path: Option<&std::path::Path>,
    ) -> (
        Option<Arc<keyhog_core::MerkleIndex>>,
        Option<keyhog_core::MerkleLoadStatus>,
    ) {
        let Some(path) = path else {
            return (None, None);
        };
        let report =
            keyhog_core::MerkleIndex::load_with_spec_report(path, &self.detector_spec_hash);
        if let Some(warning) = incremental_cache_warning(report.status()) {
            eprintln!("{warning}");
        }
        let status = report.status().clone();
        let idx = report.into_index();
        tracing::info!("incremental scan: loaded merkle index");
        (Some(Arc::new(idx)), Some(status))
    }

    /// Test-only entry point for the producer/scanner pipeline.
    #[doc(hidden)]
    pub(crate) fn scan_sources_for_test(
        &self,
        sources: Vec<Box<dyn Source>>,
        show_progress: bool,
        merkle: Option<Arc<keyhog_core::MerkleIndex>>,
    ) -> Result<Vec<RawMatch>> {
        self.scan_sources(sources, show_progress, merkle, None)
    }

    /// Test-only constructor bypassing detector-cache and lockdown gating.
    #[doc(hidden)]
    pub(crate) fn from_parts_for_test(
        args: ScanArgs,
        detectors: Vec<DetectorSpec>,
        scanner: Arc<CompiledScanner>,
        signatures: std::collections::HashSet<Arc<str>>,
        test_fixture_suppressions: crate::test_fixture_suppressions::TestFixtureSuppressions,
    ) -> Self {
        let batch_pipeline = args.batch_pipeline && !args.no_batch_pipeline;
        let threads = args.threads;
        let reader_threads = args.reader_threads;
        let fused_batch = args
            .fused_batch
            .unwrap_or(crate::orchestrator_config::FUSED_BATCH_DEFAULT); // LAW10: absent fused-batch config => documented compiled throughput default; no scan feature disabled and effective config prints the concrete value
        let fused_depth = args.fused_depth;
        let detector_spec_hash = keyhog_core::compute_spec_hash(&detectors);
        let detector_rules_digest = keyhog_core::hex_encode(&detector_spec_hash);
        let detector_corpus_digest = detector_rules_digest.clone();
        let detector_corpus_provenance = DetectorCorpusProvenance {
            mode: "provided",
            source: "library/test constructor".to_string(),
            embedded_count: 0,
            custom_count: detectors.len(),
        };
        let detector_count = detectors.len();
        #[cfg(feature = "verify")]
        let verifier_detectors = args.verify.then(|| detectors.into());
        #[cfg(not(feature = "verify"))]
        drop(detectors);
        Self {
            args,
            detector_count,
            #[cfg(feature = "verify")]
            verifier_detectors,
            detector_spec_hash,
            detector_rules_digest,
            detector_corpus_provenance,
            detector_corpus_digest,
            scanner,
            signatures,
            test_fixture_suppressions,
            disabled_detectors: std::collections::HashSet::new(),
            detector_min_confidence: std::collections::HashMap::new(),
            autoroute_measurement_observer: None,
            early_profile_session: None,
            early_profile_build: None,
            effective_config: ResolvedScanConfig {
                backend_override: Some(keyhog_scanner::ScanBackend::CpuFallback),
                batch_pipeline,
                threads,
                reader_threads,
                fused_batch,
                fused_depth,
                gpu_runtime_policy: keyhog_scanner::gpu::GpuRuntimePolicy::Auto,
                autoroute_gpu: false,
                autoroute_calibration: false,
                scanner: keyhog_scanner::ScannerConfig::default(),
                min_confidence: keyhog_scanner::ScannerConfig::default().min_confidence,
                ml_enabled: keyhog_scanner::ScannerConfig::default().ml_enabled,
                detector_min_confidence: std::collections::HashMap::new(),
                disabled_detectors: std::collections::HashSet::new(),
                require_lockdown: false,
                regex_dfa_limit: None,
                gpu_batch_input_limit: None,
                max_file_size: None,
                #[cfg(feature = "git")]
                max_commits: crate::orchestrator_config::MAX_COMMITS_DEFAULT,
                no_default_excludes: false,
                exclude_paths: Vec::new(),
                incremental: false,
                incremental_cache_path: None,
                hyperscan_cache_dir: None,
                autoroute_cache_path: None,
                matcher_cache_path: None,
                calibration_cache_path: None,
                calibration_entry_count: 0,
                calibration_digest: 0,
                aws_canary_accounts: Vec::new(),
                scanner_tuning: keyhog_scanner::ScannerTuningConfig::default(),
                allowlist: crate::orchestrator_config::ResolvedAllowlistConfig {
                    file: None,
                    require_reason: false,
                    require_approved_by: false,
                    max_expires_days: None,
                },
                source_limits: keyhog_sources::SourceLimits::default(),
                report: crate::orchestrator_config::ResolvedReportPolicy {
                    format: crate::args::OutputFormat::Text,
                    severity: None,
                    dedup: crate::args::CliDedupScope::Credential,
                    verify: false,
                    lockdown: false,
                    show_secrets: false,
                    no_suppress_test_fixtures: false,
                    hide_client_safe: false,
                },
                verify: crate::orchestrator_config::ResolvedVerifyPolicy::disabled(),
            },
        }
    }
}

fn incremental_cache_warning(status: &MerkleLoadStatus) -> Option<String> {
    match status {
        MerkleLoadStatus::Missing { .. } | MerkleLoadStatus::Loaded { .. } => None,
        MerkleLoadStatus::ReadFailed { path, error } => Some(format!(
            "warning: incremental cache {} could not be read: {error}; starting from an empty cache and rewriting it after this scan",
            path.display()
        )),
        MerkleLoadStatus::ParseFailed { path, error } => Some(format!(
            "warning: incremental cache {} could not be parsed: {error}; starting from an empty cache and rewriting it after this scan",
            path.display()
        )),
        MerkleLoadStatus::SchemaMismatch {
            path,
            version,
            expected,
        } => Some(format!(
            "warning: incremental cache {} uses schema version {version}, expected {expected}; starting from an empty cache and rewriting it after this scan",
            path.display()
        )),
        MerkleLoadStatus::SpecChanged { path } => Some(format!(
            "warning: incremental cache {} was built for a different detector/config identity; starting from an empty cache and rewriting it after this scan",
            path.display()
        )),
        MerkleLoadStatus::InvalidEntryHash {
            path,
            entry_path,
            hash,
        } => Some(format!(
            "warning: incremental cache {} has an invalid hash for entry {} ({hash}); starting from an empty cache and rewriting it after this scan",
            path.display(),
            entry_path
        )),
    }
}

fn gpu_init_policy_for_args(
    args: &ScanArgs,
    autoroute_cache_path: Option<&std::path::Path>,
    autoroute_gpu: bool,
    autoroute_calibration: bool,
) -> GpuInitPolicy {
    // GPU init (which acquires the backend the region-presence route needs)
    // follows the selected backend: an explicit GPU driver, or the measured
    // backend-selection policy below.
    if let Some(policy) = backend_name_gpu_policy(args.backend.as_deref()) {
        return policy;
    }
    if args.no_gpu && !args.require_gpu {
        return GpuInitPolicy::ForceDisabled;
    }
    if autoroute_calibration && autoroute_gpu {
        return GpuInitPolicy::FromRuntimePolicy;
    }
    if filesystem_auto_scan_cannot_route_gpu(args) && !args.require_gpu {
        if autoroute_cache_path.is_some_and(std::path::Path::exists) {
            return GpuInitPolicy::FromRuntimePolicy;
        }
        return GpuInitPolicy::ForceDisabled;
    }
    GpuInitPolicy::FromRuntimePolicy
}

fn backend_name_gpu_policy(name: Option<&str>) -> Option<GpuInitPolicy> {
    let name = name?.trim();
    // "auto" is the explicit defer-to-routing choice (FromRuntimePolicy), and is
    // not a backend `parse_backend_str` recognizes.
    if name.eq_ignore_ascii_case("auto") {
        return None;
    }
    // Single source of truth for backend-string parsing is the scanner's
    // `parse_backend_str` (case-insensitive, owns every alias). Map its
    // ScanBackend verdict to a GPU-init policy via `backend_gpu_policy` instead
    // of re-listing every alias here, the two alias lists had already drifted
    // apart, so a `--backend` value added to one was invisible to the other.
    keyhog_scanner::hw_probe::parse_backend_str(name).map(backend_gpu_policy)
}

fn backend_gpu_policy(backend: keyhog_scanner::ScanBackend) -> GpuInitPolicy {
    GpuInitPolicy::SelectedBackend(backend)
}

fn filesystem_auto_scan_cannot_route_gpu(args: &ScanArgs) -> bool {
    if args.batch_pipeline && !args.no_batch_pipeline {
        return false;
    }
    if args.path.is_none() {
        return false;
    }
    if args.stdin {
        return false;
    }
    #[cfg(feature = "binary")]
    if args.binary {
        return false;
    }
    #[cfg(feature = "git")]
    if args.git_blobs.is_some() || args.git_diff.is_some() || args.git_history.is_some() {
        return false;
    }
    #[cfg(feature = "github")]
    if args.github_org.is_some() {
        return false;
    }
    #[cfg(feature = "gitlab")]
    if args.gitlab_group.is_some() {
        return false;
    }
    #[cfg(feature = "bitbucket")]
    if args.bitbucket_workspace.is_some() {
        return false;
    }
    #[cfg(feature = "s3")]
    if args.s3_bucket.is_some() {
        return false;
    }
    #[cfg(feature = "gcs")]
    if args.gcs_bucket.is_some() {
        return false;
    }
    #[cfg(feature = "azure")]
    if args.azure_container_url.is_some() {
        return false;
    }
    #[cfg(feature = "docker")]
    if args.docker_image.is_some() {
        return false;
    }
    #[cfg(feature = "web")]
    if args.url.is_some() {
        return false;
    }
    if args
        .source
        .as_ref()
        .is_some_and(|sources| !sources.is_empty())
    {
        return false;
    }
    true
}

// `reporting::dump_dogfood_trace` is consumed by sibling `run.rs` via
// `use reporting::{dump_dogfood_trace, …};` directly. The re-export
// that lived here was unused and tripped the unused-imports lint.

#[cfg(test)]
mod tests;
