//! Core scanning orchestration logic for the KeyHog CLI.

mod allowlist;
mod dispatch;
pub(crate) use dispatch::{
    record_completed_gpu_recovery, recover_automatic_gpu_batch, COALESCED_CHUNK_SCAN_CEILING_BYTES,
    COALESCED_CHUNK_SCAN_CEILING_MB,
};
mod postprocess;
pub(crate) mod reporting;
mod run;
mod streaming;

use crate::args::ScanArgs;
use crate::orchestrator_config::{
    auto_discover_detectors, autoroute_config_digest, backend_override_cli_value,
    configure_threads, gpu_runtime_policy_from_args, load_detectors_no_cache,
    load_detectors_with_cache, parse_backend_override, resolve_scan_config,
    resolved_scan_config_for_scanner, validate_explicit_detector_path,
    ResolvedEngineRuntimeSettings, ResolvedScanConfig,
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

fn selected_gpu_degradation_failure(
    backend: keyhog_scanner::ScanBackend,
    before: u64,
    after: u64,
) -> anyhow::Error {
    anyhow::anyhow!(
        "selected backend {} degraded during dispatch (GPU degradation counter {before} -> {after}); refusing to report a successful scan. Run `keyhog backend --self-test`, recalibrate autoroute, or choose an explicit CPU backend",
        backend.label()
    )
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

fn daemon_requires_gpu(
    backend_override: Option<keyhog_scanner::ScanBackend>,
    gpu_required_by_route: bool,
) -> Result<bool> {
    match backend_override {
        None => Ok(gpu_required_by_route),
        Some(backend) if backend.is_gpu() && gpu_required_by_route => Ok(true),
        Some(backend) if backend.is_gpu() => Err(daemon_gpu_failure(format!(
            "daemon --backend {} cannot be honored: this build and host have no eligible physical GPU path.",
            backend.label()
        ))),
        Some(keyhog_scanner::ScanBackend::SimdCpu | keyhog_scanner::ScanBackend::CpuFallback) => {
            Ok(false)
        }
        Some(unknown) => anyhow::bail!(
            "daemon backend {unknown:?} is not supported by this KeyHog build; choose auto, gpu-cuda, gpu-wgpu, simd, or cpu"
        ),
    }
}

fn validate_daemon_gpu_initialization(gpu_required: bool, gpu_ready: bool) -> Result<()> {
    if gpu_required && !gpu_ready {
        return Err(daemon_gpu_failure(
            "daemon GPU initialization failed: the detected physical GPU is unavailable or incompatible with the compiled scanner, driver, or runtime; refusing to announce readiness.",
        ));
    }
    Ok(())
}

fn validate_daemon_gpu_warmup(
    gpu_required: bool,
    degrade_before: u64,
    degrade_after: u64,
) -> Result<()> {
    if gpu_required && degrade_after != degrade_before {
        return Err(daemon_gpu_failure(
            "daemon GPU warmup degraded before readiness; refusing to apply persistent warm autoroute evidence.",
        ));
    }
    Ok(())
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

pub(crate) use dispatch::CachedBackendRouter;
pub(crate) use dispatch::{inspect_autoroute_cache, AutorouteCacheInspection};
pub(crate) use streaming::{scan_streaming_source, StreamingSourceEvent};

pub(crate) fn cached_autoroute_router_for_default_config(
    scanner: &CompiledScanner,
    detectors: &[DetectorSpec],
) -> CachedBackendRouter {
    let rules_digest = keyhog_core::hex_encode(&keyhog_core::compute_spec_hash(detectors));
    let mut resolved = resolved_scan_config_for_scanner(keyhog_scanner::ScannerConfig::default());
    resolved.threads = Some(rayon::current_num_threads());
    cached_autoroute_router(
        scanner,
        rules_digest,
        autoroute_config_digest(&resolved),
        resolved.gpu_runtime_policy != keyhog_scanner::gpu::GpuRuntimePolicy::Disabled,
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
    let hw_caps = keyhog_scanner::hw_probe::probe_hardware().clone();
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
    private_key_block_detectors: std::collections::HashSet<String>,
    test_fixture_suppressions: crate::test_fixture_suppressions::TestFixtureSuppressions,
    no_suppress_test_fixtures: bool,
    min_confidence: f64,
    min_severity: Option<keyhog_core::Severity>,
    allowlist: keyhog_core::Allowlist,
}

fn private_key_block_detector_ids(detectors: &[DetectorSpec]) -> std::collections::HashSet<String> {
    detectors
        .iter()
        .filter(|detector| detector.private_key_block)
        .map(|detector| detector.id.clone())
        .collect()
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
    /// `None` => use the persisted autoroute decision (which requires
    /// calibration). When `Some`, the per-file scan never consults the autoroute
    /// cache, so the runtime works on an uncalibrated binary.
    backend_override: Option<keyhog_scanner::ScanBackend>,
    /// Resolved suppression filter. `None` for the daemon runtime (which does its
    /// own client-side finalize via `into_parts`); `Some` for `keyhog watch`,
    /// installed by [`setup_default_scan_runtime`].
    filter: Option<DefaultScanFilter>,
}

impl DefaultScanRuntime {
    pub(crate) fn new(scanner: Arc<CompiledScanner>, detectors: &[DetectorSpec]) -> Self {
        let router = cached_autoroute_router_for_default_config(&scanner, detectors);
        Self::new_with_router(scanner, detectors, router)
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
            signatures: &f.signatures,
            disabled_detectors: &f.disabled_detectors,
            test_fixture_suppressions: &f.test_fixture_suppressions,
            no_suppress_test_fixtures: f.no_suppress_test_fixtures,
            detector_min_confidence: &f.detector_min_confidence,
            private_key_block_detectors: &f.private_key_block_detectors,
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
                if !self
                    .scanner
                    .warm_backend(keyhog_scanner::ScanBackend::SimdCpu)
                {
                    anyhow::bail!(
                        "{subcommand_name} --backend simd cannot be honored because the Hyperscan/SIMD prefilter is unavailable. Run `keyhog backend --self-test` or choose --backend cpu"
                    );
                }
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
        mut self,
        backend_override: Option<keyhog_scanner::ScanBackend>,
    ) -> Result<Self> {
        self.scanner.warm();
        let simd_ready = self
            .scanner
            .warm_backend(keyhog_scanner::ScanBackend::SimdCpu);
        let gpu_candidates = self.scanner.gpu_backend_candidates();
        if backend_override == Some(keyhog_scanner::ScanBackend::SimdCpu) && !simd_ready {
            anyhow::bail!(
                "daemon --backend simd cannot be honored because the Hyperscan/SIMD prefilter is unavailable. Run `keyhog backend --self-test` or choose --backend cpu"
            );
        }
        let gpu_routes: Vec<_> = match backend_override {
            Some(backend) if backend.is_gpu() => vec![backend],
            None => self
                .router
                .persistent_gpu_routes()
                .map_err(anyhow::Error::from)?,
            _ => Vec::new(),
        };
        let requested_gpu_is_eligible = match backend_override {
            Some(backend) if backend.is_gpu() => gpu_candidates
                .iter()
                .any(|candidate| candidate.backend == backend && candidate.is_eligible()),
            _ => !gpu_routes.is_empty(),
        };
        let gpu_must_be_ready = daemon_requires_gpu(backend_override, requested_gpu_is_eligible)?;
        let gpu_ready = gpu_must_be_ready
            && !gpu_routes.is_empty()
            && gpu_routes
                .iter()
                .all(|backend| self.scanner.warm_backend(*backend));
        validate_daemon_gpu_initialization(gpu_must_be_ready, gpu_ready)?;
        if gpu_must_be_ready {
            let warmup = keyhog_core::Chunk {
                data: "keyhog daemon accelerator warmup\n".into(),
                metadata: keyhog_core::ChunkMetadata {
                    source_type: "daemon-warmup".into(),
                    ..Default::default()
                },
            };
            let degrade_before = self.scanner.gpu_degrade_count();
            self.scanner.clear_fragment_cache();
            for backend in &gpu_routes {
                drop(
                    self.scanner
                        .scan_chunks_with_backend(std::slice::from_ref(&warmup), *backend),
                );
            }
            self.scanner.clear_fragment_cache();
            validate_daemon_gpu_warmup(
                gpu_must_be_ready,
                degrade_before,
                self.scanner.gpu_degrade_count(),
            )?;
        }
        tracing::info!(
            simd_ready,
            gpu_ready,
            selected_gpu_routes = ?gpu_routes,
            gpu_must_be_ready,
            "persistent daemon backends initialized"
        );
        self.router = self.router.for_persistent_daemon();
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
        let degrade_before = backend.is_gpu().then(|| self.scanner.gpu_degrade_count());
        let findings = self.scanner.scan_with_backend_and_admission_plan(
            chunk,
            backend,
            selection.phase1_plan.as_ref(),
        );
        if let Some(before) = degrade_before {
            let after = self.scanner.gpu_degrade_count();
            if after != before {
                return Err(selected_gpu_degradation_failure(backend, before, after));
            }
        }
        Ok(findings)
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
    map_compile_error: impl FnOnce(&keyhog_scanner::ScanError) -> anyhow::Error,
) -> Result<DefaultScanRuntime> {
    let scanner = Arc::new(
        CompiledScanner::compile(detectors.clone()).map_err(|error| map_compile_error(&error))?,
    );
    Ok(DefaultScanRuntime::new(scanner, &detectors))
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
    validate_explicit_detector_path(&synthetic.detectors, synthetic.detectors_cli_explicit)?;
    let detectors_path = auto_discover_detectors(&synthetic.detectors)?;
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

    let mut detectors = crate::orchestrator_config::load_detectors_or_embedded(&detectors_path)?;

    // Apply `[detector.<id>] enabled = false`: drop the disabled detectors before
    // compilation so they never fire (mirrors `ScanOrchestrator::new`).
    let disabled_detectors = effective_config.disabled_detectors.clone();
    if !disabled_detectors.is_empty() {
        let before = detectors.len();
        detectors.retain(|d| !disabled_detectors.contains(d.id.as_str()));
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
                &detectors_path,
                &error,
            )
        })?
        .with_config(effective_config.scanner.clone())
        .with_tuning_config(effective_config.scanner_tuning.clone()),
    );

    let router = cached_autoroute_router(
        &scanner,
        rules_digest,
        autoroute_config_digest(&effective_config),
        effective_config.gpu_runtime_policy != keyhog_scanner::gpu::GpuRuntimePolicy::Disabled,
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
            private_key_block_detectors: private_key_block_detector_ids(&detectors),
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

    if warm {
        scan_runtime.warm();
    }
    Ok(scan_runtime)
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

pub(crate) struct ScanOrchestrator {
    pub(crate) args: ScanArgs,
    pub(crate) detectors: Vec<DetectorSpec>,
    pub(crate) detector_spec_hash: [u8; 32],
    pub(crate) detector_rules_digest: String,
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
    /// Active detector ids whose TOMLs declare `private_key_block = true`.
    /// Match resolution consumes this set directly; custom detector policy must
    /// never be replaced by an embedded registry lookup.
    pub(crate) private_key_block_detectors: std::collections::HashSet<String>,
    /// Fully resolved scan policy used by the engine and post-processing.
    pub(crate) effective_config: ResolvedScanConfig,
    /// Optional receipt sink for the calibration command's exact persisted
    /// workload keys. Normal scans never install one.
    autoroute_measurement_observer: Option<dispatch::AutorouteMeasurementObserver>,
}

impl ScanOrchestrator {
    pub(crate) fn new(mut args: ScanArgs) -> Result<Self> {
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

        let hw = keyhog_scanner::hw_probe::probe_hardware();
        let worker_threads = configure_threads(args.threads, hw.physical_cores)?;
        args.threads = Some(worker_threads);
        effective_config.threads = Some(worker_threads);

        validate_explicit_detector_path(&args.detectors, args.detectors_cli_explicit)?;
        let detectors_path = auto_discover_detectors(&args.detectors)?;
        let mut detectors = if args.lockdown {
            load_detectors_no_cache(&detectors_path)
                .context("loading detectors (lockdown: cache disabled)")?
        } else {
            load_detectors_with_cache(&detectors_path)?
        };

        // Apply `[detector.<id>] enabled = false` from .keyhog.toml: drop the
        // disabled detectors from the corpus so they never compile or fire.
        // (Previously this config key was parsed and silently ignored.)
        if !disabled_detectors.is_empty() {
            let before = detectors.len();
            detectors.retain(|d| !disabled_detectors.contains(d.id.as_str()));
            let dropped = before - detectors.len();
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
        let detector_rules_digest =
            keyhog_core::hex_encode(&keyhog_core::compute_spec_hash(&detectors));

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
        let detector_spec_hash = keyhog_core::compute_spec_hash(&detectors);

        let gpu_init_policy = gpu_init_policy_for_args(
            &args,
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
            .with_context(|| format!("compiling scanner from {} detector specs", detectors.len()))?
            .with_config(effective_config.scanner.clone())
            .with_tuning_config(effective_config.scanner_tuning.clone()),
        );

        // Detector regexes are validated and seeded during scanner construction;
        // `warm()` now primarily pays regex DFA/transition-cache first-touch and
        // generated/plain fallback regex work in parallel. The earlier `is_dir`
        // gate was meant to keep one-shot single-file/stdin startup fast, but it
        // backfired: a single-file scan then paid that first-touch work serially
        // on the hot path (~340ms measured), strictly slower than the parallel
        // `warm()` a directory scan got. Single file, stdin, pre-commit hooks
        // and editor integrations all hit that worst case. `warm()` is
        // idempotent and a no-op for already-warmed patterns, so warming
        // unconditionally parallelizes work the first scan would otherwise pay.
        scanner.warm();

        let signatures = collect_detector_signatures(&detectors);

        let test_fixture_suppressions = if args.no_suppress_test_fixtures {
            crate::test_fixture_suppressions::TestFixtureSuppressions::empty()
        } else {
            crate::test_fixture_suppressions::TestFixtureSuppressions::bundled()
        };
        let private_key_block_detectors = private_key_block_detector_ids(&detectors);

        Ok(Self {
            args,
            detectors,
            detector_spec_hash,
            detector_rules_digest,
            scanner,
            signatures,
            test_fixture_suppressions,
            disabled_detectors,
            detector_min_confidence,
            private_key_block_detectors,
            effective_config,
            autoroute_measurement_observer: None,
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
    ) -> Option<Arc<keyhog_core::MerkleIndex>> {
        let path = path?;
        let report =
            keyhog_core::MerkleIndex::load_with_spec_report(path, &self.detector_spec_hash);
        if let Some(warning) = incremental_cache_warning(report.status()) {
            eprintln!("{warning}");
        }
        let idx = report.into_index();
        tracing::info!("incremental scan: loaded merkle index");
        Some(Arc::new(idx))
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
        let private_key_block_detectors = private_key_block_detector_ids(&detectors);
        Self {
            args,
            detectors,
            detector_spec_hash,
            detector_rules_digest,
            scanner,
            signatures,
            test_fixture_suppressions,
            disabled_detectors: std::collections::HashSet::new(),
            detector_min_confidence: std::collections::HashMap::new(),
            private_key_block_detectors,
            autoroute_measurement_observer: None,
            effective_config: ResolvedScanConfig {
                backend_override: Some(keyhog_scanner::ScanBackend::SimdCpu),
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
    match backend {
        keyhog_scanner::ScanBackend::GpuCuda | keyhog_scanner::ScanBackend::GpuWgpu => {
            GpuInitPolicy::ForceEnabled
        }
        keyhog_scanner::ScanBackend::SimdCpu | keyhog_scanner::ScanBackend::CpuFallback => {
            GpuInitPolicy::ForceDisabled
        }
        _ => GpuInitPolicy::FromRuntimePolicy,
    }
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
