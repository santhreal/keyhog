//! Reusable default scan filter and runtime setup for `watch`, `daemon`, and `guard`.

use std::sync::Arc;
use anyhow::{Context, Result};
use keyhog_core::{Chunk, DetectorSpec, RawMatch};
use keyhog_scanner::{CompiledScanner, GpuInitPolicy};
use crate::args::ScanArgs;
use crate::orchestrator_config::{
    auto_discover_detectors, autoroute_config_digest, backend_override_cli_value,
    configure_threads, load_effective_detector_corpus, resolve_scan_config,
    validate_detector_mode_selection, validate_explicit_detector_path,
    ResolvedEngineRuntimeSettings,
};
use super::{
    allowlist, apply_host_runtime_limits, automatic_backend_recovery_allowed,
    cached_autoroute_router, cached_autoroute_router_for_default_config,
    collect_detector_signatures, corpus_rules_digest, dispatch, filter_disabled_detectors,
    gpu_init_policy_for_args, persistent_runtime_requires_gpu, postprocess,
    router_gpu_participates, run, scan_selected_batch,
    validate_persistent_gpu_initialization, CachedBackendRouter, GpuUnavailableError,
};

/// The resolved post-scan suppression policy a [`DefaultScanRuntime`] applies so
/// `keyhog watch` honors the SAME `.keyhog.toml` / `.keyhogignore` pipeline as
/// `keyhog scan` (Law 10: watch must not silently un-suppress a finding that
/// scan would drop). Built once at setup from the resolved config plus the
/// loaded allowlist, and fed into the shared [`postprocess::MatchFilter`].

pub(crate) struct DefaultScanFilter {
    pub(super) signatures: std::collections::HashSet<Arc<str>>,
    pub(super) disabled_detectors: std::collections::HashSet<String>,
    pub(super) detector_min_confidence: std::collections::HashMap<String, f64>,
    pub(super) test_fixture_suppressions: crate::test_fixture_suppressions::TestFixtureSuppressions,
    pub(super) no_suppress_test_fixtures: bool,
    pub(super) min_confidence: f64,
    pub(super) min_severity: Option<keyhog_core::Severity>,
    pub(super) allowlist: keyhog_core::Allowlist,
}

impl DefaultScanFilter {
    /// Build a guard scan filter from detector specs. Uses bundled
    /// test-fixture suppressions and an empty allowlist (the daemon
    /// does not load a per-root allowlist for guard scans).
    pub(crate) fn for_guard(detectors: &[DetectorSpec]) -> Self {
        let signatures = collect_detector_signatures(detectors);
        // Disabled detectors are already filtered out before the
        // daemon compiles its scanner, so the guard filter starts
        // with an empty disabled set.
        let disabled_detectors = std::collections::HashSet::new();
        let detector_min_confidence = compose_detector_min_confidence(
            &mut detectors.to_vec(),
            std::collections::HashMap::new(),
        );
        Self {
            signatures,
            disabled_detectors,
            detector_min_confidence,
            test_fixture_suppressions:
                crate::test_fixture_suppressions::TestFixtureSuppressions::bundled(),
            no_suppress_test_fixtures: false,
            min_confidence: 0.0,
            min_severity: None,
            allowlist: keyhog_core::Allowlist::default(),
        }
    }

    /// Finalize raw scanner matches through the guard suppression pipeline.
    /// Returns the exact surviving findings on success. Callers must treat
    /// `None` as a coverage gap, never as zero findings.
    pub(crate) fn finalize_matches(
        &self,
        scanner: &CompiledScanner,
        matches: Vec<RawMatch>,
    ) -> Option<Vec<RawMatch>> {
        let filter = postprocess::MatchFilter {
            scanner,
            signatures: &self.signatures,
            disabled_detectors: &self.disabled_detectors,
            test_fixture_suppressions: &self.test_fixture_suppressions,
            no_suppress_test_fixtures: self.no_suppress_test_fixtures,
            detector_min_confidence: &self.detector_min_confidence,
            min_confidence: self.min_confidence,
            min_severity: self.min_severity,
        };
        match postprocess::filter_and_resolve_matches(&filter, matches, &self.allowlist) {
            Ok(finalized) => Some(finalized),
            Err(e) => {
                tracing::warn!("guard: match finalization failed: {}", e);
                None
            }
        }
    }

    pub(crate) fn finalize_default_policy_blocker_count(
        &self,
        scanner: &CompiledScanner,
        matches: Vec<RawMatch>,
    ) -> Option<usize> {
        self.finalize_matches(scanner, matches).map(|finalized| {
            finalized
                .iter()
                .filter(|finding| finding.evidence.tier().blocks(false))
                .count()
        })
    }
}

/// Compose detector-declared confidence floors with operator overrides and
/// write the effective value back into the ACTIVE corpus before compilation.
/// The returned map is the same policy used by post-processing, so early engine
/// adjudication and final filtering cannot disagree. Operator entries win;
/// detector TOML values fill only missing ids. Both sources are validated at
/// their load boundaries, so this function never clamps or silently rewrites a
/// value.
pub(super) fn compose_detector_min_confidence(
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
    /// `None` uses persisted autoroute evidence and fails closed when that state
    /// is invalid. When `Some`, the per-file scan never consults the autoroute
    /// cache, so the runtime works on an uncalibrated binary.
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
    ) -> Result<Self> {
        let router =
            cached_autoroute_router_for_default_config(&scanner, detectors, backend_override)?;
        Ok(Self::new_with_router(scanner, detectors, router)
            .with_backend_override(backend_override))
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
            #[cfg(feature = "gpu")]
            selection.ordered_gpu.as_deref(),
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
        Ok(outcome.per_chunk.into_iter().flatten().collect())
    }

    pub(crate) fn clear_fragment_cache(&self) {
        self.scanner.clear_fragment_cache();
    }

    pub(crate) fn into_parts(self) -> (Arc<CompiledScanner>, CachedBackendRouter) {
        (self.scanner, self.router)
    }
}

pub(super) fn default_runtime_gpu_init_policy(
    backend_override: Option<keyhog_scanner::ScanBackend>,
) -> GpuInitPolicy {
    backend_override.map_or(
        GpuInitPolicy::FromRuntimePolicy,
        GpuInitPolicy::SelectedBackend,
    )
}

pub(crate) fn compile_default_scan_runtime(
    detectors: Vec<DetectorSpec>,
    backend_override: Option<keyhog_scanner::ScanBackend>,
    map_compile_error: impl FnOnce(&keyhog_scanner::ScanError) -> anyhow::Error,
) -> Result<DefaultScanRuntime> {
    let gpu_policy = default_runtime_gpu_init_policy(backend_override);
    let detectors: Arc<[DetectorSpec]> = detectors.into();
    let scanner = Arc::new(
        CompiledScanner::compile_shared_with_gpu_policy_and_tuning(
            Arc::clone(&detectors),
            gpu_policy,
            &keyhog_scanner::ScannerTuningConfig::default(),
        )
        .map_err(|error| map_compile_error(&error))?,
    );
    DefaultScanRuntime::new(scanner, &detectors, backend_override)
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
    let mut disabled_detectors = effective_config.disabled_detectors.clone();
    if !disabled_detectors.is_empty() {
        let before = detectors.len();
        filter_disabled_detectors(&mut detectors, &mut disabled_detectors);
        if detectors.is_empty() && before > 0 {
            anyhow::bail!(
                "all {before} loaded detector(s) were disabled by .keyhog.toml \
                 [detector.<id>] enabled = false. Leave at least one detector enabled to run \
                 `{subcommand_name}`, or remove the config."
            );
        }
    }

    // Before composition: per-invocation floors belong to the config digest, not
    // to corpus identity.
    let rules_digest = corpus_rules_digest(&detectors)?;

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
        .with_config(effective_config.engine_scanner_config()),
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

