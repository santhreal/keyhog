//! Core scanning orchestration logic for the KeyHog CLI.

mod allowlist;
mod dispatch;
mod postprocess;
mod reporting;
mod run;

use crate::args::ScanArgs;
use crate::orchestrator_config::{
    ResolvedScanConfig, auto_discover_detectors, autoroute_config_digest, configure_threads,
    load_detectors_no_cache, load_detectors_with_cache, resolve_scan_config,
    resolved_scan_config_for_scanner,
};
use anyhow::{Context, Result};
use keyhog_core::{DetectorSpec, RawMatch, Source};
use keyhog_scanner::{CompiledScanner, GpuInitPolicy};
use std::path::PathBuf;
use std::sync::Arc;

pub use crate::exit_codes::{EXIT_LIVE_CREDENTIALS, EXIT_SCANNER_PANIC};

fn default_incremental_cache_path() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("keyhog").join("merkle.idx"))
}

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
pub(crate) use postprocess::offline_finding_metadata;

#[doc(hidden)]
pub use dispatch::{backend_requires_coalesced_batch_pipeline_for_test, explicit_backend_override};

pub(crate) use dispatch::CachedBackendRouter;

pub(crate) fn cached_autoroute_router_for_default_config(
    scanner: &CompiledScanner,
    detectors: &[DetectorSpec],
) -> CachedBackendRouter {
    let hw_caps = keyhog_scanner::hw_probe::probe_hardware().clone();
    let pattern_count = scanner.runtime_status().pattern_count;
    let rules_digest = keyhog_core::hex_encode(&keyhog_core::compute_spec_hash(detectors));
    let resolved = resolved_scan_config_for_scanner(keyhog_scanner::ScannerConfig::default());
    let config_digest = autoroute_config_digest(&resolved);
    CachedBackendRouter::new(hw_caps, pattern_count, rules_digest, config_digest, scanner)
}

#[doc(hidden)]
pub fn gpu_init_policy_for_args_for_test(args: &ScanArgs) -> GpuInitPolicy {
    gpu_init_policy_for_args(args)
}

#[doc(hidden)]
pub fn allowlist_root_for_test(path: &std::path::Path) -> std::path::PathBuf {
    allowlist::allowlist_root(path)
}

#[doc(hidden)]
pub fn scanner_panic_notice_for_test(panicked: bool) -> Option<String> {
    reporting::scanner_panic_notice(panicked)
}

pub struct ScanOrchestrator {
    pub(crate) args: ScanArgs,
    pub(crate) detectors: Vec<DetectorSpec>,
    pub(crate) scanner: Arc<CompiledScanner>,
    pub(crate) signatures: std::collections::HashSet<Arc<str>>,
    pub(crate) test_fixture_suppressions: crate::test_fixture_suppressions::TestFixtureSuppressions,
    /// Detector ids disabled via `.keyhog.toml` `[detector.<id>] enabled = false`.
    /// TOML-corpus detectors are also dropped at load (so they never compile),
    /// but the hardcoded hot-pattern fast path is not part of that corpus, so
    /// their findings are filtered here in `filter_and_resolve` - making the
    /// documented toggle work for every detector, hot or TOML.
    pub(crate) disabled_detectors: std::collections::HashSet<String>,
    /// Per-detector confidence floors from `.keyhog.toml`
    /// `[detector.<id>] min_confidence = <f>`. Applied in `filter_and_resolve`:
    /// a finding from `<id>` below this threshold is dropped, overriding the
    /// global `--min-confidence`. Empty when no per-detector overrides are set.
    pub(crate) detector_min_confidence: std::collections::HashMap<String, f64>,
    /// Fully resolved scan policy used by the engine and post-processing.
    pub(crate) effective_config: ResolvedScanConfig,
}

impl ScanOrchestrator {
    pub fn new(mut args: ScanArgs) -> Result<Self> {
        // Grep/wc/curl convention: a positional `-` means "read from
        // stdin". Some users will try `keyhog scan - --stdin <<<...`
        // and otherwise hit `error: path '-' does not exist`. Promote
        // bare `-` to `--stdin` and drop it from the path slot so the
        // existing stdin-reading source picks up. Falls through cleanly
        // when `--stdin` was already passed.
        if matches!(args.input.as_deref().and_then(|p| p.to_str()), Some("-"))
            || matches!(args.path.as_deref().and_then(|p| p.to_str()), Some("-"))
        {
            args.stdin = true;
            args.input = None;
            args.path = None;
        }
        if args.path.is_none() {
            args.path = args.input.clone();
        }
        #[cfg(feature = "git")]
        if args.git_staged && args.path.is_none() {
            args.path = Some(PathBuf::from("."));
        }
        let mut effective_config = resolve_scan_config(&mut args)?;
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

        // Tier-A: per-regex lazy-DFA cache cap (default 1 MiB → .keyhog.toml →
        // --regex-dfa-limit). Set the process-global BEFORE any detector regex
        // compiles, so the cap takes effect on the per-worker DFA caches that
        // dominate scan memory. 0 = use the compiled default.
        keyhog_scanner::types::set_regex_dfa_limit(args.regex_dfa_limit.unwrap_or(0)); // LAW10: empty/absent => documented numeric default, recall-safe

        let hw = keyhog_scanner::hw_probe::probe_hardware();
        configure_threads(args.threads, hw.physical_cores);

        let detectors_path = auto_discover_detectors(&args.detectors)?;
        let mut detectors = if args.lockdown {
            load_detectors_no_cache(&detectors_path)
                .context("loading detectors (lockdown: cache disabled)")?
        } else {
            load_detectors_with_cache(&detectors_path)?
        };

        // Seed self-declared per-detector floors from the corpus. `or_insert`
        // means an operator `.keyhog.toml` value (already present) wins; a
        // detector that declares `min_confidence` in its own TOML supplies the
        // default for any id the operator did not pin. Clamped to [0,1] so a
        // malformed spec can never invert the gate. Zero scan-time cost: the
        // post-scan floor gate already does this map lookup per finding.
        for d in &detectors {
            if let Some(mc) = d.min_confidence {
                detector_min_confidence
                    .entry(d.id.clone())
                    .or_insert(mc.clamp(0.0, 1.0));
            }
        }

        // Apply `[detector.<id>] enabled = false` from .keyhog.toml: drop the
        // disabled detectors from the corpus so they never compile or fire.
        // (Previously this config key was parsed and silently ignored.)
        if !disabled_detectors.is_empty() {
            let before = detectors.len();
            detectors.retain(|d| !disabled_detectors.iter().any(|id| id == &d.id));
            let dropped = before - detectors.len();
            if dropped > 0 {
                tracing::info!(
                    target: "keyhog::config",
                    dropped,
                    "disabled detectors via .keyhog.toml [detector.<id>] enabled = false"
                );
            } else {
                eprintln!(
                    "⚠️  .keyhog.toml disables detector id(s) {disabled_detectors:?}, but none matched the loaded corpus. \
                     Detector ids come from `keyhog detectors` (e.g. hot-pattern ids are prefixed `hot-`)."
                );
            }
        }

        // Low-RAM host adaptation: shrink the decode window and per-chunk match
        // cap on machines with < 4 GiB RAM so a deep-decode scan can't OOM. This
        // DIVERGES from the configured/documented values, so per Law 10 it is
        // surfaced LOUDLY (once per process) rather than silently applied — the
        // operator must be able to see why their effective decode window is
        // smaller than what they set. The capped values are also what the
        // `KEYHOG_PRINT_EFFECTIVE_CONFIG=1` oracle prints (this mutation lands in
        // `effective_config` before it is handed to the orchestrator), so "what
        // runs" stays a single auditable answer.
        if let Some(mem_mb) = hw.total_memory_mb {
            if mem_mb < 4096 {
                let prev_matches = effective_config.scanner.max_matches_per_chunk;
                let prev_decode = effective_config.scanner.max_decode_bytes;
                let new_matches = prev_matches.min(500);
                let new_decode = prev_decode.min(256 * 1024);
                effective_config.scanner.max_matches_per_chunk = new_matches;
                effective_config.scanner.max_decode_bytes = new_decode;
                if new_matches != prev_matches || new_decode != prev_decode {
                    static LOW_RAM_CAP_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
                    if LOW_RAM_CAP_WARNED.set(()).is_ok() {
                        eprintln!(
                            "keyhog: low-RAM host ({mem_mb} MiB < 4096) — capping scan limits to \
                             avoid OOM: max_decode_bytes {prev_decode} → {new_decode}, \
                             max_matches_per_chunk {prev_matches} → {new_matches}. Set these \
                             explicitly in .keyhog.toml or via flags to override; run with \
                             KEYHOG_PRINT_EFFECTIVE_CONFIG=1 to see the full resolved config."
                        );
                    }
                }
            }
        }
        effective_config.min_confidence = effective_config.scanner.min_confidence;
        effective_config.ml_enabled = effective_config.scanner.ml_enabled;

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

        let gpu_init_policy = gpu_init_policy_for_args(&args);
        let scanner = Arc::new(
            CompiledScanner::compile_with_gpu_policy(detectors.clone(), gpu_init_policy)
                .with_context(|| {
                    format!("compiling scanner from {} detector specs", detectors.len())
                })?
                .with_config(effective_config.scanner.clone()),
        );

        // Detector regexes compile lazily on first use. Warm the whole set in
        // parallel now, on every scan, instead of letting the first file pay a
        // serial first-touch compile of each detector. The earlier `is_dir`
        // gate was meant to keep one-shot single-file/stdin startup fast, but it
        // backfired: a single-file scan then fell into a SERIAL lazy compile of
        // all embedded regexes on the hot path (~340ms measured), strictly slower
        // than the parallel `warm()` a directory scan got. Single file, stdin,
        // pre-commit hooks and editor integrations all hit that worst case.
        // `warm()` is idempotent and a no-op for already-compiled patterns, so
        // warming unconditionally costs nothing the lazy path would not have
        // paid anyway - it just parallelizes it.
        scanner.warm();

        let signatures: std::collections::HashSet<Arc<str>> = detectors
            .iter()
            .flat_map(|d| d.patterns.iter().map(|p| Arc::from(p.regex.as_str())))
            .chain(
                detectors
                    .iter()
                    .flat_map(|d| d.companions.iter().map(|c| Arc::from(c.regex.as_str()))),
            )
            .collect();

        let test_fixture_suppressions = if args.no_suppress_test_fixtures {
            crate::test_fixture_suppressions::TestFixtureSuppressions::empty()
        } else {
            crate::test_fixture_suppressions::TestFixtureSuppressions::bundled()
        };

        Ok(Self {
            args,
            detectors,
            scanner,
            signatures,
            test_fixture_suppressions,
            disabled_detectors,
            detector_min_confidence,
            effective_config,
        })
    }

    pub fn scanner(&self) -> &CompiledScanner {
        self.scanner.as_ref()
    }

    pub fn args(&self) -> &ScanArgs {
        &self.args
    }

    pub(crate) fn incremental_cache_path(&self) -> Option<std::path::PathBuf> {
        if !self.args.incremental {
            return None;
        }
        if self.args.lockdown {
            tracing::warn!("lockdown mode: --incremental disabled (cache writes refused)");
            return None;
        }
        self.configured_incremental_cache_path()
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
            .or_else(default_incremental_cache_path)
    }

    pub(crate) fn build_merkle_index(&self) -> Option<Arc<keyhog_core::merkle_index::MerkleIndex>> {
        let path = self.incremental_cache_path()?;
        let spec_hash = keyhog_core::merkle_index::compute_spec_hash(&self.detectors);
        let idx = keyhog_core::merkle_index::MerkleIndex::load_with_spec(&path, &spec_hash);
        tracing::info!("incremental scan: loaded merkle index");
        Some(Arc::new(idx))
    }

    /// Test-only entry point for the producer/scanner pipeline.
    #[doc(hidden)]
    pub fn scan_sources_for_test(
        &self,
        sources: Vec<Box<dyn Source>>,
        show_progress: bool,
        merkle: Option<Arc<keyhog_core::merkle_index::MerkleIndex>>,
    ) -> Result<Vec<RawMatch>> {
        let prior_backend = std::env::var_os("KEYHOG_BACKEND");
        if prior_backend.is_none() {
            // SAFETY: this test-only entry point runs synchronously before the
            // dispatch workers are created. It pins deterministic SIMD routing
            // so pipeline unit tests exercise scanner behavior without needing
            // installer autoroute calibration artifacts.
            unsafe {
                std::env::set_var("KEYHOG_BACKEND", "simd");
            }
        }
        let result = self.scan_sources(sources, show_progress, merkle);
        match prior_backend {
            Some(value) => unsafe {
                // SAFETY: test-only restoration after dispatch workers have
                // joined; no scanner thread is still reading KEYHOG_BACKEND.
                std::env::set_var("KEYHOG_BACKEND", value);
            },
            None => unsafe {
                // SAFETY: test-only restoration after dispatch workers have
                // joined; no scanner thread is still reading KEYHOG_BACKEND.
                std::env::remove_var("KEYHOG_BACKEND");
            },
        }
        result
    }

    /// Test-only constructor bypassing detector-cache and lockdown gating.
    #[doc(hidden)]
    pub fn from_parts_for_test(
        args: ScanArgs,
        detectors: Vec<DetectorSpec>,
        scanner: Arc<CompiledScanner>,
        signatures: std::collections::HashSet<Arc<str>>,
        test_fixture_suppressions: crate::test_fixture_suppressions::TestFixtureSuppressions,
    ) -> Self {
        Self {
            args,
            detectors,
            scanner,
            signatures,
            test_fixture_suppressions,
            disabled_detectors: std::collections::HashSet::new(),
            detector_min_confidence: std::collections::HashMap::new(),
            effective_config: ResolvedScanConfig {
                scanner: keyhog_scanner::ScannerConfig::default(),
                min_confidence: keyhog_scanner::ScannerConfig::default().min_confidence,
                ml_enabled: keyhog_scanner::ScannerConfig::default().ml_enabled,
                detector_min_confidence: std::collections::HashMap::new(),
                disabled_detectors: std::collections::HashSet::new(),
                require_lockdown: false,
                regex_dfa_limit: None,
                source_limits: keyhog_sources::SourceLimits::default(),
            },
        }
    }
}

fn gpu_init_policy_for_args(args: &ScanArgs) -> GpuInitPolicy {
    // GPU init (which acquires the wgpu backend the megakernel needs) follows the
    // selected backend: an explicit `--backend gpu`/`KEYHOG_BACKEND=gpu`, or the
    // measured backend-selection policy below.
    if let Some(policy) = backend_name_gpu_policy(args.backend.as_deref()) {
        return policy;
    }
    if let Some(policy) = explicit_backend_override().map(backend_gpu_policy) {
        return policy;
    }
    if filesystem_auto_scan_cannot_route_gpu(args)
        && std::env::var("KEYHOG_REQUIRE_GPU").as_deref() != Ok("1")
        && !env_explicitly_enables_gpu()
    {
        return GpuInitPolicy::ForceDisabled;
    }
    GpuInitPolicy::FromEnvironment
}

fn backend_name_gpu_policy(name: Option<&str>) -> Option<GpuInitPolicy> {
    let name = name?.trim();
    // "auto" is the explicit defer-to-routing choice (FromEnvironment), and is
    // not a backend `parse_backend_str` recognizes.
    if name.eq_ignore_ascii_case("auto") {
        return None;
    }
    // Single source of truth for backend-string parsing is the scanner's
    // `parse_backend_str` (case-insensitive, owns every alias). Map its
    // ScanBackend verdict to a GPU-init policy via `backend_gpu_policy` instead
    // of re-listing every alias here — the two alias lists had already drifted
    // apart, so a `--backend` value added to one was invisible to the other.
    keyhog_scanner::hw_probe::parse_backend_str(name).map(backend_gpu_policy)
}

fn backend_gpu_policy(backend: keyhog_scanner::ScanBackend) -> GpuInitPolicy {
    match backend {
        keyhog_scanner::ScanBackend::Gpu | keyhog_scanner::ScanBackend::MegaScan => {
            GpuInitPolicy::ForceEnabled
        }
        keyhog_scanner::ScanBackend::SimdCpu | keyhog_scanner::ScanBackend::CpuFallback => {
            GpuInitPolicy::ForceDisabled
        }
        _ => GpuInitPolicy::FromEnvironment,
    }
}

fn env_explicitly_enables_gpu() -> bool {
    std::env::var("KEYHOG_NO_GPU")
        .map(|v| matches!(v.as_str(), "" | "0" | "false" | "FALSE" | "off" | "OFF"))
        .unwrap_or(false) // LAW10: empty/absent => documented numeric default, recall-safe
}

fn filesystem_auto_scan_cannot_route_gpu(args: &ScanArgs) -> bool {
    if std::env::var_os("KEYHOG_BATCH_PIPELINE").is_some() {
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
