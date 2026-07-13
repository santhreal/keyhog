use crate::args::ScanArgs;
use anyhow::Result;
use std::path::PathBuf;

/// Hard ceiling on the worker thread count. Requested values above this are
/// clamped by [`sanitise_thread_count`]; spawning thousands of threads thrashes
/// the OS scheduler without speeding the scan up.
pub(crate) const MAX_THREADS_CAP: usize = 256;

/// Documented conventional ML threshold value.
///
/// `ScanArgs::ml_threshold` is optional so the runtime can distinguish an
/// absent flag/config from an explicit `0.5`.
pub(crate) const ML_THRESHOLD_DEFAULT: f64 = 0.5;
pub(crate) const VERIFY_TIMEOUT_DEFAULT_SECS: u64 = 5;
pub(crate) const VERIFY_MAX_CONCURRENT_DEFAULT: usize = 5;
#[cfg(feature = "git")]
pub(crate) const MAX_COMMITS_DEFAULT: usize = 1000;

/// Default chunk batch size for the fused filesystem read+scan pipeline.
pub(crate) const FUSED_BATCH_DEFAULT: usize = 32;

/// Default bounded-channel depth for fused filesystem batches.
pub(crate) fn fused_depth_default(worker_threads: usize) -> usize {
    worker_threads
        .saturating_add(3)
        .saturating_div(4)
        .clamp(2, 8)
}

pub(crate) fn parse_backend_override(
    raw: Option<&str>,
) -> Result<Option<keyhog_scanner::ScanBackend>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("auto") {
        return Ok(None);
    }
    let operator_value = keyhog_scanner::hw_probe::BACKEND_OVERRIDE_VALUES
        .iter()
        .copied()
        .find(|value| !value.eq_ignore_ascii_case("auto") && value.eq_ignore_ascii_case(trimmed));
    operator_value
        .and_then(keyhog_scanner::hw_probe::parse_backend_str)
        .map(Some)
        .ok_or_else(|| {
            let supported = keyhog_scanner::hw_probe::BACKEND_OVERRIDE_VALUES.join(", ");
            anyhow::anyhow!(
                "invalid --backend value {:?}. Supported values: {supported}.",
                raw
            )
        })
}

pub(crate) fn backend_override_label(backend: Option<keyhog_scanner::ScanBackend>) -> &'static str {
    backend.map_or("auto", keyhog_scanner::ScanBackend::label)
}

/// Canonical value accepted by the public `--backend` parser for a resolved
/// backend. The engine's diagnostic label for the scalar CPU implementation is
/// `cpu-fallback`, while the stable operator spelling is `cpu`.
pub(crate) fn backend_override_cli_value(backend: keyhog_scanner::ScanBackend) -> &'static str {
    match backend {
        keyhog_scanner::ScanBackend::Gpu => "gpu",
        keyhog_scanner::ScanBackend::SimdCpu => "simd",
        keyhog_scanner::ScanBackend::CpuFallback => "cpu",
        _ => backend.label(),
    }
}

pub(crate) fn gpu_runtime_policy_from_args(
    args: &ScanArgs,
) -> keyhog_scanner::gpu::GpuRuntimePolicy {
    if args.require_gpu {
        keyhog_scanner::gpu::GpuRuntimePolicy::Required
    } else if args.no_gpu || explicit_cpu_backend(args) {
        keyhog_scanner::gpu::GpuRuntimePolicy::Disabled
    } else {
        keyhog_scanner::gpu::GpuRuntimePolicy::Auto
    }
}

pub(crate) fn gpu_runtime_policy_for_backend_override(
    backend: Option<keyhog_scanner::ScanBackend>,
) -> Result<keyhog_scanner::gpu::GpuRuntimePolicy> {
    let policy = match backend {
        Some(keyhog_scanner::ScanBackend::Gpu) => keyhog_scanner::gpu::GpuRuntimePolicy::Required,
        Some(keyhog_scanner::ScanBackend::SimdCpu | keyhog_scanner::ScanBackend::CpuFallback) => {
            keyhog_scanner::gpu::GpuRuntimePolicy::Disabled
        }
        None => keyhog_scanner::gpu::GpuRuntimePolicy::Auto,
        Some(backend) => anyhow::bail!(
            "daemon GPU runtime policy is undefined for backend {}; update the daemon policy mapping",
            backend.label()
        ),
    };
    Ok(policy)
}

#[cfg(test)]
mod daemon_gpu_policy_tests {
    use super::gpu_runtime_policy_for_backend_override;
    use keyhog_scanner::{gpu::GpuRuntimePolicy, ScanBackend};

    #[test]
    fn explicit_daemon_backend_owns_the_matching_gpu_policy() {
        assert_eq!(
            gpu_runtime_policy_for_backend_override(Some(ScanBackend::Gpu)).unwrap(),
            GpuRuntimePolicy::Required,
        );
        assert_eq!(
            gpu_runtime_policy_for_backend_override(Some(ScanBackend::SimdCpu)).unwrap(),
            GpuRuntimePolicy::Disabled,
        );
        assert_eq!(
            gpu_runtime_policy_for_backend_override(Some(ScanBackend::CpuFallback)).unwrap(),
            GpuRuntimePolicy::Disabled,
        );
        assert_eq!(
            gpu_runtime_policy_for_backend_override(None).unwrap(),
            GpuRuntimePolicy::Auto,
        );
    }
}

/// True when the operator explicitly selected a CPU-only backend
/// (`--backend cpu`/`--backend simd`). Such a scan never acquires the GPU, so
/// the resolved policy is `Disabled`: this keeps `gpu_probe()` from creating a
/// wgpu/Vulkan instance the scan would never use. Beyond skipping a pointless
/// (and slow) Vulkan init on the CPU path (Law 7), it prevents a real crash
/// the probe spawns a mesa driver worker thread that SIGSEGVs during teardown
/// if the process exits fast on an early error (expired `.keyhogignore`,
/// missing scan path) before the driver finishes initialising, turning a clean
/// fail-closed `exit(2)` into a signal death (exit 139). `auto` (no explicit
/// `--backend`) is intentionally NOT treated as CPU-only: autoroute legitimately
/// probes to choose a backend.
fn explicit_cpu_backend(args: &ScanArgs) -> bool {
    args.backend
        .as_deref()
        .and_then(keyhog_scanner::hw_probe::parse_backend_str)
        .is_some_and(|backend| !matches!(backend, keyhog_scanner::ScanBackend::Gpu))
}

#[derive(Debug, Clone)]
pub(crate) struct ScanRuntimeInput {
    pub(crate) cache_dir: Option<PathBuf>,
    pub(crate) autoroute_cache: Option<String>,
    pub(crate) calibration_cache: Option<PathBuf>,
    pub(crate) backend: Option<String>,
    pub(crate) batch_pipeline: bool,
    pub(crate) threads: Option<usize>,
    pub(crate) reader_threads: Option<usize>,
    pub(crate) fused_batch: usize,
    pub(crate) fused_depth: Option<usize>,
    pub(crate) gpu_runtime_policy: keyhog_scanner::gpu::GpuRuntimePolicy,
    pub(crate) autoroute_gpu: bool,
    pub(crate) autoroute_calibration: bool,
    pub(crate) regex_dfa_limit: Option<usize>,
    pub(crate) gpu_batch_input_limit: Option<usize>,
    pub(crate) max_file_size: Option<usize>,
    #[cfg(feature = "git")]
    pub(crate) max_commits: usize,
    pub(crate) no_default_excludes: bool,
    pub(crate) exclude_paths: Vec<String>,
    pub(crate) incremental: bool,
    pub(crate) incremental_cache_path: Option<PathBuf>,
    pub(crate) source_limits: keyhog_sources::SourceLimits,
}

impl ScanRuntimeInput {
    pub(crate) fn from_scan_args(args: &ScanArgs) -> Self {
        Self {
            cache_dir: args.cache_dir.clone(),
            autoroute_cache: args.autoroute_cache.clone(),
            calibration_cache: args.calibration_cache.clone(),
            backend: args.backend.clone(),
            batch_pipeline: args.batch_pipeline && !args.no_batch_pipeline,
            threads: args.threads,
            reader_threads: args.reader_threads,
            fused_batch: args.fused_batch.unwrap_or(FUSED_BATCH_DEFAULT), // LAW10: absent fused-batch config => documented compiled throughput default; no recall path changes and the value is printed/hashes into autoroute identity
            fused_depth: args.fused_depth,
            gpu_runtime_policy: gpu_runtime_policy_from_args(args),
            autoroute_gpu: args.autoroute_gpu && !args.no_autoroute_gpu,
            autoroute_calibration: args.autoroute_calibrate,
            regex_dfa_limit: args.regex_dfa_limit,
            gpu_batch_input_limit: args.gpu_batch_input_limit,
            max_file_size: args.max_file_size,
            #[cfg(feature = "git")]
            max_commits: args.max_commits.unwrap_or(MAX_COMMITS_DEFAULT), // LAW10: absent max-commits => documented compiled git traversal cap; effective config prints the concrete value and source construction consumes this resolved field
            no_default_excludes: args.no_default_excludes,
            exclude_paths: match &args.exclude_paths {
                Some(paths) => paths.clone(),
                None => Vec::new(),
            },
            incremental: args.incremental,
            incremental_cache_path: args.incremental_cache.clone(),
            source_limits: args.limits.to_source_limits(),
        }
    }
}

pub(crate) fn configure_threads(threads: Option<usize>, physical_cores: usize) {
    // Resolution order: --threads / [scan].threads > physical core count.
    // Physical cores are the right default for CPU-bound regex: SMT siblings
    // share execution units, so doubling threads mostly doubles cache pressure.
    let (n, source) = if let Some(t) = threads {
        (
            sanitise_thread_count(t, physical_cores, "cli-arg"),
            "cli-arg",
        )
    } else {
        (physical_cores.max(1), "physical-cores")
    };

    let builder = rayon::ThreadPoolBuilder::new()
        .num_threads(n)
        .stack_size(8 * 1024 * 1024)
        .thread_name(|i| format!("keyhog-worker-{i}"));

    if let Err(error) = builder.build_global() {
        tracing::warn!(
            requested_threads = n,
            source,
            "failed to configure rayon thread pool: {error}"
        );
    } else {
        tracing::info!(
            threads = n,
            source,
            physical_cores,
            "rayon thread pool configured"
        );
    }
}

pub(crate) fn configure_hyperscan_cache_dir(cache_dir: Option<PathBuf>) -> Result<()> {
    if let Some(path) = cache_dir.as_ref() {
        if !path.is_absolute() {
            anyhow::bail!(
                "Hyperscan cache dir '{}' must be absolute. Fix: pass an absolute path under \
                 your home directory or the per-user keyhog temp cache root.",
                path.display()
            );
        }
    }

    #[cfg(feature = "simd")]
    {
        if let Some(path) = cache_dir.as_ref() {
            keyhog_scanner::validate_hyperscan_cache_dir(path).map_err(|error| {
                anyhow::anyhow!("{error}. Configure with --cache-dir or [system].cache_dir")
            })?;
        }
        keyhog_scanner::set_hyperscan_cache_dir(cache_dir);
    }

    #[cfg(not(feature = "simd"))]
    {
        if cache_dir.is_some() {
            anyhow::bail!(
                "--cache-dir / [system].cache_dir requires a keyhog build with the simd \
                 feature; this binary has no Hyperscan cache to configure"
            );
        }
    }

    Ok(())
}

/// Clamp a user-supplied thread count to a sane range. Logs a warning when the
/// value was outside the accepted bounds so an operator sees what was used.
fn sanitise_thread_count(requested: usize, physical_cores: usize, source: &'static str) -> usize {
    let safe_default = physical_cores.max(1);
    if requested == 0 {
        eprintln!(
            "keyhog: invalid {source} thread count 0; expected an integer >= 1; using {safe_default}"
        );
        tracing::warn!(
            source,
            requested = 0,
            using = safe_default,
            "thread count of 0 is not meaningful; falling back to physical-cores"
        );
        return safe_default;
    }
    if requested > MAX_THREADS_CAP {
        eprintln!(
            "keyhog: {source} thread count {requested} exceeds cap {MAX_THREADS_CAP}; using {MAX_THREADS_CAP}"
        );
        tracing::warn!(
            source,
            requested,
            cap = MAX_THREADS_CAP,
            "requested thread count exceeds cap; clamping"
        );
        return MAX_THREADS_CAP;
    }
    requested
}

#[doc(hidden)]
pub(crate) mod testing {
    pub(crate) fn sanitise_thread_count(
        requested: usize,
        physical_cores: usize,
        source: &'static str,
    ) -> usize {
        super::sanitise_thread_count(requested, physical_cores, source)
    }
}
