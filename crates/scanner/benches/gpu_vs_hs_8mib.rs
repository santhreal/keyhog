//! Apples-to-apples 8 MiB baseline: Hyperscan/SimdCpu vs GPU region presence.
//!
//! Same `CompiledScanner` (real detector catalog), same production-style 1 MiB
//! windows with 128 KiB overlap over an 8 MiB file, same
//! `scan_coalesced_with_backend` entry. Every acquired CUDA and WGPU peer is
//! measured independently. The layout lets the Hyperscan path use
//! its production coalesced trigger pass and real Rayon parallelism instead of
//! handicapping it behind one oversized sequential chunk. `SimdCpu`
//! runs the Hyperscan literal prefilter; each GPU peer routes the batch through VYRE
//! `ResidentFusedRegionScan`. Timing includes each
//! backend's production batching, scheduling, phase 2, and post-processing.
//!
//! Pass `-- --perf-trace` to get the region-presence phase breakdown
//! (matcher / coalesce / dispatch / floor / phase2_gpu / phase2) and VYRE
//! dispatch telemetry on stderr. Trace instrumentation is intentionally not a
//! crossover measurement: it adds GPU-specific timers and counters, so the
//! speed gate is enforced only by the normal untraced, unprofiled run.
//! `--diagnostic` keeps timing unprofiled but makes the run ineligible for a
//! release verdict, allowing measurements from an explicitly dirty worktree.
//! `--profile` keeps selection and held-out timing unprofiled, then records one
//! isolated production scan for each Hyperscan route and the selected GPU route.
//! Full-result parity and zero GPU degradation remain mandatory in every mode.
//! Plain-pattern and keyword-anchor localization are independent candidates for
//! every backend. `KH_BENCH_PHASE2_PLAIN_LOCALIZER=1|0` and
//! `KH_BENCH_PHASE2_KEYWORD_LOCALIZER=1|0` restrict diagnostic runs; the release
//! gate refuses either restriction and measures all four plans for every peer.
//!
//! Selection uses rotating candidate order. The selected exact GPU route then
//! receives fresh rotating held-out comparisons against every Hyperscan route.
//! The release gate pairs GPU time with the fastest Hyperscan observation in
//! each trial and requires that ratio's 95% confidence upper bound below 1.0.

use keyhog_core::{
    load_detectors,
    timing::{median_duration, paired_ratio_confidence_95},
    Chunk, ChunkMetadata, RawMatch,
};
use keyhog_scanner::{
    set_perf_trace_enabled, set_profile_enabled, CompiledScanner, ScanBackend, ScanExecutionRoute,
    ScannerTuningConfig,
};
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const MIB: usize = 1024 * 1024;
const WINDOW_OVERLAP: usize = 128 * 1024;
// The measured crossover is close enough that 20 pairs produced a 95% interval
// spanning parity. These floors distinguish a repeatable 1% win from noise
// without reusing peer-selection samples as held-out evidence.
const RELEASE_HELD_OUT_PAIRS: usize = 100;
const RELEASE_SELECTION_ROUNDS: usize = 20;

#[derive(serde::Serialize)]
struct TimingSampleArtifact {
    backend: String,
    phase2_plain_localizer: bool,
    phase2_keyword_localizer: bool,
    round: usize,
    order: usize,
    nanoseconds: u128,
}

#[derive(serde::Serialize)]
struct TimingPairArtifact {
    pair: usize,
    order: String,
    hyperscan_backend: String,
    hyperscan_phase2_plain_localizer: bool,
    hyperscan_phase2_keyword_localizer: bool,
    gpu_phase2_plain_localizer: bool,
    gpu_phase2_keyword_localizer: bool,
    hyperscan_nanoseconds: u128,
    gpu_nanoseconds: u128,
}

#[derive(serde::Serialize)]
struct HyperscanComparisonArtifact {
    backend: String,
    phase2_plain_localizer: bool,
    phase2_keyword_localizer: bool,
    hyperscan_median_nanoseconds: u128,
    gpu_median_nanoseconds: u128,
    ratio_geometric_mean: f64,
    ratio_ci95_low: f64,
    ratio_ci95_high: f64,
}

#[derive(serde::Serialize)]
struct GpuPeerArtifact {
    backend: String,
    acquired: bool,
    driver: String,
    driver_version: String,
    device: String,
    runtime: String,
    acquisition_error: String,
}

#[derive(serde::Serialize)]
struct CrossoverArtifact {
    schema_version: u32,
    measured_at_utc: String,
    diagnostic: bool,
    production_comparable: bool,
    crossover_passed: bool,
    git_hash: String,
    build_source_tree_state: String,
    source_tree_state: String,
    binary_sha256: String,
    detector_spec_blake3: String,
    scanner_detector_digest: String,
    resolved_tuning: String,
    compiled_features: String,
    command: String,
    os: String,
    arch: String,
    cpu_model: String,
    physical_cores: usize,
    logical_cores: usize,
    total_memory_mb: Option<u64>,
    simd_features: String,
    fastest_hyperscan_backend: String,
    fastest_hyperscan_phase2_plain_localizer: bool,
    fastest_hyperscan_phase2_keyword_localizer: bool,
    hyperscan_reference: String,
    selected_gpu_backend: String,
    selected_gpu_phase2_plain_localizer: bool,
    selected_gpu_phase2_keyword_localizer: bool,
    selected_gpu_driver: String,
    selected_gpu_driver_version: String,
    selected_gpu_device: String,
    selected_gpu_runtime: String,
    gpu_peers: Vec<GpuPeerArtifact>,
    source_bytes: usize,
    scanned_bytes: usize,
    chunk_bytes: usize,
    overlap_bytes: usize,
    chunks: usize,
    detectors: usize,
    reference_findings: usize,
    selection_rounds: usize,
    held_out_pairs: usize,
    full_result_parity: bool,
    gpu_degraded: bool,
    ratio_geometric_mean: f64,
    ratio_ci95_low: f64,
    ratio_ci95_high: f64,
    hyperscan_route_comparisons: Vec<HyperscanComparisonArtifact>,
    selection_samples: Vec<TimingSampleArtifact>,
    held_out_samples: Vec<TimingPairArtifact>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BenchRoute {
    backend: ScanBackend,
    phase2_plain_localizer: bool,
    phase2_keyword_localizer: bool,
}

impl BenchRoute {
    fn label(self) -> String {
        format!(
            "{}+plain-localizer={}+keyword-localizer={}",
            self.backend.label(),
            self.phase2_plain_localizer,
            self.phase2_keyword_localizer
        )
    }

    fn execution_route(self) -> ScanExecutionRoute {
        ScanExecutionRoute {
            decode_backend: if self.backend.is_gpu() {
                ScanBackend::CpuFallback
            } else {
                self.backend
            },
            phase2_plain_localizer: self.phase2_plain_localizer,
            phase2_keyword_localizer: self.phase2_keyword_localizer,
        }
    }
}

fn detectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detectors")
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn artifact_path(raw: std::ffi::OsString) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else {
        workspace_root().join(path)
    }
}

fn running_binary_sha256() -> Result<String, io::Error> {
    use sha2::{Digest, Sha256};

    let executable = env::current_exe()?;
    let mut file = std::fs::File::open(executable)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn source_tree_status(workspace_root: &Path) -> Result<Vec<u8>, io::Error> {
    let output = Command::new("git")
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .current_dir(workspace_root)
        .output()
        .map_err(|source| {
            io::Error::new(
                source.kind(),
                format!(
                    "cannot inspect benchmark source state in {}: {source}",
                    workspace_root.display()
                ),
            )
        })?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "git status failed while identifying benchmark source state in {}: {}",
            workspace_root.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(output.stdout)
}

fn current_source_tree_head(workspace_root: &Path) -> Result<String, io::Error> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .current_dir(workspace_root)
        .output()
        .map_err(|source| {
            io::Error::new(
                source.kind(),
                format!(
                    "cannot resolve benchmark source commit in {}: {source}",
                    workspace_root.display()
                ),
            )
        })?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "git rev-parse failed while identifying benchmark source in {}: {}",
            workspace_root.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let head = String::from_utf8(output.stdout)
        .map_err(|source| io::Error::new(io::ErrorKind::InvalidData, source))?;
    let head = head.trim();
    if head.len() != 40 || !head.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("git returned invalid benchmark source commit {head:?}"),
        ));
    }
    Ok(head.to_owned())
}

fn host_cpu_model() -> Result<String, io::Error> {
    #[cfg(target_os = "linux")]
    {
        let cpuinfo = fs::read_to_string("/proc/cpuinfo").map_err(|source| {
            io::Error::new(
                source.kind(),
                format!("cannot read /proc/cpuinfo for benchmark identity: {source}"),
            )
        })?;
        for line in cpuinfo.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            if matches!(
                key.trim().to_ascii_lowercase().as_str(),
                "model name" | "hardware"
            ) && !value.trim().is_empty()
            {
                return Ok(value.trim().to_owned());
            }
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "/proc/cpuinfo contains no non-empty model name or hardware field",
        ));
    }
    #[cfg(not(target_os = "linux"))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the crossover artifact requires a platform CPU-model probe",
    ))
}

fn write_artifact(path: &Path, artifact: &CrossoverArtifact) -> Result<(), io::Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        fs::create_dir_all(parent)?;
    }
    let rendered = toml::to_string_pretty(artifact).map_err(|source| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cannot encode crossover artifact as TOML: {source}"),
        )
    })?;
    let extension = match path.extension().and_then(|extension| extension.to_str()) {
        Some(extension) => extension,
        None => "toml",
    };
    let temporary = path.with_extension(format!("{extension}.tmp-{}", std::process::id()));
    fs::write(&temporary, rendered.as_bytes())?;
    fs::rename(&temporary, path).map_err(|source| {
        let cleanup = match fs::remove_file(&temporary) {
            Ok(()) => String::new(),
            Err(cleanup_error) => format!(
                "; temporary artifact {} also could not be removed: {cleanup_error}",
                temporary.display()
            ),
        };
        io::Error::new(
            source.kind(),
            format!(
                "cannot atomically publish crossover artifact {}: {source}{cleanup}",
                path.display(),
            ),
        )
    })
}

fn visible_peer_field<'a>(value: Option<&'a str>, absent: &'static str) -> &'a str {
    match value {
        Some(value) => value,
        None => absent,
    }
}

fn make_chunk(
    data: String,
    path: &str,
    base_offset: usize,
    base_line: usize,
    source_size: usize,
) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            base_offset,
            base_line,
            source_type: "filesystem/windowed".into(),
            path: Some(path.into()),
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: Some(source_size as u64),
            ..Default::default()
        },
    }
}

fn make_chunks(data: String, chunk_bytes: usize, overlap: usize) -> Vec<Chunk> {
    assert!(chunk_bytes > overlap, "window must exceed overlap");
    let stride = chunk_bytes - overlap;
    let source_size = data.len();
    let mut chunks = Vec::with_capacity(data.len().div_ceil(stride));
    let mut offset = 0usize;
    while offset < data.len() {
        let end = (offset + chunk_bytes).min(data.len());
        let chunk = &data[offset..end];
        let base_line = data.as_bytes()[..offset]
            .iter()
            .filter(|&&byte| byte == b'\n')
            .count();
        chunks.push(make_chunk(
            chunk.to_owned(),
            "src/bench_8mib.rs",
            offset,
            base_line,
            source_size,
        ));
        if end == data.len() {
            break;
        }
        offset += stride;
    }
    chunks
}

/// Realistic source-like text with a sparse real hit every ~64 KiB, so phase-2
/// runs on a few candidate windows (the common scan shape) rather than either
/// extreme (all-hit dense / zero-hit). 8 MiB total.
fn gen_payload(size: usize) -> String {
    let filler = "fn ordinary_function() { let x = compute_value(42); println!(\"{}\", x); }\n";
    let secret = "const api_key = \"sk_live_0123456789abcdefghijklmnopqrstuv\";\n";
    let mut s = String::with_capacity(size + 128);
    let mut since_secret = 0usize;
    while s.len() < size {
        if since_secret >= 64 * 1024 {
            s.push_str(secret);
            since_secret = 0;
        } else {
            s.push_str(filler);
            since_secret += filler.len();
        }
    }
    s.truncate(size);
    s
}

fn canonicalize_results(results: &mut [Vec<RawMatch>]) {
    for matches in results {
        matches.sort();
    }
}

fn scan_backend_checked(
    label: &str,
    scanner: &CompiledScanner,
    chunks: &[Chunk],
    route: BenchRoute,
    expected: &[Vec<RawMatch>],
) -> (Duration, Vec<Vec<RawMatch>>) {
    scanner.clear_fragment_cache();
    let started = Instant::now();
    let mut results = scanner.scan_coalesced_with_backend_admission_and_route(
        chunks,
        route.backend,
        None,
        route.execution_route(),
    );
    let elapsed = started.elapsed();
    canonicalize_results(&mut results);
    if results != expected {
        let chunk_index = results
            .iter()
            .zip(expected)
            .position(|(actual, reference)| actual != reference)
            .map_or_else(|| results.len().min(expected.len()), |index| index);
        let actual = results.get(chunk_index);
        let reference = expected.get(chunk_index);
        panic!(
            "{label} broke exact Hyperscan parity: first differing chunk={chunk_index}, \
             actual={actual:?}, reference={reference:?}"
        );
    }
    std::hint::black_box(&results);
    (elapsed, results)
}

fn hit_count(results: &[Vec<RawMatch>]) -> usize {
    results.iter().map(Vec::len).sum()
}

fn report(label: &str, d: Duration, scanned_bytes: usize, hits: usize) {
    let ms = d.as_secs_f64() * 1e3;
    let gbps = scanned_bytes as f64 / d.as_secs_f64() / 1e9;
    println!("{label:<28} {ms:>10.4} ms   {gbps:>8.3} GB/s   hits={hits}",);
}

fn env_positive_usize(name: &str, default: usize) -> Result<usize, io::Error> {
    match env::var(name) {
        Ok(raw) => {
            let value = raw.parse::<usize>().map_err(|source| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{name}={raw:?} must be a positive integer: {source}"),
                )
            })?;
            if value == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{name} must be greater than zero"),
                ));
            }
            Ok(value)
        }
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(raw)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} is not valid Unicode: {raw:?}"),
        )),
    }
}

fn env_optional_bool(name: &str) -> Result<Option<bool>, io::Error> {
    match env::var(name) {
        Ok(raw) => match raw.as_str() {
            "1" | "true" | "on" | "yes" => Ok(Some(true)),
            "0" | "false" | "off" | "no" => Ok(Some(false)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name}={raw:?} must be one of 1/0, true/false, on/off, or yes/no"),
            )),
        },
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(raw)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} is not valid Unicode: {raw:?}"),
        )),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let perf_trace = args.iter().any(|arg| arg == "--perf-trace");
    let profile = args.iter().any(|arg| arg == "--profile");
    let diagnostic = args.iter().any(|arg| arg == "--diagnostic");
    set_perf_trace_enabled(perf_trace);
    set_profile_enabled(false);

    let size_mib = env_positive_usize("KH_BENCH_SIZE_MIB", 8)?;
    let size = size_mib.checked_mul(MIB).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{size_mib} MiB overflows usize on this host"),
        )
    })?;
    let iters = env_positive_usize("KH_BENCH_ITERS", RELEASE_HELD_OUT_PAIRS)?;
    if iters < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "KH_BENCH_ITERS must be at least 2 for paired confidence evidence",
        )
        .into());
    }
    let selection_rounds =
        env_positive_usize("KH_BENCH_SELECTION_ROUNDS", RELEASE_SELECTION_ROUNDS)?;
    let release_gate = size_mib == 8 && !perf_trace && !profile && !diagnostic;
    if release_gate
        && (iters < RELEASE_HELD_OUT_PAIRS || selection_rounds < RELEASE_SELECTION_ROUNDS)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "the 8 MiB release gate requires at least {RELEASE_HELD_OUT_PAIRS} held-out pairs and {RELEASE_SELECTION_ROUNDS} selection rounds; received {iters} and {selection_rounds}"
            ),
        )
        .into());
    }
    let forced_plain_localizer = env_optional_bool("KH_BENCH_PHASE2_PLAIN_LOCALIZER")?;
    let forced_keyword_localizer = env_optional_bool("KH_BENCH_PHASE2_KEYWORD_LOCALIZER")?;
    if release_gate && (forced_plain_localizer.is_some() || forced_keyword_localizer.is_some()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the 8 MiB release gate must measure all plain-pattern and keyword-anchor localization plans; unset KH_BENCH_PHASE2_PLAIN_LOCALIZER and KH_BENCH_PHASE2_KEYWORD_LOCALIZER",
        )
        .into());
    }
    let workspace_root = workspace_root();
    let build_source_tree_state = env!("KEYHOG_BUILD_SOURCE_TREE_STATE");
    let source_tree_head = current_source_tree_head(&workspace_root)?;
    if source_tree_head != keyhog_core::git_hash() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "benchmark binary was built from {}, but the source tree is at {}; rebuild before measuring",
                keyhog_core::git_hash(),
                source_tree_head
            ),
        )
        .into());
    }
    let initial_source_tree_status = source_tree_status(&workspace_root)?;
    let source_tree_clean = initial_source_tree_status.is_empty();
    println!(
        "build_source_tree_state={build_source_tree_state} source_tree_clean={source_tree_clean}"
    );
    if release_gate && build_source_tree_state != "clean" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "the 8 MiB release gate requires a binary compiled from a clean source tree, but this binary was stamped {build_source_tree_state:?}; clean the tree and rebuild before measuring"
            ),
        )
        .into());
    }
    if release_gate && !source_tree_clean {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the 8 MiB release gate requires a clean source tree; commit the intended source and remove unrelated generated files before publishing crossover evidence",
        )
        .into());
    }

    let detectors = load_detectors(&detectors_dir())?;
    let n_det = detectors.len();
    let detector_spec_digest = hex::encode(keyhog_core::compute_spec_hash(&detectors));
    let binary_sha256 = running_binary_sha256()?;
    let confirmed_suffix_gate = env_optional_bool("KH_BENCH_CONFIRMED_SUFFIX_GATE")?;
    let tuning = ScannerTuningConfig {
        confirmed_suffix_gate,
        ..ScannerTuningConfig::default()
    };
    let effective_tuning = tuning.effective();
    let scanner = CompiledScanner::compile(detectors)?.with_tuning_config(tuning);

    let payload = gen_payload(size);
    let chunks = make_chunks(payload, MIB, WINDOW_OVERLAP);
    let scanned_bytes = chunks.iter().try_fold(0usize, |total, chunk| {
        total.checked_add(chunk.data.len()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "benchmark scanned-byte count overflows host usize",
            )
        })
    })?;

    assert!(
        scanner.warm_backend(ScanBackend::SimdCpu),
        "Hyperscan/SimdCpu is unavailable; refusing to benchmark a CPU fallback"
    );
    #[cfg(not(feature = "gpu"))]
    return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the 8 MiB crossover gate requires a GPU-enabled build; rebuild with --features gpu",
    )
    .into());

    #[cfg(feature = "gpu")]
    {
        let gpu_candidates = scanner.gpu_backend_candidates();
        for candidate in &gpu_candidates {
            println!(
                "gpu-peer backend={} available={} eligible={} software={} driver={} version={} device={} runtime={} error={}",
                candidate.backend.label(),
                candidate.available,
                candidate.is_eligible(),
                candidate.is_software,
                visible_peer_field(candidate.driver_id, "unavailable"),
                visible_peer_field(candidate.driver_version, "unavailable"),
                visible_peer_field(candidate.device_identity.as_deref(), "unavailable"),
                visible_peer_field(candidate.runtime_identity.as_deref(), "unavailable"),
                visible_peer_field(candidate.acquisition_error.as_deref(), "none")
            );
        }
        let gpu_backends: Vec<_> = gpu_candidates
            .iter()
            .filter(|candidate| candidate.is_eligible())
            .map(|candidate| candidate.backend)
            .collect();
        assert!(
            !gpu_backends.is_empty(),
            "no exact GPU region-presence peer was acquired; refusing to benchmark a CPU fallback"
        );
        for &backend in &gpu_backends {
            assert!(
                scanner.warm_backend(backend),
                "{} was reported as acquired but failed its warm-up",
                backend.label()
            );
        }

        let plain_localizer_modes =
            forced_plain_localizer.map_or_else(|| vec![false, true], |mode| vec![mode]);
        let keyword_localizer_modes =
            forced_keyword_localizer.map_or_else(|| vec![false, true], |mode| vec![mode]);
        let route_capacity = gpu_backends
            .len()
            .checked_add(1)
            .and_then(|backends| backends.checked_mul(plain_localizer_modes.len()))
            .and_then(|routes| routes.checked_mul(keyword_localizer_modes.len()))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "benchmark route-candidate count overflows host usize",
                )
            })?;
        let mut candidate_routes = Vec::with_capacity(route_capacity);
        for phase2_plain_localizer in plain_localizer_modes {
            for &phase2_keyword_localizer in &keyword_localizer_modes {
                candidate_routes.push(BenchRoute {
                    backend: ScanBackend::SimdCpu,
                    phase2_plain_localizer,
                    phase2_keyword_localizer,
                });
                candidate_routes.extend(gpu_backends.iter().copied().map(|backend| BenchRoute {
                    backend,
                    phase2_plain_localizer,
                    phase2_keyword_localizer,
                }));
            }
        }

        scanner.clear_fragment_cache();
        let reference_route = BenchRoute {
            backend: ScanBackend::SimdCpu,
            phase2_plain_localizer: false,
            phase2_keyword_localizer: false,
        };
        let mut reference = scanner.scan_coalesced_with_backend_admission_and_route(
            &chunks,
            reference_route.backend,
            None,
            reference_route.execution_route(),
        );
        canonicalize_results(&mut reference);
        for &route in &candidate_routes {
            let degrade_before = scanner.gpu_degrade_count();
            scan_backend_checked(
                &format!("{} warm parity", route.label()),
                &scanner,
                &chunks,
                route,
                &reference,
            );
            if route.backend.is_gpu() {
                assert_eq!(
                    scanner.gpu_degrade_count(),
                    degrade_before,
                    "{} degraded during warm parity; refusing fallback evidence",
                    route.label()
                );
            }
        }

        let gpu_peer_labels = gpu_backends
            .iter()
            .map(|backend| backend.label())
            .collect::<Vec<_>>()
            .join(",");
        println!("=== keyhog paired crossover gate (GPU region presence vs Hyperscan) ===");
        let runtime = scanner.runtime_status();
        let hardware = keyhog_scanner::hw_probe::probe_hardware();
        let cpu_model = host_cpu_model()?;
        let simd_features = keyhog_scanner::hw_probe::simd_label(
            hardware.has_avx512,
            hardware.has_avx2,
            hardware.has_neon,
        );
        println!(
            "git_hash={} binary_sha256={} detector_spec_blake3={} scanner_detector_digest={:016x}",
            keyhog_core::git_hash(),
            binary_sha256,
            detector_spec_digest,
            runtime.detector_digest,
        );
        println!(
            "host_os={} host_arch={} cpu_model={:?} physical_cores={} logical_cores={} total_memory_mb={} simd_features={} resolved_tuning={:?}",
            std::env::consts::OS,
            std::env::consts::ARCH,
            cpu_model,
            hardware.physical_cores,
            hardware.logical_cores,
            hardware.total_memory_mb.map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
            simd_features,
            effective_tuning,
        );
        println!(
            "source={} MiB scanned_bytes={} chunks={} detectors={} gpu_peers={} host_threads={} selection_rounds={} held_out_pairs={}",
            size / MIB,
            scanned_bytes,
            chunks.len(),
            n_det,
            gpu_peer_labels,
            std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get),
            selection_rounds,
            iters,
        );
        if let Some(enabled) = confirmed_suffix_gate {
            println!("confirmed_suffix_gate={enabled}");
        }
        if let Some(enabled) = forced_plain_localizer {
            println!("diagnostic_phase2_plain_localizer_filter={enabled}");
        }
        if let Some(enabled) = forced_keyword_localizer {
            println!("diagnostic_phase2_keyword_localizer_filter={enabled}");
        }

        let candidate_order = candidate_routes;
        let mut selection_samples: Vec<(BenchRoute, Vec<Duration>)> = candidate_order
            .iter()
            .copied()
            .map(|route| (route, Vec::with_capacity(selection_rounds)))
            .collect();
        let mut artifact_selection_samples = Vec::new();
        artifact_selection_samples
            .try_reserve(
                selection_rounds
                    .checked_mul(candidate_order.len())
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "benchmark selection-sample count overflows host usize",
                        )
                    })?,
            )
            .map_err(|source| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    format!("cannot reserve benchmark selection evidence: {source}"),
                )
            })?;
        for round in 0..selection_rounds {
            for offset in 0..candidate_order.len() {
                let route = candidate_order[(round + offset) % candidate_order.len()];
                let degrade_before = scanner.gpu_degrade_count();
                let route_label = route.label();
                let (elapsed, _) =
                    scan_backend_checked(&route_label, &scanner, &chunks, route, &reference);
                if route.backend.is_gpu() {
                    assert_eq!(
                        scanner.gpu_degrade_count(),
                        degrade_before,
                        "{} degraded during selection; refusing fallback timing",
                        route_label
                    );
                }
                selection_samples
                    .iter_mut()
                    .find(|(candidate, _)| *candidate == route)
                    .expect("selection route owns a sample vector")
                    .1
                    .push(elapsed);
                println!(
                    "selection-sample round={round} order={offset} route={} ns={}",
                    route_label,
                    elapsed.as_nanos(),
                );
                artifact_selection_samples.push(TimingSampleArtifact {
                    backend: route.backend.label().to_owned(),
                    phase2_plain_localizer: route.phase2_plain_localizer,
                    phase2_keyword_localizer: route.phase2_keyword_localizer,
                    round,
                    order: offset,
                    nanoseconds: elapsed.as_nanos(),
                });
            }
        }
        for (route, samples) in &selection_samples {
            let selected_median = median_duration(samples).expect("selection samples");
            report(
                &format!("{} selection", route.label()),
                selected_median,
                scanned_bytes,
                hit_count(&reference),
            );
        }
        let hyperscan_routes = selection_samples
            .iter()
            .filter(|(route, _)| route.backend == ScanBackend::SimdCpu)
            .map(|(route, _)| *route)
            .collect::<Vec<_>>();
        let selection_hyperscan = selection_samples
            .iter()
            .filter(|(route, _)| route.backend == ScanBackend::SimdCpu)
            .min_by_key(|(_, samples)| median_duration(samples).expect("selection samples"))
            .map(|(route, _)| *route)
            .expect("Hyperscan has route-selection evidence");
        let selected_gpu = selection_samples
            .iter()
            .filter(|(route, _)| route.backend.is_gpu())
            .min_by_key(|(_, samples)| median_duration(samples).expect("selection samples"))
            .map(|(route, _)| *route)
            .expect("an acquired GPU peer has selection evidence");
        println!(
            "held-out routes selected from selection-only evidence: hyperscan={} gpu={}",
            selection_hyperscan.label(),
            selected_gpu.label(),
        );

        let mut held_out_hs = hyperscan_routes
            .iter()
            .copied()
            .map(|route| (route, Vec::with_capacity(iters)))
            .collect::<Vec<_>>();
        let mut held_out_gpu = Vec::with_capacity(iters);
        let held_out_evidence_capacity =
            iters.checked_mul(hyperscan_routes.len()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "benchmark held-out evidence count overflows host usize",
                )
            })?;
        let mut artifact_held_out = Vec::new();
        artifact_held_out
            .try_reserve(held_out_evidence_capacity)
            .map_err(|source| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    format!("cannot reserve held-out benchmark evidence: {source}"),
                )
            })?;
        let mut held_out_routes = hyperscan_routes.clone();
        held_out_routes.push(selected_gpu);
        for pair in 0..iters {
            let mut order = held_out_routes.clone();
            let order_len = order.len();
            order.rotate_left(pair % order_len);
            let order_label = order
                .iter()
                .copied()
                .map(BenchRoute::label)
                .collect::<Vec<_>>()
                .join(",");
            let mut pair_hs = Vec::with_capacity(hyperscan_routes.len());
            let mut pair_gpu = None;
            for route in order {
                let degrade_before = scanner.gpu_degrade_count();
                let (elapsed, _) = scan_backend_checked(
                    &format!("{} held-out pair {pair}", route.label()),
                    &scanner,
                    &chunks,
                    route,
                    &reference,
                );
                if route.backend.is_gpu() {
                    assert_eq!(
                        scanner.gpu_degrade_count(),
                        degrade_before,
                        "{} degraded during held-out pair {pair}; refusing fallback timing",
                        route.label()
                    );
                    held_out_gpu.push(elapsed);
                    pair_gpu = Some(elapsed);
                } else {
                    pair_hs.push((route, elapsed));
                }
            }
            let gpu_elapsed = pair_gpu.expect("held-out rotation includes selected GPU");
            for (route, elapsed) in pair_hs {
                held_out_hs
                    .iter_mut()
                    .find(|(candidate, _)| *candidate == route)
                    .expect("held-out Hyperscan route owns a sample vector")
                    .1
                    .push(elapsed);
                println!(
                    "held-out-pair pair={pair} order={order_label} hs_route={} hs_ns={} gpu_route={} gpu_ns={}",
                    route.label(),
                    elapsed.as_nanos(),
                    selected_gpu.label(),
                    gpu_elapsed.as_nanos(),
                );
                artifact_held_out.push(TimingPairArtifact {
                    pair,
                    order: order_label.clone(),
                    hyperscan_backend: route.backend.label().to_owned(),
                    hyperscan_phase2_plain_localizer: route.phase2_plain_localizer,
                    hyperscan_phase2_keyword_localizer: route.phase2_keyword_localizer,
                    gpu_phase2_plain_localizer: selected_gpu.phase2_plain_localizer,
                    gpu_phase2_keyword_localizer: selected_gpu.phase2_keyword_localizer,
                    hyperscan_nanoseconds: elapsed.as_nanos(),
                    gpu_nanoseconds: gpu_elapsed.as_nanos(),
                });
            }
        }
        if profile {
            set_profile_enabled(true);
            let mut profile_routes = hyperscan_routes.clone();
            profile_routes.push(selected_gpu);
            for route in profile_routes {
                scanner.reset_profile_reports();
                let degrade_before = scanner.gpu_degrade_count();
                scan_backend_checked(
                    &format!("{} isolated profile", route.label()),
                    &scanner,
                    &chunks,
                    route,
                    &reference,
                );
                if route.backend.is_gpu() {
                    assert_eq!(
                        scanner.gpu_degrade_count(),
                        degrade_before,
                        "{} degraded during isolated profiling; refusing fallback evidence",
                        route.label()
                    );
                }
                scanner.dump_profile_reports(&format!("gpu-vs-hs:{}", route.label()));
            }
            set_profile_enabled(false);
        }
        let gpu_median = median_duration(&held_out_gpu).expect("held-out GPU samples");
        report(
            &format!("{} held-out", selected_gpu.label()),
            gpu_median,
            scanned_bytes,
            hit_count(&reference),
        );
        let mut hyperscan_comparisons = Vec::with_capacity(held_out_hs.len());
        for (route, samples) in &held_out_hs {
            let hs_median = median_duration(samples).expect("held-out Hyperscan samples");
            report(
                &format!("{} held-out", route.label()),
                hs_median,
                scanned_bytes,
                hit_count(&reference),
            );
            let interval = paired_ratio_confidence_95(samples, &held_out_gpu)
                .expect("held-out paired timing evidence must contain at least two positive pairs");
            println!(
                "paired GPU/Hyperscan route={} ratio geometric_mean={:.4} ci95=[{:.4}, {:.4}] pairs={}",
                route.label(),
                interval.geometric_mean_ratio,
                interval.low_ratio,
                interval.high_ratio,
                interval.sample_count,
            );
            hyperscan_comparisons.push((*route, hs_median, interval));
        }
        let (fastest_hyperscan, _, _) = hyperscan_comparisons
            .iter()
            .copied()
            .min_by_key(|(_, median, _)| *median)
            .expect("at least one held-out Hyperscan comparison exists");
        let held_out_fastest_hs = (0..iters)
            .map(|pair| {
                held_out_hs
                    .iter()
                    .map(|(_, samples)| samples[pair])
                    .min()
                    .expect("at least one held-out Hyperscan route exists")
            })
            .collect::<Vec<_>>();
        let interval = paired_ratio_confidence_95(&held_out_fastest_hs, &held_out_gpu)
            .expect("per-pair fastest Hyperscan evidence must contain two positive pairs");
        println!(
            "paired GPU/per-pair-fastest-Hyperscan ratio geometric_mean={:.4} ci95=[{:.4}, {:.4}] pairs={}",
            interval.geometric_mean_ratio,
            interval.low_ratio,
            interval.high_ratio,
            interval.sample_count,
        );

        if let Some(path) = env::var_os("KH_BENCH_ARTIFACT") {
            let publish_tree_head = current_source_tree_head(&workspace_root)?;
            let publish_tree_status = source_tree_status(&workspace_root)?;
            if publish_tree_head != source_tree_head
                || publish_tree_status != initial_source_tree_status
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "benchmark source state changed during measurement; refusing to publish mixed-source evidence",
                )
                .into());
            }
            let selected_peer = gpu_candidates
                .iter()
                .find(|candidate| {
                    candidate.backend == selected_gpu.backend && candidate.is_eligible()
                })
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "selected GPU peer lost its complete acquisition identity",
                    )
                })?;
            let selected_driver = selected_peer.driver_id.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "selected GPU peer is missing its driver identity",
                )
            })?;
            let selected_driver_version = selected_peer.driver_version.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "selected GPU peer is missing its driver version",
                )
            })?;
            let selected_device = selected_peer.device_identity.as_ref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "selected GPU peer is missing its device identity",
                )
            })?;
            let selected_runtime = selected_peer.runtime_identity.as_ref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "selected GPU peer is missing its runtime identity",
                )
            })?;
            let production_comparable = release_gate
                && build_source_tree_state == "clean"
                && source_tree_clean
                && iters >= RELEASE_HELD_OUT_PAIRS
                && selection_rounds >= RELEASE_SELECTION_ROUNDS;
            let artifact = CrossoverArtifact {
                schema_version: 8,
                measured_at_utc: chrono::Utc::now().to_rfc3339(),
                diagnostic,
                production_comparable,
                crossover_passed: production_comparable && interval.high_ratio < 1.0,
                git_hash: keyhog_core::git_hash().to_owned(),
                build_source_tree_state: build_source_tree_state.to_owned(),
                source_tree_state: if source_tree_clean {
                    "clean".to_owned()
                } else {
                    "dirty".to_owned()
                },
                binary_sha256,
                detector_spec_blake3: detector_spec_digest,
                scanner_detector_digest: format!("{:016x}", runtime.detector_digest),
                resolved_tuning: format!("{effective_tuning:?}"),
                compiled_features: format!(
                    "simd={},gpu={},decode={},entropy={}",
                    cfg!(feature = "simd"),
                    cfg!(feature = "gpu"),
                    cfg!(feature = "decode"),
                    cfg!(feature = "entropy")
                ),
                command: env::args().collect::<Vec<_>>().join(" "),
                os: std::env::consts::OS.to_owned(),
                arch: std::env::consts::ARCH.to_owned(),
                cpu_model: cpu_model.clone(),
                physical_cores: hardware.physical_cores,
                logical_cores: hardware.logical_cores,
                total_memory_mb: hardware.total_memory_mb,
                simd_features: simd_features.to_owned(),
                fastest_hyperscan_backend: fastest_hyperscan.backend.label().to_owned(),
                fastest_hyperscan_phase2_plain_localizer: fastest_hyperscan.phase2_plain_localizer,
                fastest_hyperscan_phase2_keyword_localizer: fastest_hyperscan
                    .phase2_keyword_localizer,
                hyperscan_reference: "per-pair-fastest-parity-correct-route".to_owned(),
                selected_gpu_backend: selected_gpu.backend.label().to_owned(),
                selected_gpu_phase2_plain_localizer: selected_gpu.phase2_plain_localizer,
                selected_gpu_phase2_keyword_localizer: selected_gpu.phase2_keyword_localizer,
                selected_gpu_driver: selected_driver.to_owned(),
                selected_gpu_driver_version: selected_driver_version.to_owned(),
                selected_gpu_device: selected_device.clone(),
                selected_gpu_runtime: selected_runtime.clone(),
                gpu_peers: gpu_candidates
                    .iter()
                    .map(|candidate| GpuPeerArtifact {
                        backend: candidate.backend.label().to_owned(),
                        acquired: candidate.available,
                        driver: visible_peer_field(candidate.driver_id, "unavailable").to_owned(),
                        driver_version: visible_peer_field(candidate.driver_version, "unavailable")
                            .to_owned(),
                        device: visible_peer_field(
                            candidate.device_identity.as_deref(),
                            "unavailable",
                        )
                        .to_owned(),
                        runtime: visible_peer_field(
                            candidate.runtime_identity.as_deref(),
                            "unavailable",
                        )
                        .to_owned(),
                        acquisition_error: visible_peer_field(
                            candidate.acquisition_error.as_deref(),
                            "none",
                        )
                        .to_owned(),
                    })
                    .collect(),
                source_bytes: size,
                scanned_bytes,
                chunk_bytes: MIB,
                overlap_bytes: WINDOW_OVERLAP,
                chunks: chunks.len(),
                detectors: n_det,
                reference_findings: hit_count(&reference),
                selection_rounds,
                held_out_pairs: iters,
                full_result_parity: true,
                gpu_degraded: false,
                ratio_geometric_mean: interval.geometric_mean_ratio,
                ratio_ci95_low: interval.low_ratio,
                ratio_ci95_high: interval.high_ratio,
                hyperscan_route_comparisons: hyperscan_comparisons
                    .iter()
                    .map(
                        |(route, hs_median, comparison)| HyperscanComparisonArtifact {
                            backend: route.backend.label().to_owned(),
                            phase2_plain_localizer: route.phase2_plain_localizer,
                            phase2_keyword_localizer: route.phase2_keyword_localizer,
                            hyperscan_median_nanoseconds: hs_median.as_nanos(),
                            gpu_median_nanoseconds: gpu_median.as_nanos(),
                            ratio_geometric_mean: comparison.geometric_mean_ratio,
                            ratio_ci95_low: comparison.low_ratio,
                            ratio_ci95_high: comparison.high_ratio,
                        },
                    )
                    .collect(),
                selection_samples: artifact_selection_samples,
                held_out_samples: artifact_held_out,
            };
            let path = artifact_path(path);
            write_artifact(&path, &artifact)?;
            println!("artifact={}", path.display());
        }

        if perf_trace || profile {
            println!(
                "crossover gate not enforced with profiling or perf tracing enabled; parity and no-degradation checks remain mandatory"
            );
        } else if diagnostic {
            println!(
                "crossover gate not enforced in explicit diagnostic mode; timing, parity, and no-degradation evidence is not release-comparable"
            );
        } else if size_mib != 8 {
            println!(
                "8 MiB crossover gate not enforced for the requested {size_mib} MiB diagnostic size. Rerun with KH_BENCH_SIZE_MIB=8 for the release gate."
            );
        } else {
            assert!(
                interval.high_ratio < 1.0,
                "8 MiB crossover missed: selected exact GPU route {} has paired GPU/per-pair-fastest-Hyperscan 95% CI upper bound {:.4}, which does not prove it faster than every parity-correct Hyperscan route",
                selected_gpu.label(),
                interval.high_ratio,
            );
        }
    }
    Ok(())
}
