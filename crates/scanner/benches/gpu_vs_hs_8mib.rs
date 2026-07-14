//! Apples-to-apples 8 MiB baseline: Hyperscan/SimdCpu vs GPU region presence.
//!
//! Same `CompiledScanner` (real detector catalog), same production-style 1 MiB
//! windows with 128 KiB overlap over an 8 MiB file, same
//! `scan_coalesced_with_backend` entry. Every acquired CUDA and WGPU peer is
//! measured independently. The layout lets the Hyperscan path use
//! its production coalesced trigger pass and real Rayon parallelism instead of
//! handicapping it behind one oversized sequential chunk. `SimdCpu`
//! runs the Hyperscan literal prefilter; each GPU peer routes the batch through VYRE
//! `ResidentPresencePipeline`. Timing includes each
//! backend's production batching, scheduling, phase 2, and post-processing.
//!
//! Pass `-- --perf-trace` to get the region-presence phase breakdown
//! (matcher / coalesce / dispatch / floor / phase2_gpu / phase2) and VYRE
//! dispatch telemetry on stderr. Trace instrumentation is intentionally not a
//! crossover measurement: it adds GPU-specific timers and counters, so the
//! speed gate is enforced only by the normal untraced, unprofiled run.
//! Full-result parity and zero GPU degradation remain mandatory in every mode.
//!
//! Selection uses rotating candidate order. The selected exact GPU peer then
//! receives fresh alternating held-out pairs against Hyperscan. The release
//! gate requires the paired GPU/Hyperscan ratio's 95% confidence upper bound
//! to remain below 1.0.

use keyhog_core::{
    load_detectors,
    timing::{median_duration, paired_ratio_confidence_95},
    Chunk, ChunkMetadata, RawMatch,
};
use keyhog_scanner::{
    set_perf_trace_enabled, set_profile_enabled, CompiledScanner, ScanBackend, ScannerTuningConfig,
};
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
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
    round: usize,
    order: usize,
    nanoseconds: u128,
}

#[derive(serde::Serialize)]
struct TimingPairArtifact {
    pair: usize,
    order: String,
    hyperscan_nanoseconds: u128,
    gpu_nanoseconds: u128,
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
    production_comparable: bool,
    crossover_passed: bool,
    git_hash: String,
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
    selected_gpu_backend: String,
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
    selection_rounds: usize,
    held_out_pairs: usize,
    full_result_parity: bool,
    gpu_degraded: bool,
    ratio_geometric_mean: f64,
    ratio_ci95_low: f64,
    ratio_ci95_high: f64,
    selection_samples: Vec<TimingSampleArtifact>,
    held_out_samples: Vec<TimingPairArtifact>,
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

fn host_cpu_model() -> String {
    #[cfg(target_os = "linux")]
    if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
        for line in cpuinfo.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            if matches!(
                key.trim().to_ascii_lowercase().as_str(),
                "model name" | "hardware"
            ) && !value.trim().is_empty()
            {
                return value.trim().to_owned();
            }
        }
    }
    "unavailable".to_owned()
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
    let temporary = path.with_extension(format!(
        "{}.tmp-{}",
        path.extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("toml"),
        std::process::id()
    ));
    fs::write(&temporary, rendered.as_bytes())?;
    fs::rename(&temporary, path).map_err(|source| {
        let _ = fs::remove_file(&temporary);
        io::Error::new(
            source.kind(),
            format!(
                "cannot atomically publish crossover artifact {}: {source}",
                path.display()
            ),
        )
    })
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
    backend: ScanBackend,
    expected: &[Vec<RawMatch>],
) -> (Duration, Vec<Vec<RawMatch>>) {
    scanner.clear_fragment_cache();
    let started = Instant::now();
    let mut results = scanner.scan_coalesced_with_backend(chunks, backend);
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
    set_perf_trace_enabled(perf_trace);
    set_profile_enabled(profile);

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
    let release_gate = size_mib == 8 && !perf_trace && !profile;
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
                "gpu-peer backend={} acquired={} driver={} version={} device={} runtime={} error={}",
                candidate.backend.label(),
                candidate.acquired,
                candidate.driver_id.unwrap_or("unavailable"),
                candidate.driver_version.unwrap_or("unavailable"),
                candidate.device_identity.as_deref().unwrap_or("unavailable"),
                candidate.runtime_identity.as_deref().unwrap_or("unavailable"),
                candidate.acquisition_error.as_deref().unwrap_or("none")
            );
        }
        let gpu_backends: Vec<_> = gpu_candidates
            .iter()
            .filter(|candidate| candidate.acquired)
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

        scanner.clear_fragment_cache();
        let mut reference = scanner.scan_coalesced_with_backend(&chunks, ScanBackend::SimdCpu);
        canonicalize_results(&mut reference);
        for &backend in &gpu_backends {
            let degrade_before = scanner.gpu_degrade_count();
            let _ = scan_backend_checked(
                &format!("{} warm parity", backend.label()),
                &scanner,
                &chunks,
                backend,
                &reference,
            );
            assert_eq!(
                scanner.gpu_degrade_count(),
                degrade_before,
                "{} degraded during warm parity; refusing fallback evidence",
                backend.label()
            );
        }

        let gpu_peer_labels = gpu_backends
            .iter()
            .map(|backend| backend.label())
            .collect::<Vec<_>>()
            .join(",");
        println!("=== keyhog paired crossover gate (GPU region presence vs Hyperscan) ===");
        let runtime = scanner.runtime_status();
        let hardware = keyhog_scanner::hw_probe::probe_hardware();
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
            host_cpu_model(),
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

        let mut candidate_order = Vec::with_capacity(gpu_backends.len() + 1);
        candidate_order.push(ScanBackend::SimdCpu);
        candidate_order.extend(gpu_backends.iter().copied());
        let mut selection_samples: Vec<(ScanBackend, Vec<Duration>)> = candidate_order
            .iter()
            .copied()
            .map(|backend| (backend, Vec::with_capacity(selection_rounds)))
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
        if profile {
            scanner.reset_profile_reports();
        }
        for round in 0..selection_rounds {
            for offset in 0..candidate_order.len() {
                let backend = candidate_order[(round + offset) % candidate_order.len()];
                let degrade_before = scanner.gpu_degrade_count();
                let (elapsed, _) =
                    scan_backend_checked(backend.label(), &scanner, &chunks, backend, &reference);
                if backend.is_gpu() {
                    assert_eq!(
                        scanner.gpu_degrade_count(),
                        degrade_before,
                        "{} degraded during selection; refusing fallback timing",
                        backend.label()
                    );
                }
                selection_samples
                    .iter_mut()
                    .find(|(candidate, _)| *candidate == backend)
                    .expect("selection backend owns a sample vector")
                    .1
                    .push(elapsed);
                println!(
                    "selection-sample round={round} order={offset} backend={} ns={}",
                    backend.label(),
                    elapsed.as_nanos(),
                );
                artifact_selection_samples.push(TimingSampleArtifact {
                    backend: backend.label().to_owned(),
                    round,
                    order: offset,
                    nanoseconds: elapsed.as_nanos(),
                });
            }
        }
        for (backend, samples) in &selection_samples {
            let selected_median = median_duration(samples).expect("selection samples");
            report(
                &format!("{} selection", backend.label()),
                selected_median,
                scanned_bytes,
                hit_count(&reference),
            );
        }
        let selected_gpu = selection_samples
            .iter()
            .filter(|(backend, _)| backend.is_gpu())
            .min_by_key(|(_, samples)| median_duration(samples).expect("selection samples"))
            .map(|(backend, _)| *backend)
            .expect("an acquired GPU peer has selection evidence");
        println!(
            "held-out GPU peer selected from selection-only evidence: {}",
            selected_gpu.label()
        );

        let mut held_out_hs = Vec::with_capacity(iters);
        let mut held_out_gpu = Vec::with_capacity(iters);
        let mut artifact_held_out = Vec::with_capacity(iters);
        for pair in 0..iters {
            let order = if pair % 2 == 0 {
                [ScanBackend::SimdCpu, selected_gpu]
            } else {
                [selected_gpu, ScanBackend::SimdCpu]
            };
            let order_label = if pair % 2 == 0 { "hs-gpu" } else { "gpu-hs" };
            let mut pair_hs = None;
            let mut pair_gpu = None;
            for backend in order {
                let degrade_before = scanner.gpu_degrade_count();
                let (elapsed, _) = scan_backend_checked(
                    &format!("{} held-out pair {pair}", backend.label()),
                    &scanner,
                    &chunks,
                    backend,
                    &reference,
                );
                if backend.is_gpu() {
                    assert_eq!(
                        scanner.gpu_degrade_count(),
                        degrade_before,
                        "{} degraded during held-out pair {pair}; refusing fallback timing",
                        backend.label()
                    );
                    held_out_gpu.push(elapsed);
                    pair_gpu = Some(elapsed);
                } else {
                    held_out_hs.push(elapsed);
                    pair_hs = Some(elapsed);
                }
            }
            println!(
                "held-out-pair pair={pair} order={order_label} hs_ns={} gpu_backend={} gpu_ns={}",
                pair_hs.expect("pair includes Hyperscan").as_nanos(),
                selected_gpu.label(),
                pair_gpu.expect("pair includes selected GPU").as_nanos(),
            );
            artifact_held_out.push(TimingPairArtifact {
                pair,
                order: order_label.to_owned(),
                hyperscan_nanoseconds: pair_hs.expect("pair includes Hyperscan").as_nanos(),
                gpu_nanoseconds: pair_gpu.expect("pair includes selected GPU").as_nanos(),
            });
        }
        if profile {
            scanner.dump_profile_reports("gpu-vs-hs-paired");
        }
        let hs_median = median_duration(&held_out_hs).expect("held-out Hyperscan samples");
        let gpu_median = median_duration(&held_out_gpu).expect("held-out GPU samples");
        report(
            "SimdCpu held-out",
            hs_median,
            scanned_bytes,
            hit_count(&reference),
        );
        report(
            &format!("{} held-out", selected_gpu.label()),
            gpu_median,
            scanned_bytes,
            hit_count(&reference),
        );
        let interval = paired_ratio_confidence_95(&held_out_hs, &held_out_gpu)
            .expect("held-out paired timing evidence must contain at least two positive pairs");
        println!(
            "paired GPU/Hyperscan ratio geometric_mean={:.4} ci95=[{:.4}, {:.4}] pairs={}",
            interval.geometric_mean_ratio,
            interval.low_ratio,
            interval.high_ratio,
            interval.sample_count,
        );

        if let Some(path) = env::var_os("KH_BENCH_ARTIFACT") {
            let selected_peer = gpu_candidates
                .iter()
                .find(|candidate| candidate.backend == selected_gpu && candidate.acquired)
                .expect("selected GPU peer retains acquisition identity");
            let production_comparable = release_gate
                && iters >= RELEASE_HELD_OUT_PAIRS
                && selection_rounds >= RELEASE_SELECTION_ROUNDS;
            let artifact = CrossoverArtifact {
                schema_version: 2,
                measured_at_utc: chrono::Utc::now().to_rfc3339(),
                production_comparable,
                crossover_passed: production_comparable && interval.high_ratio < 1.0,
                git_hash: keyhog_core::git_hash().to_owned(),
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
                cpu_model: host_cpu_model(),
                physical_cores: hardware.physical_cores,
                logical_cores: hardware.logical_cores,
                total_memory_mb: hardware.total_memory_mb,
                simd_features: simd_features.to_owned(),
                selected_gpu_backend: selected_gpu.label().to_owned(),
                selected_gpu_driver: selected_peer.driver_id.unwrap_or("unavailable").to_owned(),
                selected_gpu_driver_version: selected_peer
                    .driver_version
                    .unwrap_or("unavailable")
                    .to_owned(),
                selected_gpu_device: selected_peer
                    .device_identity
                    .clone()
                    .unwrap_or_else(|| "unavailable".to_owned()),
                selected_gpu_runtime: selected_peer
                    .runtime_identity
                    .clone()
                    .unwrap_or_else(|| "unavailable".to_owned()),
                gpu_peers: gpu_candidates
                    .iter()
                    .map(|candidate| GpuPeerArtifact {
                        backend: candidate.backend.label().to_owned(),
                        acquired: candidate.acquired,
                        driver: candidate.driver_id.unwrap_or("unavailable").to_owned(),
                        driver_version: candidate
                            .driver_version
                            .unwrap_or("unavailable")
                            .to_owned(),
                        device: candidate
                            .device_identity
                            .clone()
                            .unwrap_or_else(|| "unavailable".to_owned()),
                        runtime: candidate
                            .runtime_identity
                            .clone()
                            .unwrap_or_else(|| "unavailable".to_owned()),
                        acquisition_error: candidate
                            .acquisition_error
                            .clone()
                            .unwrap_or_else(|| "none".to_owned()),
                    })
                    .collect(),
                source_bytes: size,
                scanned_bytes,
                chunk_bytes: MIB,
                overlap_bytes: WINDOW_OVERLAP,
                chunks: chunks.len(),
                detectors: n_det,
                selection_rounds,
                held_out_pairs: iters,
                full_result_parity: true,
                gpu_degraded: false,
                ratio_geometric_mean: interval.geometric_mean_ratio,
                ratio_ci95_low: interval.low_ratio,
                ratio_ci95_high: interval.high_ratio,
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
        } else if size_mib != 8 {
            println!(
                "8 MiB crossover gate not enforced for the requested {size_mib} MiB diagnostic size. Rerun with KH_BENCH_SIZE_MIB=8 for the release gate."
            );
        } else {
            assert!(
                interval.high_ratio < 1.0,
                "8 MiB crossover missed: selected exact GPU peer {} has paired GPU/Hyperscan 95% CI upper bound {:.4}, which does not prove it faster than Hyperscan",
                selected_gpu.label(),
                interval.high_ratio,
            );
        }
    }
    Ok(())
}
