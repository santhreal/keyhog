use keyhog_core::{load_detectors, Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

const SOURCE_EXTENSIONS: &[&str] = &[
    "c", "h", "rs", "S", "s", "lds", "dts", "dtsi", "py", "pl", "sh", "awk", "mk", "mak", "txt",
];

const SOURCE_NAMES: &[&str] = &[
    "Kconfig",
    "Makefile",
    ".config",
    "MAINTAINERS",
    "README",
    "COPYING",
];

fn main() {
    let mut args = env::args().skip(1);
    let root = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("linux"));
    let mut max_lines = None;
    let mut backend_args = Vec::new();
    while let Some(arg) = args.next() {
        if arg == "--max-lines" {
            max_lines = args.next().and_then(|value| value.parse::<usize>().ok());
        } else {
            backend_args.push(arg);
        }
    }
    let requested_backends: Vec<ScanBackend> = backend_args
        .iter()
        .filter_map(|arg| parse_backend(arg))
        .collect();
    let detectors_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detectors");
    let detectors = load_detectors(&detectors_dir).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let started = Instant::now();
    let mut chunks = Vec::new();
    let mut loaded_lines = 0usize;
    collect_chunks(&root, &mut chunks, max_lines, &mut loaded_lines);
    let read_elapsed = started.elapsed();
    let bytes: usize = chunks.iter().map(|chunk| chunk.data.len()).sum();
    let lines: usize = chunks
        .iter()
        .map(|chunk| chunk.data.bytes().filter(|byte| *byte == b'\n').count())
        .sum();

    println!(
        "loaded path={} files={} lines={} bytes={} read_ms={}",
        root.display(),
        chunks.len(),
        lines,
        bytes,
        read_elapsed.as_millis()
    );

    let backends = if requested_backends.is_empty() {
        vec![
            ScanBackend::CpuFallback,
            ScanBackend::SimdCpu,
            ScanBackend::Gpu,
        ]
    } else {
        requested_backends
    };

    for backend in backends {
        scanner.warm_backend(backend);
        let started = Instant::now();
        let results = scanner.scan_chunks_with_backend(&chunks, backend);
        let elapsed = started.elapsed();
        let findings: usize = results.iter().map(Vec::len).sum();
        let detector_counts = detector_counts(&results);
        let mib = bytes as f64 / (1024.0 * 1024.0);
        let seconds = elapsed.as_secs_f64();
        println!(
            "backend={} elapsed_ms={} throughput_mib_s={:.2} findings={}",
            backend.label(),
            elapsed.as_millis(),
            mib / seconds,
            findings
        );
        print_top_detectors(backend, &detector_counts);
    }
}

fn parse_backend(name: &str) -> Option<ScanBackend> {
    match name {
        "cpu" | "cpu-fallback" => Some(ScanBackend::CpuFallback),
        "simd" | "simd-cpu" => Some(ScanBackend::SimdCpu),
        "gpu" | "vyre-gpu" => Some(ScanBackend::Gpu),
        _ => None,
    }
}

fn detector_counts(results: &[Vec<keyhog_core::RawMatch>]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for finding in results.iter().flatten() {
        *counts.entry(finding.detector_id.to_string()).or_insert(0) += 1;
    }
    counts
}

fn print_top_detectors(backend: ScanBackend, counts: &BTreeMap<String, usize>) {
    let mut pairs: Vec<_> = counts.iter().collect();
    pairs.sort_unstable_by(|left, right| right.1.cmp(left.1).then_with(|| left.0.cmp(right.0)));
    let summary = pairs
        .into_iter()
        .take(8)
        .map(|(detector, count)| format!("{detector}:{count}"))
        .collect::<Vec<_>>()
        .join(",");
    println!("backend={} top_detectors={summary}", backend.label());
}

fn collect_chunks(
    path: &Path,
    chunks: &mut Vec<Chunk>,
    max_lines: Option<usize>,
    loaded_lines: &mut usize,
) {
    if max_lines.is_some_and(|limit| *loaded_lines >= limit) {
        return;
    }
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.is_dir() {
        if should_skip_dir(path) {
            return;
        }
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            collect_chunks(&entry.path(), chunks, max_lines, loaded_lines);
        }
        return;
    }
    if !metadata.is_file() || !is_source_file(path) {
        return;
    }
    let Ok(data) = fs::read(path) else {
        return;
    };
    if data.contains(&0) {
        return;
    }
    let Ok(data) = String::from_utf8(data) else {
        return;
    };
    *loaded_lines += data.bytes().filter(|byte| *byte == b'\n').count();
    chunks.push(Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            source_type: "filesystem".into(),
            path: Some(path.display().to_string()),
            commit: None,
            author: None,
            date: None,
        },
    });
}

fn should_skip_dir(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    matches!(
        name,
        ".git" | "target" | "node_modules" | "build" | "dist" | "out"
    )
}

fn is_source_file(path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
        if SOURCE_NAMES.contains(&name) {
            return true;
        }
    }
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| SOURCE_EXTENSIONS.contains(&extension))
}
