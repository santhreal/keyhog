//! Honest crossover bench: file-size and pattern-count sweep.
//!
//! Answers two questions:
//!   1. At what input size does GPU stop losing to Hyperscan?
//!   2. How does that crossover shift when the pattern count grows?
//!
//! Run with: `cargo bench -p keyhog-scanner --bench size_pattern_sweep`
//!
//! Notes:
//! - Every cell drives scalar CPU, coalesced Hyperscan, and GPU explicitly.
//!   Missing accelerated backends fail the run instead of silently producing
//!   a scalar-only chart with accelerated labels.
//! - Each timed result is compared with its backend warm result. Every backend
//!   is also compared with the scalar reference before timing.
//! - Inputs use the production 1 MiB filesystem windows with 128 KiB overlap,
//!   including source-size and base-offset metadata.
//! - The "patterns" axis re-builds the scanner from a slice of the
//!   embedded detector corpus (~900 detectors); we slice 10 / 100 / 500 to
//!   expose how dispatch overhead amortizes.

use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::hint::black_box;
use std::time::{Duration, Instant};

const SIZES: &[usize] = &[
    4 * 1024,         // 4 KB - well below GPU break-even
    64 * 1024,        // 64 KB - typical small source file
    1024 * 1024,      // 1 MB - typical medium file
    8 * 1024 * 1024,  // 8 MB - large file
    64 * 1024 * 1024, // 64 MB - coalesced-batch territory
];

const DETECTOR_COUNTS: &[usize] = &[10, 100, 500];
const WINDOW_BYTES: usize = 1024 * 1024;
const WINDOW_OVERLAP: usize = 128 * 1024;

/// Select `n` detectors at even intervals through the canonical corpus so each
/// tier spans the alphabetized vendor and regex-shape distribution.
fn sampled_detectors(n: usize) -> Vec<DetectorSpec> {
    let all =
        keyhog_core::load_embedded_detectors_or_fail().expect("embedded detector corpus must load");
    let count = n.min(all.len());
    (0..count)
        .map(|index| all[index * all.len() / count].clone())
        .collect()
}

/// Generate `size` bytes of plausible source code with a few real-looking
/// secrets sprinkled in. Used as the input to the scanner.
fn generate_payload(size: usize) -> String {
    let mut s = String::with_capacity(size);
    let chunk = "
const config = {
    aws_key: \"AKIAIOSFODNN7EXAMPLE\",
    aws_secret: \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\",
    github_token: \"ghp_aaaabbbbccccddddeeeeffff00001111222233\",
    stripe_secret: \"sk_live_aaaabbbbccccddddeeeeffff00001111\",
    fill: \"// some random comment text and identifiers like client_id user_email\"
};
function authenticate(req, res) {
    const t = req.headers['authorization'] || '';
    if (t.startsWith('Bearer ')) {
        return verifyToken(t.slice(7));
    }
    return null;
}
";
    while s.len() < size {
        s.push_str(chunk);
    }
    s.truncate(size);
    s
}

fn make_chunks(payload: &str) -> Vec<Chunk> {
    let stride = WINDOW_BYTES - WINDOW_OVERLAP;
    let mut chunks = Vec::with_capacity(payload.len().div_ceil(stride));
    let mut offset = 0usize;
    while offset < payload.len() {
        let end = (offset + WINDOW_BYTES).min(payload.len());
        let base_line = 1 + payload.as_bytes()[..offset]
            .iter()
            .filter(|&&byte| byte == b'\n')
            .count();
        chunks.push(Chunk {
            data: payload[offset..end].to_string().into(),
            metadata: ChunkMetadata {
                base_offset: offset,
                base_line,
                source_type: "filesystem/windowed".into(),
                path: Some("synthetic.txt".into()),
                size_bytes: Some(payload.len() as u64),
                ..Default::default()
            },
        });
        if end == payload.len() {
            break;
        }
        offset += stride;
    }
    chunks
}

fn canonicalize_results(results: &mut [Vec<RawMatch>]) {
    for matches in results {
        matches.sort();
    }
}

fn scan_cell(
    scanner: &CompiledScanner,
    chunks: &[Chunk],
    backend: ScanBackend,
) -> Vec<Vec<RawMatch>> {
    scanner.clear_fragment_cache();
    let mut results = scanner.scan_coalesced_with_backend(chunks, backend);
    canonicalize_results(&mut results);
    results
}

fn bench_size_pattern_grid(c: &mut Criterion) {
    let mut group = c.benchmark_group("size_pattern_sweep");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    for &detector_count in DETECTOR_COUNTS {
        let detectors = sampled_detectors(detector_count);
        if detectors.is_empty() {
            panic!("embedded detector corpus was empty; refusing a vacuous crossover chart");
        }
        let scanner = match CompiledScanner::compile(detectors) {
            Ok(scanner) => scanner,
            Err(error) => {
                panic!("compile detector_count={detector_count} for crossover sweep: {error:#}")
            }
        };
        let pattern_count = scanner.runtime_status().pattern_count;
        let backends = [
            ("scalar", ScanBackend::CpuFallback),
            ("hyperscan", ScanBackend::SimdCpu),
            ("gpu", ScanBackend::Gpu),
        ];
        for (label, backend) in backends {
            assert!(
                scanner.warm_backend(backend),
                "{label} backend is unavailable for detector_count={detector_count}, pattern_count={pattern_count}; refusing to emit an incomplete crossover chart"
            );
        }

        for &size in SIZES {
            let payload = generate_payload(size);
            let chunks = make_chunks(&payload);
            let reference = scan_cell(&scanner, &chunks, ScanBackend::CpuFallback);

            group.throughput(Throughput::Bytes(size as u64));
            for (label, backend) in backends {
                let warm = scan_cell(&scanner, &chunks, backend);
                assert_eq!(
                    warm, reference,
                    "{label} full RawMatch parity failed before timing detector_count={detector_count}, pattern_count={pattern_count}, bytes={size}"
                );
                let degrade_before = scanner.gpu_degrade_count();
                group.bench_function(
                    BenchmarkId::new(
                        format!("{label}/d{detector_count}-p{pattern_count}"),
                        size,
                    ),
                    |b| {
                        b.iter_custom(|iterations| {
                            let mut elapsed = Duration::ZERO;
                            for _ in 0..iterations {
                                scanner.clear_fragment_cache();
                                let started = Instant::now();
                                let mut matches = scanner
                                    .scan_coalesced_with_backend(black_box(&chunks), backend);
                                elapsed += started.elapsed();
                                canonicalize_results(&mut matches);
                                assert_eq!(
                                    matches, warm,
                                    "{label} produced nondeterministic full RawMatch output for detector_count={detector_count}, pattern_count={pattern_count}, bytes={size}"
                                );
                                black_box(matches);
                            }
                            elapsed
                        });
                    },
                );
                if backend == ScanBackend::Gpu {
                    assert_eq!(
                        scanner.gpu_degrade_count(),
                        degrade_before,
                        "GPU degraded while measuring detector_count={detector_count}, pattern_count={pattern_count}, bytes={size}; refusing to report fallback timing as GPU"
                    );
                }
            }
        }
    }
    group.finish();
}

criterion_group!(benches, bench_size_pattern_grid);
criterion_main!(benches);
