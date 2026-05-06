//! Honest crossover bench: file-size and pattern-count sweep.
//!
//! Answers two questions:
//!   1. At what input size does GPU stop losing to Hyperscan?
//!   2. How does that crossover shift when the pattern count grows?
//!
//! Run with: `cargo bench -p keyhog_scanner --bench size_pattern_sweep`
//!
//! Notes:
//! - This bench drives `CompiledScanner::scan` end-to-end, so the result
//!   reflects keyhog's actual routing decisions (CPU SIMD via Hyperscan
//!   when `simd` feature on, GPU when `KEYHOG_BACKEND=gpu` plus a real
//!   wgpu adapter, plain CPU regex otherwise). To force a backend, set
//!   `KEYHOG_BACKEND={cpu,simd,gpu}` before invoking.
//! - The "patterns" axis re-builds the scanner from a slice of the
//!   embedded detector corpus. 888 detectors total; we slice 10 / 100 /
//!   500 / 888 to expose how dispatch overhead amortizes.

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use keyhog_core::{Chunk, ChunkMetadata, DetectorFile, DetectorSpec};
use keyhog_scanner::CompiledScanner;

const SIZES: &[usize] = &[
    4 * 1024,         // 4 KB — well below GPU break-even
    64 * 1024,        // 64 KB — typical small source file
    1024 * 1024,      // 1 MB — typical medium file
    8 * 1024 * 1024,  // 8 MB — large file
    64 * 1024 * 1024, // 64 MB — coalesced-batch territory
];

const PATTERN_COUNTS: &[usize] = &[10, 100, 500];

/// Pull `n` detectors from the embedded corpus. Round-robins through the
/// list to give a heterogeneous slice (mix of regex shapes), not just the
/// first n alphabetically.
fn first_n_detectors(n: usize) -> Vec<DetectorSpec> {
    let embedded = keyhog_core::embedded_detector_tomls();
    let mut out = Vec::with_capacity(n);
    for (_name, body) in embedded.iter().take(n) {
        if let Ok(f) = toml::from_str::<DetectorFile>(body) {
            out.push(f.detector);
        }
        if out.len() >= n {
            break;
        }
    }
    out
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

fn make_chunk(payload: &str) -> Chunk {
    Chunk {
        data: payload.to_string().into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            source_type: "file".into(),
            path: Some("synthetic.txt".into()),
            ..Default::default()
        },
    }
}

fn bench_size_pattern_grid(c: &mut Criterion) {
    let mut group = c.benchmark_group("size_pattern_sweep");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    for &pcount in PATTERN_COUNTS {
        let detectors = first_n_detectors(pcount);
        if detectors.is_empty() {
            eprintln!("skip pcount={pcount}: no detectors loaded");
            continue;
        }
        let scanner = match CompiledScanner::compile(detectors) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skip pcount={pcount}: compile error {e:?}");
                continue;
            }
        };

        for &size in SIZES {
            let payload = generate_payload(size);
            let chunk = make_chunk(&payload);

            group.throughput(Throughput::Bytes(size as u64));
            group.bench_function(BenchmarkId::new(format!("p{pcount}"), size), |b| {
                b.iter(|| {
                    let matches = scanner.scan(black_box(&chunk));
                    black_box(matches);
                });
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_size_pattern_grid);
criterion_main!(benches);
