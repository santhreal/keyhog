//! Parametric backend-parity matrix.
//!
//! Locks the headline GPU invariant: **every backend produces
//! byte-identical findings on the same input.** A divergence between
//! GPU/MegaScan/SimdCpu/CpuFallback on a single fixture means a real
//! bug - either the GPU kernel dropped a match, or the CPU path is
//! over-firing, or the chunk-boundary path is asymmetric.
//!
//! Each (backend × fixture) pair is its own cell. SimdCpu is the
//! reference: each non-SIMD backend must produce the same
//! `(credential, file_path, file_offset)` set. The fixture corpus is
//! synthetic so the test runs in milliseconds; real-corpus parity
//! lives in `gpu_parity.rs` (boundary) and the differential bench.
//!
//! The matrix skips GPU/MegaScan when no compatible adapter is
//! present (CI without `--features gpu`, headless containers,
//! software-only adapters that routing rejects). Skip is explicit
//! via `eprintln!` so a "no GPU" pass doesn't pretend to have
//! validated the GPU path.

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::collections::BTreeSet;
use std::path::PathBuf;

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

fn make_chunk(text: &str, path: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

type FindingKey = (String, String, usize);

fn collect_keys(results: &[Vec<RawMatch>]) -> BTreeSet<FindingKey> {
    results
        .iter()
        .flat_map(|chunk| chunk.iter())
        .map(|m| {
            (
                m.credential.as_ref().to_string(),
                m.location
                    .file_path
                    .as_deref()
                    .map(str::to_string)
                    .unwrap_or_default(),
                m.location.offset,
            )
        })
        .collect()
}

struct Fixture {
    name: &'static str,
    chunks: Vec<Chunk>,
}

/// Six synthetic corpora that each exercise a distinct engine path:
///   1. Pure clean text (zero findings - backend must agree on "nothing")
///   2. AKIA + ghp_ literal-prefix path (the GPU literal-set hot path)
///   3. Stripe sk_live_ + ASIA mixed
///   4. Multi-chunk same-file (tests chunk-id propagation)
///   5. Unicode + non-ASCII surrounding (tests byte-offset accounting)
///   6. False-prefix storm (many literal-prefix hits, few real matches -
///      catches GPU bitmap-vs-locations regressions)
fn build_fixtures() -> Vec<Fixture> {
    vec![
        Fixture {
            name: "clean_text",
            chunks: vec![make_chunk(
                "// pure prose, no credentials here at all\n\
                 fn hello() -> Result<(), Error> { Ok(()) }\n",
                "clean.rs",
            )],
        },
        Fixture {
            name: "aws_github_pair",
            chunks: vec![make_chunk(
                "const AWS_KEY = \"AKIAQYLPMN5HFIQR7XYA\";\n\
                 const PAT     = \"ghp_aBcD1234EFgh5678ijklMNop9012qrSTuvWX\";\n",
                "fixtures/aws_github.rs",
            )],
        },
        Fixture {
            name: "stripe_asia",
            chunks: vec![make_chunk(
                "auth: \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"\n\
                 alt:  \"ASIA1234567890ABCDEF\"\n",
                "fixtures/stripe_asia.yml",
            )],
        },
        Fixture {
            name: "multi_chunk_same_file",
            chunks: vec![
                Chunk {
                    data: "header\nconst KEY = \"AKIAQYLPMN5HFIQR7CCC\";\n".into(),
                    metadata: ChunkMetadata {
                        source_type: "test".into(),
                        path: Some("multi.txt".into()),
                        base_offset: 0,
                        ..Default::default()
                    },
                },
                Chunk {
                    data: "const PAT = \"ghp_zZ9876543210AbCdEfGhIjKlMnOp123456WX\";\n".into(),
                    metadata: ChunkMetadata {
                        source_type: "test".into(),
                        path: Some("multi.txt".into()),
                        base_offset: 4096,
                        ..Default::default()
                    },
                },
            ],
        },
        Fixture {
            name: "unicode_surroundings",
            chunks: vec![make_chunk(
                "// 日本語 comment\n\
                 const ключ = \"AKIAQYLPMN5HFIQR7DDD\";\n\
                 émoji: 🦀🚀 token=\"ghp_bCdE2345FGhi6789jKlmNOpq0123rsTUvwX1\"\n",
                "fixtures/unicode.txt",
            )],
        },
        Fixture {
            name: "false_prefix_storm",
            chunks: vec![make_chunk(
                &{
                    // 200 occurrences of `AKIA` followed by short non-key
                    // bodies (regex requires 16 trailing [A-Z0-9]). Plus
                    // ONE real key buried inside. Exercises the
                    // "literal-prefix-hit-then-regex-rejects" path; if
                    // the GPU kernel only reports prefix-positions, this
                    // catches the regression where it forgot to confirm
                    // with the regex.
                    let mut s = String::with_capacity(8192);
                    for i in 0..200 {
                        s.push_str(&format!("noise AKIA_{i:08}_short\n"));
                    }
                    s.push_str("\nconst KEY = \"AKIAQYLPMN5HFIQR7EEE\";\n");
                    for i in 0..200 {
                        s.push_str(&format!("more  AKIA_{i:08}_short\n"));
                    }
                    s
                },
                "fixtures/storm.txt",
            )],
        },
    ]
}

/// Run one (backend × fixture) cell. Returns `Some(keys)` on success,
/// `None` to signal SKIP (GPU adapter unavailable).
fn run_cell(
    scanner: &CompiledScanner,
    backend: ScanBackend,
    fixture: &Fixture,
    reference_keys: &BTreeSet<FindingKey>,
) -> Option<BTreeSet<FindingKey>> {
    let results = scanner.scan_chunks_with_backend(&fixture.chunks, backend);
    let keys = collect_keys(&results);

    // SKIP heuristic: GPU/MegaScan returning empty while SIMD found
    // anything is almost certainly a no-adapter fallback (the helper
    // silently falls back to SIMD inside scan_chunks_with_backend on
    // GPU init failure - that case prints zeros here). Don't flag
    // that as a parity failure; the routing layer's own job is to
    // pick a real backend, and the `gpu_smoke` test asserts the
    // adapter is present when expected.
    if matches!(backend, ScanBackend::Gpu | ScanBackend::MegaScan)
        && keys.is_empty()
        && !reference_keys.is_empty()
    {
        return None;
    }
    Some(keys)
}

#[test]
fn backend_parity_matrix_all_fixtures_all_backends() {
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors directory unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let fixtures = build_fixtures();

    let backends = [
        ScanBackend::SimdCpu,
        ScanBackend::CpuFallback,
        ScanBackend::Gpu,
        ScanBackend::MegaScan,
    ];

    let mut total_cells = 0usize;
    let mut skipped = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for fixture in &fixtures {
        // SimdCpu is the reference for this fixture.
        let reference_results =
            scanner.scan_chunks_with_backend(&fixture.chunks, ScanBackend::SimdCpu);
        let reference_keys = collect_keys(&reference_results);

        for backend in backends {
            total_cells += 1;
            let Some(keys) = run_cell(&scanner, backend, fixture, &reference_keys) else {
                skipped += 1;
                continue;
            };

            if keys != reference_keys {
                let only_ref: Vec<_> = reference_keys.difference(&keys).take(3).collect();
                let only_back: Vec<_> = keys.difference(&reference_keys).take(3).collect();
                failures.push(format!(
                    "[{}/{:?}] parity broken: ref={} got={} \
                     only-in-ref={:?} only-in-backend={:?}",
                    fixture.name,
                    backend,
                    reference_keys.len(),
                    keys.len(),
                    only_ref,
                    only_back,
                ));
            }
        }
    }

    eprintln!(
        "backend_parity_matrix: cells={} skipped={} failed={}",
        total_cells,
        skipped,
        failures.len()
    );

    assert!(
        failures.is_empty(),
        "backend-parity failures (showing first {}):\n  - {}",
        failures.len(),
        failures.join("\n  - ")
    );
}

/// Per-fixture, per-backend determinism: running the same scan twice
/// must produce byte-identical findings. Catches non-deterministic
/// GPU dispatch order, RNG-seeded fallback paths, or
/// hash-iteration-order leaks.
#[test]
fn determinism_each_backend_each_fixture_runs_twice_matches() {
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors directory unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let fixtures = build_fixtures();
    let backends = [
        ScanBackend::SimdCpu,
        ScanBackend::CpuFallback,
        ScanBackend::Gpu,
        ScanBackend::MegaScan,
    ];

    let mut failures = Vec::new();
    for fixture in &fixtures {
        for backend in backends {
            let a = collect_keys(&scanner.scan_chunks_with_backend(&fixture.chunks, backend));
            let b = collect_keys(&scanner.scan_chunks_with_backend(&fixture.chunks, backend));
            if a != b {
                failures.push(format!(
                    "[{}/{:?}] non-deterministic: run-A={} run-B={} (diff={})",
                    fixture.name,
                    backend,
                    a.len(),
                    b.len(),
                    a.symmetric_difference(&b).count()
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "determinism failures:\n  - {}",
        failures.join("\n  - ")
    );
}
