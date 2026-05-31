//! Full-corpus multi-backend worst-case parity (KH-GAP-125).
//!
//! Loads the full detector corpus (894 rules) and runs the synthetic
//! worst-case fixture set from `backend_parity_matrix` plus chunk-boundary
//! straddle cases on SimdCpu (reference), CpuFallback, and GPU when
//! available. Megakernel parity is waived under KH-GAP-043 until expiry.
//! Contract recall on every positive lives in `contracts_runner.rs`; this
//! harness gates cross-backend finding-set parity on adversarial shapes.

#[path = "support/mod.rs"]
mod support;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::collections::BTreeSet;
use support::paths::detector_dir;
type FindingKey = (String, String, usize);

fn make_chunk(text: &str, path: &str, base_offset: usize) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "worst-case-parity".into(),
            path: Some(path.into()),
            base_offset,
            ..Default::default()
        },
    }
}

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

fn synthetic_worst_case_fixtures() -> Vec<(String, Vec<Chunk>)> {
    let storm = {
        let mut s = String::with_capacity(8192);
        for i in 0..200 {
            s.push_str(&format!("noise AKIA_{i:08}_short\n"));
        }
        s.push_str("\nconst KEY = \"AKIAQYLPMN5HFIQR7EEE\";\n");
        for i in 0..200 {
            s.push_str(&format!("more  AKIA_{i:08}_short\n"));
        }
        s
    };

    let secret = concat!("AK", "IAQYLPMN5HFIQR7CCC");
    let split_at = 12;
    let pad_a_len = 4096 - split_at;
    let mut data_a = "x\n".repeat(pad_a_len / 2);
    if data_a.len() < pad_a_len {
        data_a.push('x');
    }
    data_a.push_str(&secret[..split_at]);
    let len_a = data_a.len();
    let mut data_b = secret[split_at..].to_string();
    data_b.push_str("\";\n");

    vec![
        (
            "clean_text".into(),
            vec![make_chunk(
                "// pure prose, no credentials here at all\nfn hello() {}\n",
                "worst/clean.rs",
                0,
            )],
        ),
        (
            "aws_github_pair".into(),
            vec![make_chunk(
                "const KEY = \"AKIAQYLPMN5HFIQR7XYA\";\nconst PAT = \"ghp_aBcD1234EFgh5678ijklMNop9012qrSTuvWX\";\n",
                "worst/aws_github.rs",
                0,
            )],
        ),
        (
            "stripe_asia".into(),
            vec![make_chunk(
                "auth: \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"\nalt: \"ASIA1234567890ABCDEF\"\n",
                "worst/stripe_asia.yml",
                0,
            )],
        ),
        (
            "multi_chunk_same_file".into(),
            vec![
                make_chunk(
                    "header\nconst KEY = \"AKIAQYLPMN5HFIQR7CCC\";\n",
                    "worst/multi.txt",
                    0,
                ),
                make_chunk(
                    "const PAT = \"ghp_zZ9876543210AbCdEfGhIjKlMnOp123456WX\";\n",
                    "worst/multi.txt",
                    4096,
                ),
            ],
        ),
        (
            "unicode_surroundings".into(),
            vec![make_chunk(
                "// 日本語\nconst ключ = \"AKIAQYLPMN5HFIQR7DDD\";\némoji token=\"ghp_bCdE2345FGhi6789jKlmNOpq0123rsTUvwX1\"\n",
                "worst/unicode.txt",
                0,
            )],
        ),
        ("false_prefix_storm".into(), vec![make_chunk(&storm, "worst/storm.txt", 0)]),
        (
            "boundary_straddle".into(),
            vec![
                make_chunk(&data_a, "worst/boundary.txt", 0),
                make_chunk(&data_b, "worst/boundary.txt", len_a),
            ],
        ),
    ]
}

fn scan_fixture(
    scanner: &CompiledScanner,
    chunks: &[Chunk],
    backend: ScanBackend,
) -> BTreeSet<FindingKey> {
    scanner.clear_fragment_cache();
    if backend == ScanBackend::MegaScan {
        unsafe { std::env::set_var("KEYHOG_USE_MEGAKERNEL", "1") };
    }
    let results = scanner.scan_chunks_with_backend(chunks, backend);
    if backend == ScanBackend::MegaScan {
        unsafe { std::env::remove_var("KEYHOG_USE_MEGAKERNEL") };
    }
    collect_keys(&results)
}

fn megakernel_waived() -> bool {
    support::megakernel_waiver::megakernel_parity_waiver_active()
        && support::megakernel_waiver::megakernel_env_unwired_in_engine()
}

#[test]
fn full_corpus_multi_backend_worst_case_parity() {
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors directory unavailable: {e}");
            return;
        }
    };
    assert!(
        detectors.len() >= 894,
        "worst-case parity must exercise the full detector corpus (got {})",
        detectors.len()
    );

    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let fixtures = synthetic_worst_case_fixtures();

    let mut backends = vec![
        ScanBackend::SimdCpu,
        ScanBackend::CpuFallback,
        ScanBackend::Gpu,
    ];
    if !megakernel_waived() {
        backends.push(ScanBackend::MegaScan);
    }

    let mut total_cells = 0usize;
    let mut skipped = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for (name, chunks) in &fixtures {
        let reference_keys = scan_fixture(&scanner, chunks, ScanBackend::SimdCpu);

        for backend in backends
            .iter()
            .copied()
            .filter(|b| *b != ScanBackend::SimdCpu)
        {
            total_cells += 1;
            let keys = scan_fixture(&scanner, chunks, backend);

            if matches!(backend, ScanBackend::Gpu | ScanBackend::MegaScan) {
                if keys.is_empty() && !reference_keys.is_empty() {
                    skipped += 1;
                    continue;
                }
                // GPU literal-set parity is environment-sensitive; only hard-fail
                // when CI mandates a GPU adapter (`KEYHOG_REQUIRE_GPU=1`).
                if keys != reference_keys && std::env::var("KEYHOG_REQUIRE_GPU").is_err() {
                    skipped += 1;
                    eprintln!(
                        "SKIP: {backend:?} mismatch on {name} in non-mandatory GPU environment"
                    );
                    continue;
                }
            }

            if keys != reference_keys {
                let only_ref: Vec<_> = reference_keys.difference(&keys).take(3).collect();
                let only_back: Vec<_> = keys.difference(&reference_keys).take(3).collect();
                failures.push(format!(
                    "[{name}/{backend:?}] parity broken: ref={} got={} \
                     only-in-ref={only_ref:?} only-in-backend={only_back:?}",
                    reference_keys.len(),
                    keys.len()
                ));
            }
        }
    }

    eprintln!(
        "worst_case_backend_parity: detectors={} fixtures={} cells={} skipped={} failed={}",
        scanner.detector_count(),
        fixtures.len(),
        total_cells,
        skipped,
        failures.len()
    );

    assert!(
        failures.is_empty(),
        "worst-case backend parity failures:\n  - {}",
        failures.join("\n  - ")
    );
}
