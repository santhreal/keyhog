//! Parametric backend-parity matrix.
//!
//! Locks the headline GPU invariant: **every backend produces
//! byte-identical findings on the same input.** A divergence between
//! GPU/SimdCpu/CpuFallback on a single fixture means a real
//! bug - either the GPU kernel dropped a match, or the CPU path is
//! over-firing, or the chunk-boundary path is asymmetric.
//!
//! Each (backend × fixture) pair is its own cell. SimdCpu is the
//! reference: each non-SIMD backend must produce the same
//! `(detector, credential, file_path, file_offset, confidence-bits)` set. The fixture corpus is
//! synthetic so the test runs in milliseconds; real-corpus parity
//! lives in `gpu_parity.rs` (boundary) and the differential bench.
//!
//! GPU is not allowed to return an all-zero finding set on
//! secret-bearing fixtures. If a host cannot run the GPU path, the scanner must
//! fail loud or take a recall-preserving backend path before this assertion.

mod support;
use support::contracts::test_chunk as make_chunk;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};
use std::collections::BTreeSet;

type FindingKey = (String, String, String, usize, Option<u64>);

fn collect_keys(results: &[Vec<RawMatch>]) -> BTreeSet<FindingKey> {
    results
        .iter()
        .flat_map(|chunk| chunk.iter())
        .map(|m| {
            (
                m.detector_id.as_ref().to_string(),
                m.credential.as_ref().to_string(),
                m.location
                    .file_path
                    .as_deref()
                    .map(str::to_string)
                    .unwrap_or_default(),
                m.location.offset,
                m.confidence.map(f64::to_bits),
            )
        })
        .collect()
}

struct Fixture {
    name: &'static str,
    chunks: Vec<Chunk>,
}

/// Synthetic corpora that each exercise a distinct engine path:
///   1. Pure clean text (zero findings - backend must agree on "nothing")
///   2. AKIA + ghp_ literal-prefix path (the GPU literal-set hot path)
///   3. Stripe sk_live_ + ASIA mixed
///   4. Multi-chunk same-file (tests chunk-id propagation)
///   5. Unicode + non-ASCII surrounding (tests byte-offset accounting)
///   6. False-prefix storm (many literal-prefix hits, few real matches -
///      catches GPU bitmap-vs-locations regressions)
///   7. HS-only companion detector (`twilio-auth-token`, NO GPU literal prefix -
///      the no-literal / regex-only class the GPU region-presence trigger path
///      can under-admit vs SimdCpu's Hyperscan union; M-02 test-depth gap)
///   8. Two complete password assignments within the fragment proximity window;
///      they must remain independent and backend-identical, never be glued by a
///      no-hit-only reassembly side channel.
///   9. A prefixless mixed-alnum API-key assignment at the generic/entropy
///      boundary, including detector identity and source offset.
///  10. A generated JavaScript template interpolation prefix that every backend
///      must classify as source syntax, never a generic secret.
///  11. The public Azurite connection-string key split across adjacent Python
///      literals; structured recovery must not turn published fixture data into
///      a backend-specific finding.
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
        Fixture {
            // The `twilio-auth-token` detector has NO standalone literal prefix in
            // the GPU literal set, it fires only once the regex confirms the
            // 32-hex auth-token shape alongside its required `account_sid`
            // companion (`AC` + 32 hex). It is one of the ~49 no-literal / HS-only
            // detectors, the exact class the GPU region-presence trigger producer
            // can under-admit relative to SimdCpu's Hyperscan trigger union
            // (M-02). Every backend, including GPU, must surface it
            // identically to the SimdCpu reference, or the GPU path is silently
            // dropping an HS-only vendor secret on its normal success path
            // (Law 10). Chosen as the confidence-CLEAR-CUT vendor member of that
            // class (an unambiguous companion-gated finding) rather than a
            // borderline entropy detector, so any divergence this fixture surfaces
            // is an unambiguous trigger-parity bug, not a confidence-float
            // artifact. The token/companion shapes are the canonical pair from
            // `regression_backend_trigger_parity` (proven to surface on both CPU
            // backends); this fixture extends that contract across the GPU cells.
            name: "hs_only_twilio_companion",
            chunks: vec![make_chunk(
                "TWILIO_ACCOUNT_SID=AC1b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\n\
                 TWILIO_AUTH_TOKEN=4c9a8f6e3b7d1a2c5e8f0b9d6a3c4e1f\n",
                "fixtures/twilio_pair.env",
            )],
        },
        Fixture {
            name: "independent_near_passwords",
            chunks: vec![make_chunk(
                &{
                    let mut body = String::from("const string password = \"lapbxbp796\";\n");
                    for _ in 0..88 {
                        body.push_str("// unrelated source line\n");
                    }
                    body.push_str("const string password = \"ybfyqpb806\";\n");
                    body
                },
                "fixtures/independent-passwords.cs",
            )],
        },
        Fixture {
            name: "prefixless_api_key_assignment",
            chunks: vec![make_chunk(
                r#"from allauth.socialaccount.tests import OAuth2TestsMixin
from allauth.tests import MockedResponse, TestCase

from .provider import BitlyProvider

class BitlyTests(OAuth2TestsMixin, TestCase):
    provider_id = BitlyProvider.id

    def get_mocked_response(self):
        return MockedResponse(
            200,
            """{
            "data": {
                "apiKey": "T_f8086c90j408603x7d466zys2po85448",
                "custom_short_domain": null,
                "display_name": null,
                "full_name": "Bitly API Oauth Demo Account",
                "is_enterprise": false,
                "login": "bitlyapioauthdemo",
                "member_since": 1331567982,
                "profile_image": "http://bitly.com/u/bitlyapioauthdemo.png",
                "profile_url": "http://bitly.com/u/bitlyapioauthdemo",
                "share_accounts": [],
                "tracking_domains": []
            },
            "status_code": 200,
            "status_txt": "OK"
        }""",
        )
"#,
                "fixtures/prefixless-api-key.py",
            )],
        },
        Fixture {
            name: "generated_js_template_prefix",
            chunks: vec![make_chunk(
                "c.key = `__vlist${nestedIndex}_${i}__`\n",
                "fixtures/generated-template.js",
            )],
        },
        Fixture {
            name: "public_azurite_key_split_across_python_literals",
            chunks: vec![make_chunk(
                r#"TEST_AZURE_CONNECTION_STRING = (
    "DefaultEndpointsProtocol=http;"
    "AccountName=devstoreaccount1;"
    "AccountKey=Vgs4slS82kICttQnzVfKBVypCjxXMNK2BEvHC52zXV"
    "Z6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;"
)
"#,
                "fixtures/azurite.py",
            )],
        },
    ]
}

/// Run one backend x fixture cell with backend-local scanner state.
fn run_cell(
    scanner: &CompiledScanner,
    backend: ScanBackend,
    fixture: &Fixture,
) -> BTreeSet<FindingKey> {
    scanner.clear_fragment_cache();
    let results = scanner.scan_coalesced_with_backend(&fixture.chunks, backend);
    collect_keys(&results)
}

#[test]
fn backend_parity_matrix_all_fixtures_all_backends() {
    // The on-disk detector directory is a required test asset: fail closed
    // rather than let this backend-parity gate pass vacuously.
    let detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("load detectors from the required on-disk detector directory");
    let mut config = ScannerConfig::default();
    config.penalize_test_paths = false;
    let scanner = CompiledScanner::compile(detectors)
        .expect("scanner compile")
        .with_config(config);
    let fixtures = build_fixtures();

    let backends = [
        ScanBackend::SimdCpu,
        ScanBackend::CpuFallback,
        ScanBackend::Gpu,
    ];

    let mut total_cells = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for fixture in &fixtures {
        // SimdCpu is the reference for this fixture.
        scanner.clear_fragment_cache();
        let reference_results =
            scanner.scan_coalesced_with_backend(&fixture.chunks, ScanBackend::SimdCpu);
        let reference_keys = collect_keys(&reference_results);
        assert!(
            reference_keys
                .iter()
                .all(|(_, credential, _, _, _)| credential != "ybfyqpb806lapbxbp796"
                    && credential != "lapbxbp796ybfyqpb806"),
            "independent complete password assignments must never be fabricated into one credential"
        );

        for backend in backends {
            total_cells += 1;
            let keys = run_cell(&scanner, backend, fixture);

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
        "backend_parity_matrix: cells={} failed={}",
        total_cells,
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
    // The on-disk detector directory is a required test asset: fail closed
    // rather than let this backend-parity gate pass vacuously.
    let detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("load detectors from the required on-disk detector directory");
    let mut config = ScannerConfig::default();
    config.penalize_test_paths = false;
    let scanner = CompiledScanner::compile(detectors)
        .expect("scanner compile")
        .with_config(config);
    let fixtures = build_fixtures();
    let backends = [
        ScanBackend::SimdCpu,
        ScanBackend::CpuFallback,
        ScanBackend::Gpu,
    ];

    let mut failures = Vec::new();
    for fixture in &fixtures {
        for backend in backends {
            scanner.clear_fragment_cache();
            let a = collect_keys(&scanner.scan_chunks_with_backend(&fixture.chunks, backend));
            scanner.clear_fragment_cache();
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
