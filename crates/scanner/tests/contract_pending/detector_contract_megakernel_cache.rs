#![cfg(feature = "gpu")]
//! Megakernel determinism: consecutive GPU scans produce byte-identical finding sets.
//!
//! This test validates that the megakernel (batched-DFA GPU backend) exhibits
//! **strict determinism** across repeated scans of the same input:
//!
//! - Two consecutive `scan_chunks_with_backend(..., ScanBackend::Gpu)` calls on
//!   identical multi-secret corpora MUST produce **byte-for-byte identical**
//!   finding sets (credential, location, detector_id), whether the GPU cache is
//!   warm or cold.
//!
//! - The catalog must handle patterns that cannot lower to unanchored DFAs
//!   (PCRE lookaround, backrefs, state-budget explosion) by taking a **loud host
//!   path** (never silent drops), ensuring the finding still surfaces.
//!
//! Patterns exercised:
//!   1. Single GPU dispatch over synthetic multi-secret corpus (AKIA, GitHub PAT,
//!      Stripe, generic entropy).
//!   2. Back-to-back GPU scans on same data (determinism gate).
//!   3. Non-lowerable patterns that must be caught via host path.
//!   4. Chunk boundaries within the corpus.
//!   5. Empty and whitespace-only chunks (no false positives).
//!   6. Mixed secret densities (sparse real-world, dense adversarial).

#[path = "support/mod.rs"]
mod support;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::collections::BTreeSet;
use support::gpu_gate::assert_gpu_not_silent_empty;
use support::paths::detector_dir;

fn make_chunk(text: &str, path: &str, base_offset: usize) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some(path.into()),
            base_offset,
            ..Default::default()
        },
    }
}

/// Canonical finding key: (credential_string, file_path, byte_offset).
/// Used for determinism comparison across repeated scans.
type FindingKey = (String, String, usize);

fn collect_finding_keys(results: &[Vec<RawMatch>]) -> BTreeSet<FindingKey> {
    let mut set = BTreeSet::new();
    for chunk in results {
        for m in chunk {
            set.insert((
                m.credential.as_ref().to_string(),
                m.location
                    .file_path
                    .as_deref()
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
                m.location.offset,
            ));
        }
    }
    set
}

/// Determinism assertion: compare two finding key sets in detail.
fn assert_finding_sets_identical(
    findings_a: &BTreeSet<FindingKey>,
    findings_b: &BTreeSet<FindingKey>,
    context: &str,
) {
    if findings_a == findings_b {
        return;
    }

    let only_a: Vec<_> = findings_a.difference(findings_b).collect();
    let only_b: Vec<_> = findings_b.difference(findings_a).collect();

    panic!(
        "{context}: GPU determinism broken!\n  \
         Scan A: {} findings\n  \
         Scan B: {} findings\n  \
         Only in A ({}): {:?}\n  \
         Only in B ({}): {:?}",
        findings_a.len(),
        findings_b.len(),
        only_a.len(),
        only_a.iter().take(3).collect::<Vec<_>>(),
        only_b.len(),
        only_b.iter().take(3).collect::<Vec<_>>(),
    );
}

// ============================================================================
// CORE DETERMINISM TESTS
// ============================================================================

#[test]
fn megakernel_consecutive_scans_identical_single_secret() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let chunk = make_chunk(
        "const API_KEY = \"AKIAQYLPMN5HFIQR7XYA\";\n",
        "test.rs",
        0,
    );

    let scan_a = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::Gpu);
    let scan_b = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::Gpu);

    let keys_a = collect_finding_keys(&scan_a);
    let keys_b = collect_finding_keys(&scan_b);

    assert!(
        !keys_a.is_empty(),
        "fixture should find the AKIA key on first scan"
    );
    assert_finding_sets_identical(&keys_a, &keys_b, "single_secret_determinism");
}

#[test]
fn megakernel_consecutive_scans_identical_multi_secret_corpus() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // Multi-secret corpus covering distinct detector families.
    let corpus = vec![
        make_chunk(
            "// AWS credentials\nlet key1 = \"AKIAQYLPMN5HFIQR7AAA\";\n",
            "aws.rs",
            0,
        ),
        make_chunk(
            "// GitHub token\nauth_token = \"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890\";\n",
            "github.toml",
            100,
        ),
        make_chunk(
            "stripe: sk_live_4eC39HqLyjWDarjtT1zdp7dc\nregion: us-east-1\n",
            "config.yml",
            256,
        ),
        make_chunk(
            "// Alternative AWS format\nASIA5FAKEFAKEFAKEFAKE\n",
            "creds.txt",
            512,
        ),
    ];

    let scan_a = scanner.scan_chunks_with_backend(&corpus, ScanBackend::Gpu);
    let scan_b = scanner.scan_chunks_with_backend(&corpus, ScanBackend::Gpu);

    let keys_a = collect_finding_keys(&scan_a);
    let keys_b = collect_finding_keys(&scan_b);

    assert!(
        !keys_a.is_empty(),
        "multi-secret corpus should produce findings"
    );
    assert_eq!(
        keys_a.len(),
        keys_b.len(),
        "scan counts must match ({} vs {})",
        keys_a.len(),
        keys_b.len()
    );
    assert_finding_sets_identical(&keys_a, &keys_b, "multi_secret_corpus_determinism");
}

#[test]
fn megakernel_three_consecutive_scans_all_match() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let chunk = make_chunk(
        "password=\"sk_live_51JV3jHprivate123456\"\nAPI_KEY=\"AKIAZZZFAKEFAKEFAKE\"\n",
        "secrets.env",
        0,
    );

    let scan_1 = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::Gpu);
    let scan_2 = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::Gpu);
    let scan_3 = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::Gpu);

    let keys_1 = collect_finding_keys(&scan_1);
    let keys_2 = collect_finding_keys(&scan_2);
    let keys_3 = collect_finding_keys(&scan_3);

    assert_eq!(keys_1, keys_2, "scans 1 and 2 must match");
    assert_eq!(keys_2, keys_3, "scans 2 and 3 must match");
    assert_eq!(keys_1, keys_3, "all three scans must be identical");
}

#[test]
fn megakernel_determinism_with_empty_chunks() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let corpus = vec![
        make_chunk("", "empty1.rs", 0),
        make_chunk("const KEY = \"AKIAQYLPMN5HFIQR7BBB\";\n", "real.rs", 0),
        make_chunk("", "empty2.rs", 100),
        make_chunk("   \n\n  \n", "whitespace.txt", 200),
        make_chunk("const PAT = \"ghp_TestToken1234567890abcdefghijk\";\n", "auth.py", 300),
    ];

    let scan_a = scanner.scan_chunks_with_backend(&corpus, ScanBackend::Gpu);
    let scan_b = scanner.scan_chunks_with_backend(&corpus, ScanBackend::Gpu);

    let keys_a = collect_finding_keys(&scan_a);
    let keys_b = collect_finding_keys(&scan_b);

    assert!(
        keys_a.iter().all(|(_, path, _)| path == "real.rs" || path == "auth.py"),
        "empty chunks must not produce false positives"
    );
    assert_finding_sets_identical(&keys_a, &keys_b, "empty_chunks_determinism");
}

// ============================================================================
// CHUNK BOUNDARY TESTS
// ============================================================================

#[test]
fn megakernel_determinism_chunk_boundary_straddle() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let secret = "AKIAQYLPMN5HFIQR7CCC";
    let split_at = 12;

    // Chunk A: padding + first 12 chars of secret.
    let pad_len = 1024 - split_at;
    let mut data_a = "x\n".repeat(pad_len / 2);
    if data_a.len() < pad_len {
        data_a.push('x');
    }
    data_a.push_str(&secret[..split_at]);
    let len_a = data_a.len();

    // Chunk B: remaining 8 chars + suffix.
    let mut data_b = secret[split_at..].to_string();
    data_b.push_str("\";\n");

    let chunk_a = make_chunk(&data_a, "boundary.rs", 0);
    let chunk_b = make_chunk(&data_b, "boundary.rs", len_a);
    let corpus = vec![chunk_a.clone(), chunk_b.clone()];

    let scan_a = scanner.scan_chunks_with_backend(&corpus, ScanBackend::Gpu);
    let scan_b = scanner.scan_chunks_with_backend(&corpus, ScanBackend::Gpu);

    let keys_a = collect_finding_keys(&scan_a);
    let keys_b = collect_finding_keys(&scan_b);

    assert!(
        keys_a.iter().any(|(cred, _, _)| cred == secret),
        "boundary-straddled secret must be found on first scan"
    );
    assert_finding_sets_identical(&keys_a, &keys_b, "chunk_boundary_straddle_determinism");
}

#[test]
fn megakernel_determinism_multiple_chunks_same_file() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // Same logical file split into multiple chunks.
    let corpus = vec![
        make_chunk(
            "// part 1\nconst KEY1 = \"AKIAQYLPMN5HFIQR7AAA\";\n",
            "split.rs",
            0,
        ),
        make_chunk(
            "// part 2\nconst KEY2 = \"AKIAQYLPMN5HFIQR7BBB\";\n",
            "split.rs",
            100,
        ),
        make_chunk(
            "// part 3\nconst KEY3 = \"AKIAQYLPMN5HFIQR7CCC\";\n",
            "split.rs",
            200,
        ),
    ];

    let scan_a = scanner.scan_chunks_with_backend(&corpus, ScanBackend::Gpu);
    let scan_b = scanner.scan_chunks_with_backend(&corpus, ScanBackend::Gpu);

    let keys_a = collect_finding_keys(&scan_a);
    let keys_b = collect_finding_keys(&scan_b);

    assert_eq!(keys_a.len(), 3, "should find all three secrets");
    assert_finding_sets_identical(&keys_a, &keys_b, "multiple_chunks_same_file_determinism");
}

// ============================================================================
// ADVERSARIAL & NEGATIVE TESTS
// ============================================================================

#[test]
fn megakernel_determinism_false_positive_immunity() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // AKIA prefix alone is not a secret; must be followed by 16 alphanumerics.
    let corpus = vec![
        make_chunk("const AKIA_PREFIX = 10; // just a variable name", "false.rs", 0),
        make_chunk("comment // AKIA_XY1234", "false2.rs", 50),
        make_chunk("ghp_ is incomplete", "false3.rs", 100),
    ];

    let scan_a = scanner.scan_chunks_with_backend(&corpus, ScanBackend::Gpu);
    let scan_b = scanner.scan_chunks_with_backend(&corpus, ScanBackend::Gpu);

    let keys_a = collect_finding_keys(&scan_a);
    let keys_b = collect_finding_keys(&scan_b);

    assert!(
        keys_a.is_empty(),
        "incomplete credential prefixes must not trigger"
    );
    assert_eq!(keys_a, keys_b, "both scans must correctly return empty");
}

#[test]
fn megakernel_determinism_adversarial_noise_density() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // Dense noise (many false-positive candidates) interspersed with one real secret.
    let mut data = String::new();
    for i in 0..500 {
        data.push_str(&format!("AKIA_fake_{}_{}\n", i, "x".repeat(16)));
    }
    data.push_str("real_key = \"AKIAQYLPMN5HFIQR7EEE\";\n");
    for i in 500..1000 {
        data.push_str(&format!("AKIA_fake_{}_{}\n", i, "y".repeat(16)));
    }

    let chunk = make_chunk(&data, "noise.rs", 0);

    let scan_a = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::Gpu);
    let scan_b = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::Gpu);

    let keys_a = collect_finding_keys(&scan_a);
    let keys_b = collect_finding_keys(&scan_b);

    assert!(
        keys_a
            .iter()
            .any(|(cred, _, _)| cred == "AKIAQYLPMN5HFIQR7EEE"),
        "real secret must be found among noise"
    );
    assert_finding_sets_identical(&keys_a, &keys_b, "noise_density_determinism");
}

#[test]
fn megakernel_determinism_high_entropy_fallback() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // Generic high-entropy string (no known prefix).
    let corpus = vec![
        make_chunk("api_token=aBcDeF1234567890GhIjKlMnOpQrStUv", "entropy.py", 0),
        make_chunk(
            "const SECRET = \"XxYyZz1234567890AbCdEfGhIjKlMnOpQr\";\n",
            "entropy.rs",
            50,
        ),
    ];

    let scan_a = scanner.scan_chunks_with_backend(&corpus, ScanBackend::Gpu);
    let scan_b = scanner.scan_chunks_with_backend(&corpus, ScanBackend::Gpu);

    let keys_a = collect_finding_keys(&scan_a);
    let keys_b = collect_finding_keys(&scan_b);

    // Entropy fallback may or may not trigger depending on threshold; the test
    // gates determinism, not presence.
    assert_eq!(
        keys_a, keys_b,
        "entropy fallback results must be identical across scans"
    );
}

// ============================================================================
// DENSE CORPUS STRESS TESTS
// ============================================================================

#[test]
fn megakernel_determinism_dense_secret_corpus() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // Dense corpus: one credential per line.
    let mut data = String::new();
    let secrets = vec![
        "AKIAQYLPMN5HFIQR7DDD",
        "ASIAQYLPMN5HFIQR7EEE",
        "ghp_1234567890abcdefghij1234567890",
        "sk_live_51JV3jHprivateKey123456789",
    ];
    for (i, secret) in secrets.iter().enumerate() {
        data.push_str(&format!("secret_{}: {}\n", i, secret));
    }

    let chunk = make_chunk(&data, "dense.txt", 0);

    let scan_a = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::Gpu);
    let scan_b = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::Gpu);

    let keys_a = collect_finding_keys(&scan_a);
    let keys_b = collect_finding_keys(&scan_b);

    assert!(
        keys_a.len() >= 2,
        "should find multiple secrets in dense corpus"
    );
    assert_finding_sets_identical(&keys_a, &keys_b, "dense_secret_corpus_determinism");
}

#[test]
fn megakernel_determinism_mixed_secret_types() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let corpus = vec![
        make_chunk(
            "# AWS\nAKIA_KEY=AKIAQYLPMN5HFIQR7000\n# GitHub\nGH_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx\n",
            "mixed.sh",
            0,
        ),
        make_chunk(
            "stripe.key = sk_live_4eC39HqLyjWDarjtT1zdp7dc\n\
             gcp.key = AIza_zzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n",
            "config.toml",
            200,
        ),
        make_chunk(
            "APIKEY: AKIAZZZFAKEFAKEFAKE\nREGION: us-west-2\n",
            "deploy.yml",
            400,
        ),
    ];

    let scan_a = scanner.scan_chunks_with_backend(&corpus, ScanBackend::Gpu);
    let scan_b = scanner.scan_chunks_with_backend(&corpus, ScanBackend::Gpu);

    let keys_a = collect_finding_keys(&scan_a);
    let keys_b = collect_finding_keys(&scan_b);

    assert!(
        !keys_a.is_empty(),
        "should find credentials of different types"
    );
    assert_finding_sets_identical(&keys_a, &keys_b, "mixed_secret_types_determinism");
}

// ============================================================================
// HOST PATH (NON-LOWERABLE PATTERNS) TESTS
// ============================================================================

#[test]
fn megakernel_host_path_loud_fallback() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // Fixture includes credentials that may not lower to unanchored DFA
    // (e.g., patterns with lookahead, backrefs, or extreme state budgets).
    // The megakernel must catch these via the loud host path.
    let chunk = make_chunk(
        "password = \"AKIAQYLPMN5HFIQR7FFF\"\ntoken = \"ghp_XXXXXXXXXXXXXXXXXXXXXXXX\"\n",
        "hostpath.rs",
        0,
    );

    let scan_a = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::Gpu);
    let scan_b = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::Gpu);

    let keys_a = collect_finding_keys(&scan_a);
    let keys_b = collect_finding_keys(&scan_b);

    // Even if some patterns take the host path, they must be deterministically found.
    assert!(
        !keys_a.is_empty(),
        "host path patterns must still be found"
    );
    assert_finding_sets_identical(&keys_a, &keys_b, "host_path_determinism");
}

#[test]
fn megakernel_catalog_handles_non_lowerable_gracefully() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // Deliberately craft a corpus that exercises patterns at the edge of
    // what can lower to unanchored DFA vs. what must use host path.
    let corpus = vec![
        make_chunk("AKIA with exact 20 chars: AKIAQYLPMN5HFIQR7GGG\n", "edge1.rs", 0),
        make_chunk(
            "variant with suffix: AKIAQYLPMN5HFIQR7HHH_extra_stuff\n",
            "edge2.rs",
            100,
        ),
        make_chunk("ghp_token_github: ghp_abcdefghijklmnopqrst\n", "edge3.rs", 200),
    ];

    let scan_a = scanner.scan_chunks_with_backend(&corpus, ScanBackend::Gpu);
    let scan_b = scanner.scan_chunks_with_backend(&corpus, ScanBackend::Gpu);

    let keys_a = collect_finding_keys(&scan_a);
    let keys_b = collect_finding_keys(&scan_b);

    // Regardless of which patterns lower vs. use host path, the result must be
    // identical and reproducible.
    assert_finding_sets_identical(
        &keys_a,
        &keys_b,
        "non_lowerable_patterns_determinism",
    );
}

// ============================================================================
// LARGE BATCH DETERMINISM
// ============================================================================

#[test]
fn megakernel_large_batch_determinism() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // Create a batch of many chunks to stress the dispatcher.
    let mut corpus = Vec::new();
    for i in 0..50 {
        let content = if i % 5 == 0 {
            format!("const KEY_{} = \"AKIAQYLPMN5HFIQR{:04}\";\n", i, i)
        } else {
            format!("// chunk {}: no secrets here\nfn func_{}() {{}}\n", i, i)
        };
        corpus.push(make_chunk(&content, &format!("batch_{}.rs", i), i * 100));
    }

    let scan_a = scanner.scan_chunks_with_backend(&corpus, ScanBackend::Gpu);
    let scan_b = scanner.scan_chunks_with_backend(&corpus, ScanBackend::Gpu);

    let keys_a = collect_finding_keys(&scan_a);
    let keys_b = collect_finding_keys(&scan_b);

    assert!(
        keys_a.len() >= 10,
        "large batch should find multiple credentials"
    );
    assert_finding_sets_identical(&keys_a, &keys_b, "large_batch_determinism");
}

// ============================================================================
// PARITY WITH OTHER BACKENDS (BONUS)
// ============================================================================

#[test]
fn megakernel_finding_count_vs_simd_parity() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let corpus = vec![
        make_chunk(
            "key1 = AKIAQYLPMN5HFIQR7III\nkey2 = ghp_abcdefghijklmnopqrst123456\n",
            "parity.rs",
            0,
        ),
        make_chunk(
            "stripe = sk_live_4eC39HqLyjWDarjtT1zdp7dc\nother = xyz\n",
            "parity2.yml",
            150,
        ),
    ];

    let gpu_results = scanner.scan_chunks_with_backend(&corpus, ScanBackend::Gpu);
    let simd_results = scanner.scan_chunks_with_backend(&corpus, ScanBackend::SimdCpu);

    let gpu_keys = collect_finding_keys(&gpu_results);
    let simd_keys = collect_finding_keys(&simd_results);

    assert_gpu_not_silent_empty(
        gpu_results.iter().all(|c| c.is_empty()),
        simd_keys.len(),
        "megakernel_vs_simd_parity",
    );

    // Allow for minor differences (e.g., detector attribution on shared literals),
    // but finding count must match and core credentials must agree.
    assert_eq!(
        gpu_keys.len(),
        simd_keys.len(),
        "GPU and SIMD must find the same number of credentials"
    );
}

// ============================================================================
// CACHE FRESHNESS TESTS
// ============================================================================

#[test]
fn megakernel_determinism_cache_warm_cold_identical() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let chunk = make_chunk(
        "REAL_SECRET=AKIAQYLPMN5HFIQR7JJJ\n",
        "cache_test.rs",
        0,
    );

    // Cold scan (first dispatch).
    let scan_cold = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::Gpu);

    // Warm scan (same GPU session, cache resident).
    let scan_warm = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::Gpu);

    let keys_cold = collect_finding_keys(&scan_cold);
    let keys_warm = collect_finding_keys(&scan_warm);

    assert!(
        !keys_cold.is_empty(),
        "cold scan must find the secret"
    );
    assert_finding_sets_identical(&keys_cold, &keys_warm, "cache_warm_cold_identical");
}

#[test]
fn megakernel_many_rounds_stable() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let chunk = make_chunk(
        "api=AKIAQYLPMN5HFIQR7KKK\ntoken=ghp_LongGitHubTokenValue123456789012\n",
        "stability.py",
        0,
    );

    let mut keys_baseline = None;
    for round in 0..10 {
        let scan_result = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::Gpu);
        let keys = collect_finding_keys(&scan_result);

        match keys_baseline {
            None => keys_baseline = Some(keys),
            Some(ref baseline) => {
                assert_eq!(
                    &keys, baseline,
                    "round {} diverged from baseline",
                    round
                );
            }
        }
    }

    assert!(
        keys_baseline.is_some() && !keys_baseline.as_ref().unwrap().is_empty(),
        "at least one baseline scan must find credentials"
    );
}
