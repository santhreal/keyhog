//! Integration test suite for phase-2 anchor and literal prefilter verification.
//!
//! Validates candidate collection, preallocated buffer reuse across chunks,
//! always-active prefilter gating, and differential parity between localized
//! shared-anchor execution and baseline whole-chunk scanning.

fn detector_dir() -> std::path::PathBuf {
    let mut d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.join("detectors")
}

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScanExecutionRoute};
use std::collections::BTreeSet;

fn chunk_of(bytes: &[u8], label: &str) -> Chunk {
    Chunk {
        data: String::from_utf8_lossy(bytes).into_owned().into(),
        metadata: ChunkMetadata {
            source_type: "integration-phase2".into(),
            path: Some(label.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

type FindingKey = (String, String, usize);

fn canonical_findings(matches: &[RawMatch]) -> BTreeSet<FindingKey> {
    matches
        .iter()
        .map(|m| {
            (
                m.detector_id.as_ref().to_string(),
                m.credential.as_ref().to_string(),
                m.location.offset,
            )
        })
        .collect()
}

fn compile_scanner(detector_ids: &[&str]) -> CompiledScanner {
    let mut detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    detectors.retain(|d| detector_ids.contains(&d.id.as_str()));
    for id in detector_ids {
        assert!(
            detectors.iter().any(|d| d.id == *id),
            "test detector set missing required detector: {id}"
        );
    }
    CompiledScanner::compile(detectors).expect("compile scanner")
}

const TEST_DETECTORS: &[&str] = &[
    "aws-access-key",
    "github-classic-pat",
    "slack-bot-token",
    "stripe-secret-key",
];

#[test]
fn test_phase2_anchor_candidate_verification_and_buffer_reuse() {
    let scanner = compile_scanner(TEST_DETECTORS);

    // Sequence of distinct chunks scanned back-to-back to verify candidate scratch
    // buffer reuse without cross-chunk residual pollution or reallocation stalls.
    let test_cases = [
        // 1. AWS key at start (offset 0)
        (
            "AKIAQYLPMN5HFIQR7XYZ rest of config",
            vec!["aws-access-key"],
        ),
        // 2. GitHub PAT mid-chunk (checksum-valid CRC32 token from detectors/github-classic-pat.toml)
        (
            "let token = \"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\";",
            vec!["github-classic-pat"],
        ),
        // 3. Slack bot token
        (
            "slack_token: xoxb-123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUvWx",
            vec!["slack-bot-token"],
        ),
        // 4. Multiple adjacent secrets in one chunk
        (
            "AKIAQYLPMN5HFIQR7XYZ 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",
            vec!["aws-access-key", "github-classic-pat"],
        ),
        // 5. Clean / no-candidate chunk
        (
            "fn helper() -> bool { true // clean source code without secrets\n}",
            vec![],
        ),
        // 6. Stripe secret key
        (
            "stripe_key = 'sk_live_0123456789abcdefABCDEFxyz0'",
            vec!["stripe-secret-key"],
        ),
    ];

    for (i, (text, expected_detectors)) in test_cases.iter().enumerate() {
        let chunk = chunk_of(text.as_bytes(), &format!("chunk-{i}.txt"));
        let matches = scanner
            .scan(&chunk)
            .expect("phase2 candidate verification scan succeeds");
        let detected: BTreeSet<&str> = matches.iter().map(|m| m.detector_id.as_ref()).collect();
        let expected: BTreeSet<&str> = expected_detectors.iter().copied().collect();
        assert_eq!(
            detected, expected,
            "detected detector mismatch on chunk {i} ({text}): got {detected:?}, expected {expected:?}"
        );
    }
}

#[test]
fn test_phase2_localized_route_parity_with_whole_chunk() {
    let scanner = compile_scanner(TEST_DETECTORS);

    let test_corpus = [
        "AKIAQYLPMN5HFIQR7XYZ",
        "export GITHUB_TOKEN=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",
        "api_key: sk_live_0123456789abcdefABCDEFxyz0\nslack: xoxb-123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUvWx",
        "prefix AKIAQYLPMN5HFIQR7XYZ middle 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 suffix",
        "no secrets anywhere here in this file, purely benign text\nsecond line also clean\n",
    ];

    for (i, text) in test_corpus.iter().enumerate() {
        let chunk = chunk_of(text.as_bytes(), &format!("parity-{i}.txt"));

        // Localized shared-anchor route (production default)
        scanner.clear_fragment_cache();
        let localized_res = scanner
            .scan_coalesced_with_backend_admission_and_route(
                std::slice::from_ref(&chunk),
                ScanBackend::CpuFallback,
                None,
                ScanExecutionRoute {
                    decode_backend: ScanBackend::CpuFallback,
                    phase2_plain_localizer: true,
                    phase2_keyword_localizer: true,
                    gpu_pipeline_depth: 1,
                },
            )
            .expect("localized scan succeeds");
        let localized_findings =
            canonical_findings(&localized_res.into_iter().flatten().collect::<Vec<_>>());

        // Baseline whole-chunk route (unoptimized baseline)
        scanner.clear_fragment_cache();
        let whole_chunk_res = scanner
            .scan_coalesced_with_backend_admission_and_route(
                std::slice::from_ref(&chunk),
                ScanBackend::CpuFallback,
                None,
                ScanExecutionRoute {
                    decode_backend: ScanBackend::CpuFallback,
                    phase2_plain_localizer: false,
                    phase2_keyword_localizer: false,
                    gpu_pipeline_depth: 1,
                },
            )
            .expect("whole-chunk scan succeeds");
        let whole_chunk_findings =
            canonical_findings(&whole_chunk_res.into_iter().flatten().collect::<Vec<_>>());

        assert_eq!(
            localized_findings, whole_chunk_findings,
            "parity mismatch on test corpus #{i} for text: {text:?}"
        );
    }
}

#[test]
fn test_phase2_prefilter_clean_chunk_produces_zero_findings() {
    let scanner = compile_scanner(TEST_DETECTORS);
    let clean_chunk = chunk_of(
        b"// This is completely clean text\nconst x = 42;\nfn compute() -> i32 { x * 2 }\n",
        "clean.rs",
    );

    scanner.clear_fragment_cache();
    let matches = scanner.scan(&clean_chunk).expect("clean scan succeeds");
    assert!(
        matches.is_empty(),
        "clean text must have zero findings, got {matches:?}"
    );
}
