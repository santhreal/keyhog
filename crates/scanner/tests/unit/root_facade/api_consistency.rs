//! API consistency matrix - every public scanner entry point must
//! produce equivalent findings for the same input.
//!
//! CompiledScanner exposes four scan APIs:
//!   * `scan(chunk)` - single chunk, portable CPU reference, no deadline.
//!   * `scan_with_backend(chunk, backend)` - single chunk, caller-
//!     selected backend.
//!   * `scan_with_deadline(chunk, deadline)` - single chunk, CPU reference,
//!     with timeout.
//!   * `scan_chunks_with_backend(chunks, backend)` - multi-chunk, caller-
//!     selected backend, returns one Vec<RawMatch> per input chunk.
//!
//! All four must produce the same finding set on the same input
//! (modulo deadline cuts when the deadline fires mid-scan, which we
//! avoid here by passing `None` / a far-future deadline). A drift here
//! is a contract regression invisible to per-API tests.

use super::support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::collections::BTreeSet;
use std::sync::LazyLock;

const DETECTOR_IDS: &[&str] = &["aws-access-key", "github-classic-pat", "stripe-secret-key"];

fn compile_scanner(backend: ScanBackend) -> CompiledScanner {
    let mut detectors =
        keyhog_core::load_detectors(&support::paths::detector_dir()).expect("detectors");
    detectors.retain(|detector| DETECTOR_IDS.contains(&detector.id.as_str()));
    for id in DETECTOR_IDS {
        assert!(
            detectors.iter().any(|detector| detector.id == *id),
            "API consistency detector subset missing shipped detector {id}"
        );
    }
    CompiledScanner::compile_for_backend(detectors, backend).expect("compile exact backend scanner")
}

static CPU_SCANNER: LazyLock<CompiledScanner> =
    LazyLock::new(|| compile_scanner(ScanBackend::CpuFallback));
static SIMD_SCANNER: LazyLock<CompiledScanner> =
    LazyLock::new(|| compile_scanner(ScanBackend::SimdCpu));

fn scanner(backend: ScanBackend) -> &'static CompiledScanner {
    match backend {
        ScanBackend::CpuFallback => &CPU_SCANNER,
        ScanBackend::SimdCpu => &SIMD_SCANNER,
        _ => panic!("API consistency scanner only covers exact CPU and SIMD routes"),
    }
}

fn make_chunk(text: &str, path: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "api-consistency".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

type FindingKey = (String, String, String, usize);

fn key(matches: &[keyhog_core::RawMatch]) -> BTreeSet<FindingKey> {
    matches
        .iter()
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
            )
        })
        .collect()
}

fn key_chunks(per_chunk: &[Vec<keyhog_core::RawMatch>]) -> BTreeSet<FindingKey> {
    let mut s = BTreeSet::new();
    for chunk in per_chunk {
        for m in chunk {
            s.insert((
                m.detector_id.as_ref().to_string(),
                m.credential.as_ref().to_string(),
                m.location
                    .file_path
                    .as_deref()
                    .map(str::to_string)
                    .unwrap_or_default(),
                m.location.offset,
            ));
        }
    }
    s
}

/// Hyperscan UCP semantics reject word boundaries and can use different
/// Unicode tables for shorthand classes such as `\d`. The SIMD path must
/// retain those shipped detectors through its exact CPU recovery route instead
/// of failing backend initialization or losing a Unicode finding.
#[test]
fn daemon_style_stdin_aws_chunk_reports_named_detector() {
    let _telemetry_guard = super::super::telemetry_serial::lock();
    let chunk = Chunk {
        data: "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n".into(),
        metadata: ChunkMetadata {
            source_type: "stdin".into(),
            path: None,
            base_offset: 0,
            ..Default::default()
        },
    };
    for backend in [ScanBackend::SimdCpu, ScanBackend::CpuFallback] {
        let scanner = scanner(backend);
        scanner.clear_fragment_cache();
        let matches = scanner
            .scan_with_backend(&chunk, backend)
            .expect("selected backend scan succeeds");
        assert!(
            matches.iter().any(|m| {
                m.detector_id.as_ref() == "aws-access-key"
                    && m.credential.as_ref() == "AKIAQYLPMN5HFIQR7XYA"
                    && m.location.source.as_ref() == "stdin"
                    && m.location.file_path.is_none()
                    && m.location.line == Some(1)
            }),
            "daemon-style stdin scan on {backend:?} must include the named AWS detector; got {matches:?}"
        );
    }
}

#[test]
fn scan_and_scan_with_deadline_none_agree() {
    let _telemetry_guard = super::super::telemetry_serial::lock();
    let scanner = scanner(ScanBackend::CpuFallback);
    scanner.clear_fragment_cache();
    let chunk = make_chunk(
        "const AWS = \"AKIAQYLPMN5HFIQR7XYA\";\nconst PAT = \"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\";\n",
        "fixtures/aws_pat.rs",
    );
    let auto = key(&scanner.scan(&chunk).expect("test scan succeeds"));
    let deadline_none = key(&keyhog_scanner::testing::scan_with_deadline(
        &scanner, &chunk, None,
    ));
    assert_eq!(
        auto, deadline_none,
        "scan() and scan_with_deadline(None) must produce identical findings"
    );
}

#[test]
fn scan_with_backend_each_matches_scan_chunks_with_backend() {
    let _telemetry_guard = super::super::telemetry_serial::lock();
    let chunk = make_chunk(
        "auth: \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"\npayload: \"AKIAQYLPMN5HFIQR7BBB\"\n",
        "fixtures/stripe_aws.yml",
    );
    for backend in [ScanBackend::SimdCpu, ScanBackend::CpuFallback] {
        let scanner = scanner(backend);
        scanner.clear_fragment_cache();
        let single = key(&scanner
            .scan_with_backend(&chunk, backend)
            .expect("selected backend scan succeeds"));
        let multi = key_chunks(
            &scanner
                .scan_chunks_with_backend(std::slice::from_ref(&chunk), backend)
                .expect("selected backend scan succeeds"),
        );
        assert_eq!(
            single,
            multi,
            "scan_with_backend({backend:?}) and scan_chunks_with_backend(&[chunk], {backend:?}) \
             must produce identical findings: single={} multi={}",
            single.len(),
            multi.len()
        );
    }
}

#[test]
fn scan_repeated_invocations_produce_identical_findings() {
    let _telemetry_guard = super::super::telemetry_serial::lock();
    // Determinism contract: the same scanner instance scanning the
    // same input twice in a row must produce byte-identical findings.
    let scanner = scanner(ScanBackend::CpuFallback);
    scanner.clear_fragment_cache();
    let chunk = make_chunk(
        "GITHUB_TOKEN=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\n",
        "env.txt",
    );
    let a = key(&scanner.scan(&chunk).expect("test scan succeeds"));
    let b = key(&scanner.scan(&chunk).expect("test scan succeeds"));
    let c = key(&scanner.scan(&chunk).expect("test scan succeeds"));
    assert_eq!(a, b);
    assert_eq!(b, c);
}

#[test]
fn empty_chunks_slice_returns_empty_results() {
    let _telemetry_guard = super::super::telemetry_serial::lock();
    let scanner = scanner(ScanBackend::CpuFallback);
    scanner.clear_fragment_cache();
    let r = scanner
        .scan_chunks_with_backend(&[], ScanBackend::CpuFallback)
        .expect("selected backend scan succeeds");
    assert!(
        r.is_empty(),
        "empty input slice must return empty result slice"
    );
}
#[test]
fn multi_chunk_input_preserves_per_chunk_attribution() {
    let _telemetry_guard = super::super::telemetry_serial::lock();
    let scanner = scanner(ScanBackend::CpuFallback);
    scanner.clear_fragment_cache();
    let chunks = vec![
        make_chunk("noise\n", "a.txt"),
        make_chunk("AWS = \"AKIAQYLPMN5HFIQR7XYA\"\n", "b.txt"),
        make_chunk("more noise\n", "c.txt"),
        make_chunk(
            "PAT = \"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\"\n",
            "d.txt",
        ),
    ];
    let results = scanner
        .scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback)
        .expect("selected backend scan succeeds");
    assert_eq!(
        results.len(),
        chunks.len(),
        "per-chunk results slice length mismatch"
    );

    // a.txt and c.txt must have NO findings (no secrets); b.txt and d.txt MUST.
    assert!(
        results[0].is_empty(),
        "a.txt should have no findings, has {}",
        results[0].len()
    );
    assert!(
        !results[1].is_empty(),
        "b.txt should have AKIA finding, has 0"
    );
    assert!(
        results[2].is_empty(),
        "c.txt should have no findings, has {}",
        results[2].len()
    );
    assert!(
        !results[3].is_empty(),
        "d.txt should have ghp_ finding, has 0"
    );

    // Per-chunk path attribution must be preserved.
    for (idx, chunk_results) in results.iter().enumerate() {
        let expected_path = chunks[idx].metadata.path.as_deref().unwrap();
        for m in chunk_results {
            assert_eq!(
                m.location.file_path.as_deref(),
                Some(expected_path),
                "chunk {idx} finding {:?} attributed to wrong path: got {:?}, want {expected_path}",
                m.credential.as_ref(),
                m.location.file_path
            );
        }
    }
}
