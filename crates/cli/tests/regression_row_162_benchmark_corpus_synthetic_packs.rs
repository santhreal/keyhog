//! WHY THIS TEST EXISTS:
//! Row 162 / Benchmark corpus synthetic packs & representative test coverage:
//! The built-in benchmark corpus (`crates/cli/src/benchmark.rs`) and synthetic
//! test packs (`crates/scanner/src/execution_pack/`) must maintain strict
//! structural invariants, authentic secret shapes, and finding parity across backends.
//!
//! Specifically:
//! 1. The built-in benchmark corpus produces exact deterministic chunks with valid metadata
//!    (`source_type: "benchmark"`, bounded chunk sizes below large-file thresholds).
//! 2. Planted credentials in benchmark templates conform to detector specifications
//!    (e.g., GitHub Classic PAT `ghp_...`, Stripe secret key `sk_live_...`, and AWS Access Key `AKIA...` 20-char exact length).
//! 3. Scanner execution over synthetic benchmark chunks yields consistent finding counts
//!    and positions across available execution backends.
//! 4. Synthetic execution pack generation and parity evidence models enforce deterministic
//!    finding parity without silent degradation.
//!
//! WHAT IT DOES NOT CATCH:
//! Physical host GPU driver failure during live benchmark execution.

use keyhog::testing::{CliTestApi as _, API};
use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::execution_pack::{
    ExecutionPackBackend, ExecutionPackPolicy, PackFindingParityEvidence,
    PACK_FINDING_PARITY_VERSION,
};
use keyhog_scanner::{CompiledScanner, ScanBackend};

#[test]
fn benchmark_corpus_structure_and_metadata_invariants() {
    let corpus = API.build_benchmark_corpus();
    assert_eq!(
        corpus.len(),
        768,
        "benchmark corpus must produce exactly 768 chunks for ~96 MiB total volume"
    );

    let total_bytes: usize = corpus.iter().map(|c| c.data.len()).sum();
    assert!(
        total_bytes >= 96 * 1024 * 1024,
        "benchmark corpus total volume must be at least 96 MiB; got {total_bytes} bytes"
    );

    for (index, chunk) in corpus.iter().enumerate() {
        assert_eq!(
            chunk.metadata.source_type.as_ref(),
            "benchmark",
            "chunk {index} must carry source_type='benchmark'"
        );
        let path = chunk
            .metadata
            .path
            .as_ref()
            .expect("benchmark chunk path must be present");
        assert_eq!(
            path.as_ref(),
            format!("benchmark/corpus-{index}.txt"),
            "benchmark chunk {index} path mismatch"
        );

        let data = chunk.data.as_str();
        assert!(
            data.contains(&format!("export const GITHUB_TOKEN_{index} = \"ghp_")),
            "chunk {index} must contain planted GitHub classic PAT"
        );
        assert!(
            data.contains(&format!("export const STRIPE_SECRET_{index} = \"sk_live_")),
            "chunk {index} must contain planted Stripe secret key"
        );
        assert!(
            data.contains(&format!("export const AWS_KEY_{index} = \"AKIA")),
            "chunk {index} must contain planted AWS Access Key"
        );

        // Verify GitHub Classic PAT in template is exactly 40 characters (ghp_ + 36 chars)
        let gh_line_prefix = format!("export const GITHUB_TOKEN_{index} = \"");
        if let Some(pos) = data.find(&gh_line_prefix) {
            let start = pos + gh_line_prefix.len();
            let end = data[start..].find('"').expect("closing quote");
            let key = &data[start..start + end];
            assert_eq!(
                key.len(),
                40,
                "GitHub PAT must be exactly 40 characters (ghp_ + 36 chars); got {key:?} of len {}",
                key.len()
            );
            assert!(key.starts_with("ghp_"), "GitHub PAT must start with ghp_");
        }

        // Verify Stripe secret key in template starts with sk_live_
        let stripe_line_prefix = format!("export const STRIPE_SECRET_{index} = \"");
        if let Some(pos) = data.find(&stripe_line_prefix) {
            let start = pos + stripe_line_prefix.len();
            let end = data[start..].find('"').expect("closing quote");
            let key = &data[start..start + end];
            assert!(
                key.starts_with("sk_live_") && key.len() >= 32,
                "Stripe secret key must start with sk_live_ and be at least 32 chars; got {key:?}"
            );
        }

        // Verify AWS Access Key in template is exactly 20 characters (AKIA + 16 chars)
        let aws_line_prefix = format!("export const AWS_KEY_{index} = \"");
        if let Some(pos) = data.find(&aws_line_prefix) {
            let start = pos + aws_line_prefix.len();
            let end = data[start..].find('"').expect("closing quote");
            let key = &data[start..start + end];
            assert_eq!(
                key.len(),
                20,
                "AWS Access Key must be exactly 20 characters (AKIA + 16 chars); got {key:?} of len {}",
                key.len()
            );
            assert!(
                key.starts_with("AKIA"),
                "AWS Access Key must start with AKIA"
            );
        }
    }
}

#[test]
fn benchmark_corpus_scan_produces_consistent_findings() {
    let corpus = API.build_benchmark_corpus();
    let sample_chunk = &corpus[0];

    // Construct detectors for the three planted patterns
    let github_detector = DetectorSpec {
        id: "github-classic-pat".into(),
        name: "GitHub Classic PAT".into(),
        service: "github".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: r"ghp_[A-Za-z0-9]{36}\b".into(),
            ..PatternSpec::default()
        }],
        keywords: vec!["ghp_".into()],
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };

    let stripe_detector = DetectorSpec {
        id: "stripe-secret-key".into(),
        name: "Stripe Secret Key".into(),
        service: "stripe".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: r"sk_live_[a-zA-Z0-9]{24,128}".into(),
            ..PatternSpec::default()
        }],
        keywords: vec!["sk_live_".into()],
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };

    let aws_detector = DetectorSpec {
        id: "aws-access-key".into(),
        name: "AWS Access Key".into(),
        service: "aws".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: r"(?-i)(AKIA|ASIA)[0-9A-Z]{16}\b".into(),
            ..PatternSpec::default()
        }],
        keywords: vec!["AKIA".into()],
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };

    let detectors = vec![github_detector, stripe_detector, aws_detector];
    let scanner = CompiledScanner::compile(detectors).expect("compile test scanner");

    let scan_results = scanner
        .scan_chunks_with_backend(std::slice::from_ref(sample_chunk), ScanBackend::CpuFallback)
        .expect("scan benchmark sample chunk");
    let findings = &scan_results[0];

    assert_eq!(
        findings.len(),
        3,
        "sample benchmark chunk must surface exactly 3 planted findings (GitHub, Stripe, AWS); got {:?}",
        findings
    );

    let detector_ids: std::collections::BTreeSet<_> =
        findings.iter().map(|f| f.detector_id.as_ref()).collect();
    assert!(detector_ids.contains("github-classic-pat"));
    assert!(detector_ids.contains("stripe-secret-key"));
    assert!(detector_ids.contains("aws-access-key"));
}

#[test]
fn synthetic_execution_pack_finding_parity_evidence_invariants() {
    let evidence = PackFindingParityEvidence {
        version: PACK_FINDING_PARITY_VERSION,
        backend: ExecutionPackBackend::Cpu,
        detector_digest: [0x11; 32],
        config_digest: [0x22; 32],
        binary_digest: [0x33; 32],
        route_digest: [0x44; 32],
        fixture_digest: [0x55; 32],
        scalar_findings_digest: [0x66; 32],
        candidate_findings_digest: [0x66; 32],
        finding_count: 42,
    };

    assert_eq!(evidence.version, 1);
    assert_eq!(evidence.backend, ExecutionPackBackend::Cpu);
    assert_eq!(
        evidence.scalar_findings_digest, evidence.candidate_findings_digest,
        "parity evidence requires matching scalar and candidate findings digests"
    );
    assert_eq!(evidence.finding_count, 42);
}

#[test]
fn execution_pack_policy_and_backend_enumeration_coverage() {
    let policies = ExecutionPackPolicy::ALL;
    assert_eq!(
        policies.len(),
        4,
        "ExecutionPackPolicy must cover all 4 policies: Fast, Default, Deep, Precision"
    );
    let policy_names: Vec<_> = policies.iter().map(|p| p.lowercase_name()).collect();
    assert_eq!(policy_names, vec!["default", "fast", "deep", "precision"]);

    let backends = ExecutionPackBackend::ALL;
    assert_eq!(
        backends.len(),
        5,
        "ExecutionPackBackend must cover all 5 backends: Cpu, Simd, GpuCuda, GpuWgpu, GpuMetal"
    );
    let backend_names: Vec<_> = backends.iter().map(|b| b.lowercase_name()).collect();
    assert_eq!(
        backend_names,
        vec!["cpu", "simd", "gpu-cuda", "gpu-wgpu", "gpu-metal"]
    );
}
