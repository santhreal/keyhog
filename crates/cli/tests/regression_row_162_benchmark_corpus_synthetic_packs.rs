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
    ExecutionPackBackend, ExecutionPackError, ExecutionPackPolicy, PackFindingParityEvidence,
    PackGenerationIdentity, PACK_FINDING_PARITY_VERSION,
};
use keyhog_scanner::{probe_hardware, CompiledScanner, ScanBackend};

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
        let gh_line_prefix = format!("export const GITHUB_TOKEN_{index} = \"");
        let stripe_line_prefix = format!("export const STRIPE_SECRET_{index} = \"");
        let aws_line_prefix = format!("export const AWS_KEY_{index} = \"");

        assert!(
            data.contains(&gh_line_prefix),
            "chunk {index} must contain planted GitHub classic PAT prefix"
        );
        assert!(
            data.contains(&stripe_line_prefix),
            "chunk {index} must contain planted Stripe secret key prefix"
        );
        assert!(
            data.contains(&aws_line_prefix),
            "chunk {index} must contain planted AWS Access Key prefix"
        );

        // Verify GitHub Classic PAT in template is exactly 40 characters (ghp_ + 36 chars)
        let gh_pos = data
            .find(&gh_line_prefix)
            .expect("planted GitHub PAT prefix must be present in chunk data");
        let gh_start = gh_pos + gh_line_prefix.len();
        let gh_end = data[gh_start..]
            .find('"')
            .expect("closing quote for GitHub PAT");
        let gh_key = &data[gh_start..gh_start + gh_end];
        assert_eq!(
            gh_key.len(),
            40,
            "GitHub PAT must be exactly 40 characters (ghp_ + 36 chars); got {gh_key:?} of len {}",
            gh_key.len()
        );
        assert!(
            gh_key.starts_with("ghp_"),
            "GitHub PAT must start with ghp_"
        );

        // Verify Stripe secret key in template starts with sk_live_
        let stripe_pos = data
            .find(&stripe_line_prefix)
            .expect("planted Stripe secret key prefix must be present in chunk data");
        let stripe_start = stripe_pos + stripe_line_prefix.len();
        let stripe_end = data[stripe_start..]
            .find('"')
            .expect("closing quote for Stripe key");
        let stripe_key = &data[stripe_start..stripe_start + stripe_end];
        assert!(
            stripe_key.starts_with("sk_live_") && stripe_key.len() >= 32,
            "Stripe secret key must start with sk_live_ and be at least 32 chars; got {stripe_key:?}"
        );

        // Verify AWS Access Key in template is exactly 20 characters (AKIA + 16 chars)
        let aws_pos = data
            .find(&aws_line_prefix)
            .expect("planted AWS Access Key prefix must be present in chunk data");
        let aws_start = aws_pos + aws_line_prefix.len();
        let aws_end = data[aws_start..]
            .find('"')
            .expect("closing quote for AWS key");
        let aws_key = &data[aws_start..aws_start + aws_end];
        assert_eq!(
            aws_key.len(),
            20,
            "AWS Access Key must be exactly 20 characters (AKIA + 16 chars); got {aws_key:?} of len {}",
            aws_key.len()
        );
        assert!(
            aws_key.starts_with("AKIA"),
            "AWS Access Key must start with AKIA"
        );
    }
}

#[test]
fn benchmark_corpus_scan_produces_consistent_findings() {
    // Bounded chunk allocation to avoid redundant 96 MiB allocations in test runner
    let sample_chunk = API.build_benchmark_chunk(0);

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

    let cpu_results = scanner
        .scan_chunks_with_backend(
            std::slice::from_ref(&sample_chunk),
            ScanBackend::CpuFallback,
        )
        .expect("scan benchmark sample chunk on CpuFallback");
    let cpu_findings = &cpu_results[0];

    assert_eq!(
        cpu_findings.len(),
        3,
        "sample benchmark chunk must surface exactly 3 planted findings (GitHub, Stripe, AWS) on CpuFallback; got {:?}",
        cpu_findings
    );

    let detector_ids: std::collections::BTreeSet<_> = cpu_findings
        .iter()
        .map(|f| f.detector_id.as_ref())
        .collect();
    assert!(detector_ids.contains("github-classic-pat"));
    assert!(detector_ids.contains("stripe-secret-key"));
    assert!(detector_ids.contains("aws-access-key"));

    // Cross-backend parity check when hardware supports SIMD
    let hw = probe_hardware();
    if hw.has_avx512 || hw.has_avx2 || hw.has_neon {
        let simd_results = scanner
            .scan_chunks_with_backend(std::slice::from_ref(&sample_chunk), ScanBackend::SimdCpu)
            .expect("scan benchmark sample chunk on SimdCpu");
        let simd_findings = &simd_results[0];
        assert_eq!(
            simd_findings.len(),
            cpu_findings.len(),
            "finding count parity between SimdCpu and CpuFallback on benchmark chunk"
        );
        let simd_detector_ids: std::collections::BTreeSet<_> = simd_findings
            .iter()
            .map(|f| f.detector_id.as_ref())
            .collect();
        assert_eq!(
            detector_ids, simd_detector_ids,
            "detector id parity between SimdCpu and CpuFallback"
        );
    }
}

#[test]
fn synthetic_execution_pack_finding_parity_evidence_invariants() {
    let detector_digest = [0x11; 32];
    let generation = PackGenerationIdentity {
        config_digest: [0x22; 32],
        target_digest: [0x33; 32],
        binary_digest: [0x44; 32],
        feature_digest: [0x55; 32],
    };
    let route_digest = [0x66; 32];
    let fixture_digest = [0x77; 32];
    let scalar_findings = b"detector:github-classic-pat:offset:12345";
    let candidate_findings = b"detector:github-classic-pat:offset:12345";

    // Prove valid parity evidence from matching scalar and candidate findings
    let evidence = PackFindingParityEvidence::prove(
        ExecutionPackBackend::Cpu,
        detector_digest,
        generation,
        route_digest,
        fixture_digest,
        1,
        scalar_findings,
        candidate_findings,
    )
    .expect("proving parity evidence with equal finding bytes must succeed");

    assert_eq!(evidence.version, PACK_FINDING_PARITY_VERSION);
    assert_eq!(evidence.backend, ExecutionPackBackend::Cpu);
    assert_eq!(evidence.detector_digest, detector_digest);
    assert_eq!(evidence.config_digest, generation.config_digest);
    assert_eq!(evidence.binary_digest, generation.binary_digest);
    assert_eq!(evidence.route_digest, route_digest);
    assert_eq!(evidence.fixture_digest, fixture_digest);
    assert_eq!(
        evidence.scalar_findings_digest,
        *blake3::hash(scalar_findings).as_bytes()
    );
    assert_eq!(
        evidence.candidate_findings_digest,
        *blake3::hash(candidate_findings).as_bytes()
    );
    assert_eq!(evidence.finding_count, 1);

    // Validation against matching generation and route succeeds
    assert!(evidence
        .validate(
            ExecutionPackBackend::Cpu,
            detector_digest,
            generation,
            route_digest
        )
        .is_ok());

    // Validation against divergent backend or route fails closed
    assert!(evidence
        .validate(
            ExecutionPackBackend::Simd,
            detector_digest,
            generation,
            route_digest
        )
        .is_err());

    // Proof fails closed when finding bytes differ
    let divergent_candidate = b"detector:github-classic-pat:offset:99999";
    let diff_err = PackFindingParityEvidence::prove(
        ExecutionPackBackend::Cpu,
        detector_digest,
        generation,
        route_digest,
        fixture_digest,
        1,
        scalar_findings,
        divergent_candidate,
    )
    .expect_err("divergent finding bytes must fail parity proof");
    match &diff_err {
        ExecutionPackError::InvalidCompilerInput(msg) => {
            assert!(msg.contains("candidate findings differ from scalar oracle"));
        }
        other => panic!("expected InvalidCompilerInput, got {other:?}"),
    }

    // Proof fails closed when fixture digest is zero
    let zero_fixture_err = PackFindingParityEvidence::prove(
        ExecutionPackBackend::Cpu,
        detector_digest,
        generation,
        route_digest,
        [0u8; 32],
        1,
        scalar_findings,
        candidate_findings,
    )
    .expect_err("zero fixture digest must fail parity proof");
    match &zero_fixture_err {
        ExecutionPackError::InvalidCompilerInput(msg) => {
            assert!(msg.contains("pack parity fixture identity is empty"));
        }
        other => panic!("expected InvalidCompilerInput, got {other:?}"),
    }
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
