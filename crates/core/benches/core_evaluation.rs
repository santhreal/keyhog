use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use keyhog_core::guard_state::{GuardPolicyIdentity, GuardRootState, GuardTransition};
use keyhog_core::suppression::RuleSuppressor;
use keyhog_core::{
    compute_detector_corpus_digest, correlate_findings, dedup_matches, load_detectors, sha256_hash,
    validate_detector, DedupScope, DetectorSpec, MatchLocation, MerkleIndex, RawMatch,
    SensitiveString, Severity, VerificationResult, VerifiedFinding,
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn sample_finding(
    detector_id: &str,
    service: &str,
    severity: Severity,
    path: &str,
    hash: &str,
) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from(detector_id),
        service: Arc::from(service),
        severity,
        credential_redacted: Cow::Owned(format!("{}...", &hash[..4.min(hash.len())])),
        credential_hash: sha256_hash(hash),
        companions_redacted: HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from(path)),
            line: Some(10),
            offset: 100,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Live,
        metadata: HashMap::new(),
        additional_locations: Vec::new(),
        entropy: None,
        evidence_score: Some(1.0),
        evidence: keyhog_core::EvidenceVerdict::review_unattributed(),
    }
}

fn sample_raw_match(detector_id: &str, file: &str, line: usize, secret: &str) -> RawMatch {
    RawMatch {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from(detector_id),
        service: Arc::from("aws"),
        severity: Severity::High,
        credential: SensitiveString::from(secret),
        credential_hash: sha256_hash(secret),
        companions: HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from(file)),
            line: Some(line),
            offset: line * 80,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: Some(0.9),
        evidence: keyhog_core::EvidenceVerdict::review_unattributed(),
    }
}

/// WHY: Measures detector spec validation and corpus digest computation latency.
fn bench_detector_validation_and_corpus(c: &mut Criterion) {
    let mut group = c.benchmark_group("core_detector_validation_and_corpus");

    let detectors_path = if Path::new("detectors").exists() {
        PathBuf::from("detectors")
    } else if Path::new("../../detectors").exists() {
        PathBuf::from("../../detectors")
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("detectors")
    };
    let all_detectors = load_detectors(&detectors_path).expect("load detectors");
    let sample_spec = all_detectors.first().cloned().expect("sample spec");

    group.bench_function("validate_single_detector", |b| {
        b.iter(|| {
            let issues = validate_detector(black_box(&sample_spec));
            let _ = black_box(issues);
        });
    });

    for &count in &[10, 50, 100] {
        let subset: Vec<DetectorSpec> = all_detectors.iter().take(count).cloned().collect();
        group.bench_with_input(
            BenchmarkId::new("compute_detector_corpus_digest", count),
            &subset,
            |b, specs| {
                b.iter(|| {
                    let digest = compute_detector_corpus_digest(black_box(specs));
                    let _ = black_box(digest);
                });
            },
        );
    }

    group.finish();
}

/// WHY: Measures declarative `.keyhogignore.toml` rule-based suppression evaluation
/// over realistic batches of findings.
fn bench_suppression_rule_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("core_suppression_rule_evaluation");

    let rule_toml = r#"
[[suppress]]
detector = "aws-access-key"
path_contains = "/tests/"

[[suppress]]
service = "stripe"
severity_lte = "low"
path_ends_with = "_fixture.json"

[[suppress]]
credential_hash = "hash_to_suppress_12345"

[[suppress]]
path_starts_with = "vendor/"

[[suppress]]
detector = "github-token"
severity_lte = "medium"
"#;

    let suppressor = RuleSuppressor::parse(rule_toml).expect("parse rule suppressor");

    let findings = vec![
        sample_finding(
            "aws-access-key",
            "aws",
            Severity::High,
            "src/tests/auth_test.rs",
            "AKIAIOSFODNN7EXAMPLE",
        ),
        sample_finding(
            "stripe",
            "stripe",
            Severity::Low,
            "fixtures/sample_fixture.json",
            "sk_test_12345",
        ),
        sample_finding(
            "generic-api-key",
            "custom",
            Severity::Critical,
            "src/main.rs",
            "hash_to_suppress_12345",
        ),
        sample_finding(
            "slack-webhook",
            "slack",
            Severity::High,
            "src/service.rs",
            "unsuppressed_hash_99999",
        ),
        sample_finding(
            "github-token",
            "github",
            Severity::High,
            "deploy/config.yml",
            "ghp_unsuppressed_token_123",
        ),
    ];

    group.bench_function("parse_rule_suppressor_toml", |b| {
        b.iter(|| {
            let supp = RuleSuppressor::parse(black_box(rule_toml)).expect("parse");
            let _ = black_box(supp);
        });
    });

    group.bench_function("evaluate_finding_batch_suppression", |b| {
        b.iter(|| {
            let mut matches_count = 0;
            for f in &findings {
                if suppressor.matches(black_box(f)) {
                    matches_count += 1;
                }
            }
            black_box(matches_count);
        });
    });

    group.finish();
}

/// WHY: Measures incremental Merkle index chunk recording, stat checking,
/// and metadata persistence throughput.
fn bench_merkle_index_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("core_merkle_index_operations");

    let index = MerkleIndex::new();
    let sample_path = PathBuf::from("/workspace/src/lib.rs");
    let content_hash = blake3::hash(b"pub fn run_scan() { println!(\"clean\"); }");

    group.bench_function("record_chunk_path_at_offset", |b| {
        b.iter(|| {
            let unchanged = index.record_chunk_path_at_offset_and_check_unchanged(
                black_box(&sample_path),
                black_box(0),
                black_box(1_700_000_000_000_000_000),
                black_box(1024),
                black_box(content_hash.as_bytes()),
            );
            let _ = black_box(unchanged);
        });
    });

    group.bench_function("metadata_unchanged_check", |b| {
        b.iter(|| {
            let unchanged = index.metadata_unchanged(
                black_box(&sample_path),
                black_box(1_700_000_000_000_000_000),
                black_box(1024),
            );
            let _ = black_box(unchanged);
        });
    });

    group.finish();
}

/// WHY: Measures deduplication and correlation algorithms across large candidate sets.
fn bench_finding_dedup_and_correlation(c: &mut Criterion) {
    let mut group = c.benchmark_group("core_dedup_and_correlation");

    for &size in &[100, 500, 2000] {
        let mut matches = Vec::with_capacity(size);
        for i in 0..size {
            let file = format!("src/module_{}.rs", i % 10);
            let secret = format!("secret_token_val_{}", i % (size / 2));
            matches.push(sample_raw_match(
                "aws-access-key",
                &file,
                (i % 50) + 1,
                &secret,
            ));
        }

        group.bench_with_input(
            BenchmarkId::new("dedup_matches_file_scope", size),
            &matches,
            |b, ms| {
                b.iter(|| {
                    let deduped = dedup_matches(black_box(ms.clone()), &DedupScope::File);
                    let _ = black_box(deduped);
                });
            },
        );

        let findings: Vec<VerifiedFinding> = matches
            .iter()
            .take(size.min(200))
            .map(|m| {
                sample_finding(
                    &m.detector_id,
                    &m.service,
                    m.severity,
                    m.location.file_path.as_deref().unwrap_or(""),
                    "secret_hash_val",
                )
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("correlate_findings", findings.len()),
            &findings,
            |b, fs| {
                b.iter(|| {
                    let correlated = correlate_findings(black_box(fs));
                    let _ = black_box(correlated);
                });
            },
        );
    }

    group.finish();
}

/// WHY: Measures guard state machine transition throughput and policy identity hashing.
fn bench_guard_state_and_policy(c: &mut Criterion) {
    let mut group = c.benchmark_group("core_guard_state_and_policy");

    let policy = GuardPolicyIdentity {
        build_identity: "git:0.5.80".to_string(),
        detector_digest: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
            .to_string(),
        suppression_digest: String::new(),
        keyhogignore_digest: String::new(),
        config_digest: "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5"
            .to_string(),
        decode_policy_version: 1,
        source_policy_digest: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
        guard_schema_version: 1,
        report_semantics_version: 1,
    };

    group.bench_function("guard_policy_identity_digest", |b| {
        b.iter(|| {
            let digest = policy.short_digest().expect("short digest");
            let _ = black_box(digest);
        });
    });

    group.bench_function("guard_root_state_transition_sequence", |b| {
        b.iter(|| {
            let s0 = GuardRootState::Stopped;
            let s1 = s0
                .transition(&GuardTransition::ReconciliationStarted)
                .expect("start");
            let s2 = s1
                .transition(&GuardTransition::ReconciliationClean)
                .expect("clean");
            let s3 = s2
                .transition(&GuardTransition::EventAccepted)
                .expect("event");
            let s4 = s3.transition(&GuardTransition::EventsClean).expect("clean");
            let _ = black_box(s4);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_detector_validation_and_corpus,
    bench_suppression_rule_evaluation,
    bench_merkle_index_operations,
    bench_finding_dedup_and_correlation,
    bench_guard_state_and_policy,
);
criterion_main!(benches);
