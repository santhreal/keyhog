//! WHY: Closes the defect class where product-level operational latency and throughput
//! benchmarks across CLI startup, pre-commit hook run execution, perpetual guard status
//! roundtrips, and core verifier evaluation were missing or decoupled from shipped
//! code paths, allowing performance regressions in interactive developer workflows
//! to slip into releases undetected (Row 147).
//!
//! What this does NOT catch: physical hardware variance or thermal throttling across fleet nodes.

use clap::Parser;
use keyhog::args::{Cli, Command, ScanArgs};
use keyhog::testing::hook::{find_hooks_dir_for_repo, install_at_repo, CANONICAL_SCAN_ARGS};
use keyhog::testing::{CliTestApi, API};
use keyhog_core::guard_state::{
    FilesystemAuthority, FilesystemIdentity, GuardPolicyIdentity, GuardRootMode, GuardRootState,
    GuardTransition,
};
use keyhog_core::json_selector;
use keyhog_core::suppression::RuleSuppressor;
use keyhog_core::{
    compute_detector_corpus_digest, correlate_findings, dedup_matches, load_detectors, sha256_hash,
    validate_detector, DedupScope, MatchLocation, MerkleIndex, RawMatch, SensitiveString, Severity,
    VerificationResult, VerifiedFinding,
};
use keyhog_sources::StagedManifest;
use keyhog_verifier::ssrf::{is_private_ip_addr, is_private_url};
use keyhog_verifier::testing::{
    aws_uri_encode, canonical_query_string, TestApi, TestVerificationCache, VerifierTestApi,
    VerifierTestCache,
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command as SysCommand;
use std::sync::Arc;
use tempfile::{tempdir, TempDir};

fn init_git_repo(dir: &Path) {
    let out = SysCommand::new("git")
        .args(["init", "-q", "-b", "main"])
        .current_dir(dir)
        .output()
        .expect("git init");
    assert!(out.status.success(), "git init must succeed");
    let _ = SysCommand::new("git")
        .args(["config", "user.email", "test@test.local"])
        .current_dir(dir)
        .output();
    let _ = SysCommand::new("git")
        .args(["config", "user.name", "Test Runner"])
        .current_dir(dir)
        .output();
}

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
            author: None,
            commit: None,
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

#[test]
fn row_147_benchmark_manifest_targets_and_files_exist() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .parent()
        .expect("repo root")
        .to_path_buf();

    let expected_benches = [
        (
            "crates/cli/Cargo.toml",
            "crates/cli/benches/cli_startup.rs",
            "cli_startup",
        ),
        (
            "crates/cli/Cargo.toml",
            "crates/cli/benches/hook_execution.rs",
            "hook_execution",
        ),
        (
            "crates/cli/Cargo.toml",
            "crates/cli/benches/guard_status.rs",
            "guard_status",
        ),
        (
            "crates/core/Cargo.toml",
            "crates/core/benches/core_evaluation.rs",
            "core_evaluation",
        ),
        (
            "crates/verifier/Cargo.toml",
            "crates/verifier/benches/verifier_evaluation.rs",
            "verifier_evaluation",
        ),
    ];

    for (manifest_rel, bench_file_rel, bench_name) in expected_benches {
        let manifest_path = root.join(manifest_rel);
        let bench_file_path = root.join(bench_file_rel);

        assert!(
            manifest_path.exists(),
            "manifest {} must exist",
            manifest_path.display()
        );
        assert!(
            bench_file_path.exists(),
            "benchmark file {} must exist",
            bench_file_path.display()
        );

        let manifest_content =
            std::fs::read_to_string(&manifest_path).expect("read manifest content");
        assert!(
            manifest_content.contains(&format!("name = \"{bench_name}\"")),
            "manifest {} must declare [[bench]] with name = \"{}\"",
            manifest_path.display(),
            bench_name
        );
        assert!(
            manifest_content.contains("criterion = { workspace = true }"),
            "manifest {} must include criterion in [dev-dependencies]",
            manifest_path.display()
        );
    }
}

#[test]
fn row_147_cli_startup_arg_parsing_and_config_resolution() {
    let command_vectors: &[(&str, &[&str])] = &[
        ("version", &["keyhog", "--version"]),
        ("help", &["keyhog", "--help"]),
        ("scan_dot", &["keyhog", "scan", "."]),
        (
            "scan_hook_canonical",
            &[
                "keyhog",
                "scan",
                "--fast",
                "--git-staged",
                "--backend",
                "cpu",
            ],
        ),
        (
            "scan_flags_matrix",
            &[
                "keyhog",
                "scan",
                ".",
                "--format",
                "json",
                "--severity",
                "high",
                "--threads",
                "4",
                "--no-config",
            ],
        ),
        ("guard_status", &["keyhog", "guard", "status", "."]),
        ("guard_list", &["keyhog", "guard", "list"]),
        ("hook_install", &["keyhog", "hook", "install"]),
        ("daemon_status", &["keyhog", "daemon", "status"]),
        ("doctor", &["keyhog", "doctor"]),
        ("explain_detector", &["keyhog", "explain", "aws-access-key"]),
    ];
    for (name, argv) in command_vectors {
        let parsed = Cli::try_parse_from(*argv);
        let is_valid = match &parsed {
            Ok(_) => true,
            Err(err) => matches!(
                err.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ),
        };
        assert!(
            is_valid,
            "CLI argument vector '{name}' must parse successfully"
        );
    }

    // Config resolution
    let dir = tempdir().expect("tempdir");
    let config_path = dir.path().join(".keyhog.toml");
    let sample_config = r#"
[scan]
format = "json"
threads = 4
min_confidence = 0.75
min_secret_len = 20

[tuning]
fallback_hs = true
hs_prefilter_max_len = 64

[guard]
hot_index_memory = "64MiB"
coalesce_window = "100ms"
"#;
    std::fs::write(&config_path, sample_config).expect("write sample config");

    let parse_res = API.parse_config_file_from_str(sample_config);
    assert!(
        parse_res.is_ok(),
        "config parsing must succeed: {parse_res:?}"
    );

    let found = API.find_config_file(Some(dir.path()));
    assert_eq!(
        found,
        Some(config_path),
        "find_config_file must resolve the .keyhog.toml path"
    );

    let mut args = ScanArgs::try_parse_from(["scan"]).expect("parse scan args");
    args.path = Some(dir.path().to_path_buf());
    API.apply_config_file_quiet(&mut args);
    assert_eq!(args.threads, Some(4));
    assert_eq!(args.min_confidence, Some(0.75));
    assert_eq!(args.min_secret_len, Some(20));

    // Banner formatting
    let banner_color = API.write_banner(true, 150).expect("colored banner");
    let banner_plain = API.write_banner(false, 150).expect("plain banner");
    assert!(!banner_color.is_empty());
    assert!(!banner_plain.is_empty());
}

#[test]
fn row_147_hook_execution_lifecycle_and_staged_scan_flow() {
    let dir = TempDir::new().expect("tempdir");
    let repo_path = dir.path().to_path_buf();
    init_git_repo(&repo_path);

    // 1. Verify canonical scan args parsing
    let raw_tokens: Vec<&str> = std::iter::once("keyhog")
        .chain(CANONICAL_SCAN_ARGS.split_whitespace())
        .collect();
    let parsed = Cli::try_parse_from(&raw_tokens).expect("parse canonical scan args");
    if let Some(Command::Scan(scan_args)) = parsed.command {
        assert!(
            scan_args.fast,
            "canonical hook scan args must have fast=true"
        );
        assert!(
            scan_args.git_staged,
            "canonical hook scan args must have git_staged=true"
        );
        assert_eq!(
            scan_args.backend.as_deref(),
            Some("cpu"),
            "canonical hook scan args must specify cpu backend"
        );
    } else {
        panic!("expected Scan command");
    }

    // 2. Find hooks dir and install hook
    let hooks_dir = find_hooks_dir_for_repo(&repo_path).expect("find hooks dir");
    assert!(hooks_dir.is_absolute());
    assert_eq!(hooks_dir, repo_path.join(".git").join("hooks"));

    let (hook_path, _status) = install_at_repo(&repo_path, false).expect("install hook");
    assert_eq!(
        hook_path,
        repo_path.join(".git").join("hooks").join("pre-commit")
    );
    assert!(hook_path.exists());

    // Idempotent re-run
    let (_, second_status) = install_at_repo(&repo_path, false).expect("re-install hook");
    assert_eq!(
        second_status,
        keyhog::testing::hook::HookInstallStatus::AlreadyInstalled
    );

    // 3. Stage synthetic files and acquire manifest
    let test_file = repo_path.join("src").join("main.rs");
    std::fs::create_dir_all(test_file.parent().unwrap()).expect("create dir");
    std::fs::write(&test_file, "pub fn run() -> u32 { 100 }\n").expect("write file");

    let add_out = SysCommand::new("git")
        .args(["add", "."])
        .current_dir(&repo_path)
        .output()
        .expect("git add");
    assert!(add_out.status.success());

    let manifest = StagedManifest::acquire(&repo_path).expect("acquire staged manifest");
    assert_eq!(manifest.entries.len(), 1);

    // 4. Build staged sources
    let args = ScanArgs::try_parse_from([
        "scan",
        "--path",
        repo_path.to_str().unwrap(),
        "--git-staged",
        "--fast",
        "--backend",
        "cpu",
    ])
    .expect("parse scan args");

    let sources = API
        .build_sources(&args, Vec::new(), None)
        .expect("build sources");
    assert!(!sources.is_empty(), "staged sources must be generated");
}

#[test]
fn row_147_guard_status_protocol_and_state_transitions() {
    #[cfg(unix)]
    {
        use keyhog::testing::daemon::fs_probe::probe_filesystem_authority;
        use keyhog::testing::daemon::guard_runtime::GuardRuntime;
        use keyhog::testing::daemon::protocol::{
            deserialize_status_response, response_kind_classification,
            sample_guard_status_result_frame, serialize_status_response,
        };

        let status_resp_frame = sample_guard_status_result_frame("/srv/repo");
        assert_eq!(
            response_kind_classification(&status_resp_frame),
            "GuardStatusResult"
        );
        let encoded_resp = serialize_status_response(&status_resp_frame);
        let (decoded_root, decoded_state) =
            deserialize_status_response(&encoded_resp).expect("deserialize resp");
        assert_eq!(decoded_root, "/srv/repo");
        assert_eq!(decoded_state, "current");

        // GuardRuntime verification
        let rt = GuardRuntime::new();
        let root_bytes = b"/srv/repo".to_vec();
        rt.add_root(
            root_bytes.clone(),
            FilesystemIdentity {
                device: 1,
                inode: 42,
            },
            FilesystemAuthority::authoritative("ext4"),
            GuardRootMode::Repo,
        )
        .expect("add root");

        let record = rt.root_record(&root_bytes).expect("record");
        assert_eq!(record.state, GuardRootState::Stopped);

        rt.transition_root(&root_bytes, &GuardTransition::ReconciliationStarted)
            .expect("transition start");
        assert_eq!(rt.root_state(&root_bytes), Some(GuardRootState::Indexing));

        rt.transition_root(&root_bytes, &GuardTransition::ReconciliationClean)
            .expect("transition clean");
        assert_eq!(rt.root_state(&root_bytes), Some(GuardRootState::Current));

        let dir = tempdir().expect("tempdir");
        let auth = probe_filesystem_authority(dir.path());
        assert!(!auth.filesystem_type.is_empty());
    }

    // Policy identity
    let policy = GuardPolicyIdentity {
        build_identity: "git:0.5.80".to_string(),
        detector_digest: "d1".to_string(),
        suppression_digest: String::new(),
        keyhogignore_digest: String::new(),
        config_digest: "c1".to_string(),
        decode_policy_version: 1,
        source_policy_digest: "s1".to_string(),
        guard_schema_version: 1,
        report_semantics_version: 1,
    };
    let digest_1 = policy.short_digest().expect("digest 1");
    assert!(!digest_1.is_empty());

    let policy_mut = GuardPolicyIdentity {
        config_digest: "c2_different".to_string(),
        ..policy
    };
    let digest_2 = policy_mut.short_digest().expect("digest 2");
    assert_ne!(
        digest_1, digest_2,
        "changing policy parameters must yield different digest"
    );
}

#[test]
fn row_147_core_evaluation_suppression_and_merkle_operations() {
    // 1. Detector validation & corpus digest
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
    for spec in all_detectors.iter().take(20) {
        let issues = validate_detector(spec);
        assert!(
            issues.is_empty(),
            "detector {} must validate cleanly",
            spec.id
        );
    }
    let digest = compute_detector_corpus_digest(&all_detectors).expect("compute corpus digest");
    assert_ne!(digest, [0u8; 32], "corpus digest must not be zero");

    // 2. Rule suppressor evaluation
    let suppressed_secret = "secret_suppressed_token_12345";
    let suppressed_hash_hex = hex::encode(sha256_hash(suppressed_secret));
    let rule_toml = format!(
        r#"
[[suppress]]
detector = "aws-access-key"
path_contains = "/tests/"

[[suppress]]
credential_hash = "{suppressed_hash_hex}"
"#
    );
    let suppressor = RuleSuppressor::parse(&rule_toml).expect("parse rules");

    let f_suppressed_1 = sample_finding(
        "aws-access-key",
        "aws",
        Severity::High,
        "src/tests/test_auth.rs",
        "AKIAIOSFODNN7EXAMPLE",
    );
    let f_suppressed_2 = sample_finding(
        "generic-token",
        "custom",
        Severity::Critical,
        "src/lib.rs",
        suppressed_secret,
    );
    let f_active = sample_finding(
        "aws-access-key",
        "aws",
        Severity::High,
        "src/production/auth.rs",
        "AKIAUNSUPPRESSEDEXAMPLE",
    );

    assert!(suppressor.matches(&f_suppressed_1));
    assert!(suppressor.matches(&f_suppressed_2));
    assert!(!suppressor.matches(&f_active));

    // 3. Merkle index operations
    let index = MerkleIndex::new();
    let sample_path = PathBuf::from("/workspace/src/main.rs");
    let content_hash = blake3::hash(b"fn main() {}");

    let first_check = index.record_chunk_path_at_offset_and_check_unchanged(
        &sample_path,
        0,
        1_700_000_000,
        1_700_000_100,
        1024,
        content_hash.as_bytes(),
    );
    assert!(!first_check, "first encounter must not be unchanged");

    let second_check = index.record_chunk_path_at_offset_and_check_unchanged(
        &sample_path,
        0,
        1_700_000_000,
        1_700_000_100,
        1024,
        content_hash.as_bytes(),
    );
    assert!(
        second_check,
        "second encounter with identical metadata must be unchanged"
    );

    assert!(index.metadata_unchanged(&sample_path, 1_700_000_000, 1_700_000_100, 1024));
    assert!(!index.metadata_unchanged(&sample_path, 1_700_000_000, 1_700_000_101, 1024));
    assert!(!index.metadata_unchanged(&sample_path, 1_700_000_001, 1_700_000_100, 1024));

    // 4. Dedup matches and correlate
    let raw_1 = RawMatch {
        detector_id: Arc::from("aws-access-key"),
        detector_name: Arc::from("aws-access-key"),
        service: Arc::from("aws"),
        severity: Severity::High,
        credential: SensitiveString::from("AKIA1"),
        credential_hash: sha256_hash("AKIA1"),
        companions: HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("src/file.rs")),
            line: Some(5),
            offset: 50,
            author: None,
            commit: None,
            date: None,
        },
        entropy: None,
        confidence: Some(0.9),
        evidence: keyhog_core::EvidenceVerdict::review_unattributed(),
    };
    let raw_2 = raw_1.clone();
    let deduped = dedup_matches(vec![raw_1, raw_2], &DedupScope::File);
    assert_eq!(deduped.len(), 1, "exact match in same file must dedup to 1");

    let f_reuse_1 = sample_finding(
        "aws-access-key",
        "aws",
        Severity::High,
        "src/a.rs",
        "AKIAIOSFODNN7EXAMPLE",
    );
    let f_reuse_2 = sample_finding(
        "aws-access-key",
        "aws",
        Severity::High,
        "src/b.rs",
        "AKIAIOSFODNN7EXAMPLE",
    );
    let correlated = correlate_findings(&[f_reuse_1, f_reuse_2]);
    assert_eq!(
        correlated.len(),
        1,
        "identical credentials across paths must form 1 reuse correlation"
    );
}

#[test]
fn row_147_verifier_evaluation_interpolation_ssrf_and_cache() {
    // 1. Template interpolation
    let mut companions = HashMap::new();
    companions.insert("tenant".to_string(), "corp".to_string());
    companions.insert("user_id".to_string(), "usr_123".to_string());
    let interpolated_url = TestApi.interpolate_url(
        "https://api.{{companion.tenant}}.example.com/users/{{companion.user_id}}/keys/{{match}}",
        "token_xyz_456",
        &companions,
    );
    assert_eq!(
        interpolated_url,
        "https://api.corp.example.com/users/usr%5F123/keys/token%5Fxyz%5F456"
    );

    let interpolated_header =
        TestApi.interpolate_http_value("Bearer {{match}}", "token_xyz_456", &companions);
    assert_eq!(interpolated_header, "Bearer token_xyz_456");

    // 2. Response selector
    json_selector::validate("$.data.account.id").expect("validate selector");
    let json_data: serde_json::Value = serde_json::json!({
        "data": {
            "account": {
                "id": "acc_789"
            }
        }
    });
    let selected = json_selector::select(&json_data, "$.data.account.id")
        .expect("select")
        .cloned();
    assert_eq!(
        selected,
        Some(serde_json::Value::String("acc_789".to_string()))
    );

    // 3. Verification Cache
    let cache = TestVerificationCache::new(std::time::Duration::from_secs(60));
    assert!(cache.is_empty());
    cache.put(
        "AKIAIOSFODNN7EXAMPLE",
        "aws-access-key",
        VerificationResult::Live,
        HashMap::new(),
    );
    assert_eq!(cache.len(), 1);
    let hit = cache.get("AKIAIOSFODNN7EXAMPLE", "aws-access-key");
    assert!(hit.is_some());
    assert_eq!(hit.unwrap().0, VerificationResult::Live);

    let miss = cache.get("NONEXISTENT", "aws-access-key");
    assert!(miss.is_none());

    // 4. SSRF screening and domain policy
    assert!(is_private_url("http://127.0.0.1:8080/admin"));
    assert!(is_private_url("http://169.254.169.254/metadata"));
    assert!(is_private_url("http://10.0.0.1/status"));
    assert!(is_private_url("http://[::1]/debug"));
    assert!(!is_private_url("https://api.github.com/user"));

    let private_ip: IpAddr = "192.168.1.1".parse().unwrap();
    let public_ip: IpAddr = "8.8.8.8".parse().unwrap();
    assert!(is_private_ip_addr(&private_ip));
    assert!(!is_private_ip_addr(&public_ip));

    let allowlist = vec!["github.com".to_string(), "stripe.com".to_string()];
    assert!(TestApi.host_is_allowed("api.github.com", &allowlist));
    assert!(TestApi.host_is_allowed("api.stripe.com", &allowlist));
    assert!(TestApi.host_is_allowed("hooks.stripe.com", &allowlist));
    assert!(!TestApi.host_is_allowed("evil.example.com", &allowlist));

    // 5. SigV4 canonicalization
    assert_eq!(aws_uri_encode("foo/bar baz"), "foo%2Fbar%20baz");
    let params = vec![
        ("b".to_string(), "2".to_string()),
        ("a".to_string(), "1".to_string()),
    ];
    assert_eq!(canonical_query_string(&params), "a=1&b=2");
}
