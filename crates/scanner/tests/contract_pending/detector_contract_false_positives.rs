//! FALSE POSITIVE CONTRACT: Negative tests for common non-secret patterns
//! that should NOT trigger detector matches (or should only produce
//! CLIENT-SAFE-only findings).
//!
//! Coverage areas:
//! - SHA256 hex digests (commonly seen in diffs, changelogs, security advisories)
//! - Semantic versioning (valid semver patterns)
//! - UUID/GUID patterns (often used as doc examples, mock IDs)
//! - Base64-encoded non-secrets (config examples, encoded documentation)
//! - Example URLs and documentation placeholders (AKIAEXAMPLE, db://localhost)
//! - Git commit hashes, object IDs
//! - Checksums, fingerprints, hashes in config
//!
//! Each test asserts:
//! - CPU (SimdCpu) backend produces zero FP findings (or only CLIENT-SAFE)
//! - GPU backend (if available) matches CPU parity
//! - No silent divergence between backends

#[path = "support/mod.rs"]
mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use support::paths::detector_dir;

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

fn build_scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors loadable");
    CompiledScanner::compile(detectors).expect("scanner compile")
}

fn scan_cpu(scanner: &CompiledScanner, text: &str, path: &str) -> Vec<keyhog_core::RawMatch> {
    let chunk = make_chunk(text, path);
    scanner
        .scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu)
        .into_iter()
        .flatten()
        .collect()
}

fn scan_gpu(scanner: &CompiledScanner, text: &str, path: &str) -> Vec<keyhog_core::RawMatch> {
    let chunk = make_chunk(text, path);
    scanner
        .scan_chunks_with_backend(&[chunk], ScanBackend::Gpu)
        .into_iter()
        .flatten()
        .collect()
}

/// Extract finding credentials into a set for easy comparison
fn credential_set(matches: &[keyhog_core::RawMatch]) -> std::collections::BTreeSet<String> {
    matches
        .iter()
        .map(|m| m.credential.as_ref().to_string())
        .collect()
}

/// Count findings attributed to a specific detector
fn detector_count(matches: &[keyhog_core::RawMatch], detector_id: &str) -> usize {
    matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == detector_id)
        .count()
}

// ============================================================================
// SHA256 HEX DIGESTS (40-64 char hex strings, common in diffs & docs)
// ============================================================================

#[test]
fn sha256_in_git_commit_log_not_secret() {
    let scanner = build_scanner();
    let text = "commit 9f3c1a7e2b8d4056c1e9a7b3f0d6428e5a1c9b7e3f2d8064a5c1e9b7f3d20486\n\
                Author: dev <dev@example.com>\n\
                Date: Mon Jun 9 12:00:00 2026 +0000\n\
                Fix: update dependencies";
    let matches = scan_cpu(&scanner, text, "CHANGELOG");
    assert_eq!(
        matches.len(),
        0,
        "SHA256 commit hash must not trigger secret detection"
    );
}

#[test]
fn sha256_in_security_advisory_not_secret() {
    let scanner = build_scanner();
    let text = "## CVE-2026-1234\n\n\
                **Vulnerability Hash:** 9f3c1a7e2b8d4056c1e9a7b3f0d6428e5a1c9b7e\n\
                **Fixed in:** v2.0.0\n\
                **Severity:** High\n\
                Patch available at https://example.com/patch";
    let matches = scan_cpu(&scanner, text, "SECURITY.md");
    assert_eq!(
        matches.len(),
        0,
        "SHA256 hash in advisory header must not be detected"
    );
}

#[test]
fn sha256_in_checksums_file_not_secret() {
    let scanner = build_scanner();
    let text = "9f3c1a7e2b8d4056c1e9a7b3f0d6428e5a1c9b7e3f2d8064a5c1e9b7f3d20486  release-v1.0.0.tar.gz\n\
                2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a  release-v1.0.1.tar.gz";
    let matches = scan_cpu(&scanner, text, "SHA256SUMS");
    assert_eq!(
        matches.len(),
        0,
        "SHA256 checksums must not be detected as secrets"
    );
}

#[test]
fn sha1_in_git_ref_not_secret() {
    let scanner = build_scanner();
    let text = "refs/heads/main: 5a8f3c9e2b1d4e7a9c6f3d2a1e5b8c0f4a2d9e7c\n\
                refs/tags/v1.0: 3f2a9c7e1b4d4e8a9c0f7a2b6d8e1c3f5a9b2e0d";
    let matches = scan_cpu(&scanner, text, ".git/refs");
    assert_eq!(
        matches.len(),
        0,
        "Git object hashes (SHA1/SHA256) must not trigger detection"
    );
}

#[test]
fn md5_hash_in_documentation_not_secret() {
    let scanner = build_scanner();
    let text = "The file checksum (MD5) is: 5a1c3d4b2e9f6a8c1d5e7b3f2a9c4d6e\n\
                Do not rely on this for security.";
    let matches = scan_cpu(&scanner, text, "README.md");
    assert_eq!(matches.len(), 0, "MD5 checksums must not be detected");
}

// ============================================================================
// SEMANTIC VERSIONING (valid semver patterns)
// ============================================================================

#[test]
fn semver_versions_not_secrets() {
    let scanner = build_scanner();
    let text = "version = \"1.2.3\"\n\
                min_version = \"0.1.0\"\n\
                max_version = \"2.5.9-rc.1\"\n\
                prerelease = \"1.0.0-alpha.1+build.123\"";
    let matches = scan_cpu(&scanner, text, "Cargo.toml");
    assert_eq!(
        matches.len(),
        0,
        "Semantic versions must not be detected as secrets"
    );
}

#[test]
fn version_strings_in_comments_not_secrets() {
    let scanner = build_scanner();
    let text = "// Compatible with v1.2.3 and above\n\
                // Breaking change in v2.0.0\n\
                const VERSION: &str = \"3.4.5\";";
    let matches = scan_cpu(&scanner, text, "lib.rs");
    assert_eq!(
        matches.len(),
        0,
        "Version strings in comments must not trigger detection"
    );
}

#[test]
fn npm_package_versions_not_secrets() {
    let scanner = build_scanner();
    let text = "{\n  \"name\": \"my-package\",\n\
                  \"version\": \"1.2.3\",\n\
                  \"dependencies\": {\n\
                    \"react\": \"^18.2.0\",\n\
                    \"lodash\": \"~4.17.21\"\n\
                  }\n\
                }";
    let matches = scan_cpu(&scanner, text, "package.json");
    assert_eq!(
        matches.len(),
        0,
        "npm package versions must not be detected"
    );
}

#[test]
fn docker_image_tags_not_secrets() {
    let scanner = build_scanner();
    let text = "FROM ubuntu:20.04\n\
                RUN apt-get update\n\
                RUN pip install python:3.9.5\n\
                COPY --from=node:16.13.0 /app /app";
    let matches = scan_cpu(&scanner, text, "Dockerfile");
    assert_eq!(
        matches.len(),
        0,
        "Docker image version tags must not be detected"
    );
}

// ============================================================================
// UUID/GUID PATTERNS (valid UUIDs commonly in docs, test fixtures)
// ============================================================================

#[test]
fn uuids_in_documentation_not_secrets() {
    let scanner = build_scanner();
    let text = "User ID: 550e8400-e29b-41d4-a716-446655440000\n\
                Session ID: 6ba7b810-9dad-11d1-80b4-00c04fd430c8\n\
                Request ID: f47ac10b-58cc-4372-a567-0e02b2c3d479";
    let matches = scan_cpu(&scanner, text, "docs/examples.md");
    assert_eq!(
        matches.len(),
        0,
        "UUIDs in documentation must not be detected as secrets"
    );
}

#[test]
fn guid_examples_in_test_code_not_secrets() {
    let scanner = build_scanner();
    let text = "const USER_ID = \"3f2a9c7e-1b4d-4e8a-9c0f-7a2b6d8e1c3f\";\n\
                const SESSION_ID = \"6ba7b811-9dad-11d1-80b4-00c04fd430c8\";\n\
                let instance_id = uuid::Uuid::parse_str(\"550e8400-e29b-41d4-a716-446655440000\").unwrap();";
    let matches = scan_cpu(&scanner, text, "tests.rs");
    assert_eq!(
        matches.len(),
        0,
        "UUID examples in test code must not be detected"
    );
}

#[test]
fn uuid_fixtures_in_contract_tests_not_secrets() {
    let scanner = build_scanner();
    let text = "fn test_uuid_validation() {\n  \
                  let valid_id = \"550e8400-e29b-41d4-a716-446655440000\";\n  \
                  let invalid_id = \"not-a-uuid\";\n  \
                  assert!(is_valid_uuid(valid_id));\n  \
                  assert!(!is_valid_uuid(invalid_id));\n\
                }";
    let matches = scan_cpu(&scanner, text, "uuid_contract.rs");
    assert_eq!(
        matches.len(),
        0,
        "UUID fixtures in unit tests must not be detected"
    );
}

#[test]
fn microsoft_guid_format_not_secrets() {
    let scanner = build_scanner();
    let text = "{3f2a9c7e-1b4d-4e8a-9c0f-7a2b6d8e1c3f}\n\
                {{550e8400-e29b-41d4-a716-446655440000}}\n\
                Device GUID: 6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    let matches = scan_cpu(&scanner, text, "registry.xml");
    assert_eq!(
        matches.len(),
        0,
        "Microsoft GUID formats must not be detected"
    );
}

// ============================================================================
// BASE64 ENCODED NON-SECRETS (documentation, config examples)
// ============================================================================

#[test]
fn base64_encoded_text_not_secret() {
    let scanner = build_scanner();
    let text = "# Base64 examples (not secrets)\n\
                hello_world_b64 = \"aGVsbG8gd29ybGQ=\"  // 'hello world'\n\
                config_example_b64 = \"ZXhhbXBsZV9jb25maWc=\"  // 'example_config'\n\
                data_payload = \"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=\""; // alphabet
    let matches = scan_cpu(&scanner, text, "examples.conf");
    assert_eq!(
        matches.len(),
        0,
        "Base64-encoded plain text must not be detected"
    );
}

#[test]
fn base64_in_data_url_not_secret() {
    let scanner = build_scanner();
    let text = "image_url = \"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA\"\n\
                image_embed = \"data:text/plain;base64,SGVsbG8gV29ybGQ=\"";
    let matches = scan_cpu(&scanner, text, "config.json");
    assert_eq!(matches.len(), 0, "Base64 in data URLs must not be detected");
}

#[test]
fn base64_test_vectors_not_secrets() {
    let scanner = build_scanner();
    let text = "[test_vectors]\n\
                plaintext = \"hello\"\n\
                encoded = \"aGVsbG8=\"\n\
                plaintext2 = \"The quick brown fox\"\n\
                encoded2 = \"VGhlIHF1aWNrIGJyb3duIGZveA==\"";
    let matches = scan_cpu(&scanner, text, "test_vectors.toml");
    assert_eq!(matches.len(), 0, "Base64 test vectors must not be detected");
}

#[test]
fn base64url_encoding_not_secret() {
    let scanner = build_scanner();
    let text = "jwt_payload = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\"\n\
                // ^ Standard JWT header (not a real secret)\n\
                padding_variant = \"SGVsbG8gd29ybGQh\"";
    let matches = scan_cpu(&scanner, text, "jwt_example.py");
    assert_eq!(
        matches.len(),
        0,
        "Base64url JWT examples must not be detected"
    );
}

// ============================================================================
// EXAMPLE PLACEHOLDERS AND DOCUMENTATION URLS
// ============================================================================

#[test]
fn aws_example_akia_placeholder_not_secret() {
    let scanner = build_scanner();
    let text = "# Example IAM user credentials (NEVER use in production)\n\
                # AWS Access Key ID: AKIAIOSFODNN7EXAMPLE\n\
                # AWS Secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n\
                # Use only in documentation";
    let matches = scan_cpu(&scanner, text, "README.md");
    assert_eq!(
        matches.len(),
        0,
        "AWS EXAMPLE placeholder credentials must not trigger detection"
    );
}

#[test]
fn stripe_example_placeholder_not_secret() {
    let scanner = build_scanner();
    let text = "// Stripe test keys (from official documentation)\n\
                const STRIPE_PK = 'pk_test_4eC39HqLyjWDarjtT1zdp7dc';\n\
                const STRIPE_SK = 'sk_test_4eC39HqLyjWDarjtT1zdp7dc';";
    let matches = scan_cpu(&scanner, text, "stripe_config.js");
    assert_eq!(
        matches.len(),
        0,
        "Stripe test key placeholders from docs must not be detected"
    );
}

#[test]
fn github_token_example_placeholder_not_secret() {
    let scanner = build_scanner();
    let text = "# GitHub Personal Access Token Format (Example)\n\
                # ghp_0123456789ABCDEFGHIJKLMNOPQRSTUVWXyz\n\
                # ^^ Exactly 36 characters after 'ghp_' prefix\n\
                # Never commit real tokens";
    let matches = scan_cpu(&scanner, text, "github_docs.txt");
    assert_eq!(
        matches.len(),
        0,
        "GitHub token format example must not be detected"
    );
}

#[test]
fn documentation_example_urls_not_secrets() {
    let scanner = build_scanner();
    let text = "database_url = \"postgresql://user:password@localhost:5432/mydb\"\n\
                api_endpoint = \"https://api.example.com/v1/endpoint\"\n\
                redis_url = \"redis://127.0.0.1:6379/0\"\n\
                mysql_url = \"mysql://root@localhost:3306/testdb\"";
    let matches = scan_cpu(&scanner, text, "config_example.env");
    assert_eq!(
        matches.len(),
        0,
        "Example DB URLs with localhost must not be detected"
    );
}

#[test]
fn placeholder_domains_not_secrets() {
    let scanner = build_scanner();
    let text = "api_url = \"https://example.com/api\"\n\
                static_url = \"https://cdn.example.org/assets\"\n\
                auth_server = \"https://auth.example.net\"\n\
                domain = \"example.io\"";
    let matches = scan_cpu(&scanner, text, "urls.toml");
    assert_eq!(
        matches.len(),
        0,
        "example.com/example.org placeholder domains must not be detected"
    );
}

#[test]
fn localhost_db_connection_not_secret() {
    let scanner = build_scanner();
    let text = "// Development database configuration\n\
                DatabaseHost=localhost\n\
                DatabasePort=5432\n\
                DatabaseName=myapp_dev\n\
                DatabaseUser=dev_user\n\
                DatabasePassword=dev_password\n\
                ConnectionString=\"Server=localhost;Database=myapp;User=dev;Password=dev;\"";
    let matches = scan_cpu(&scanner, text, "appsettings.Development.json");
    assert_eq!(
        matches.len(),
        0,
        "localhost database URLs must not be detected"
    );
}

// ============================================================================
// CHECKSUMS, FINGERPRINTS, HASHES IN CONFIG
// ============================================================================

#[test]
fn ssl_certificate_fingerprint_not_secret() {
    let scanner = build_scanner();
    let text = "# TLS Certificate Fingerprint (SHA256)\n\
                # Public information, safe to publish\n\
                certificate_fingerprint = \"5a8f3c9e2b1d4e7a9c6f3d2a1e5b8c0f4a2d9e7c1b8f3d2a9e5c6b7f8a0d\"\n\
                # Pin this fingerprint for certificate pinning";
    let matches = scan_cpu(&scanner, text, "tls_pins.conf");
    assert_eq!(
        matches.len(),
        0,
        "SSL certificate fingerprints must not be detected"
    );
}

#[test]
fn gpg_key_fingerprint_not_secret() {
    let scanner = build_scanner();
    let text = "# GPG Public Key Fingerprint\n\
                pub_key_fp = \"3F2A 9C7E 1B4D 4E8A 9C0F 7A2B 6D8E 1C3F 5A9B 2E0D\"\n\
                # This is public information from keyservers";
    let matches = scan_cpu(&scanner, text, "gpg_keys.txt");
    assert_eq!(
        matches.len(),
        0,
        "GPG public key fingerprints must not be detected"
    );
}

#[test]
fn docker_image_digest_not_secret() {
    let scanner = build_scanner();
    let text = "# Docker image digests (SHA256, public)\n\
                ubuntu@sha256:9f3c1a7e2b8d4056c1e9a7b3f0d6428e5a1c9b7e3f2d8064a5c1e9b7f3d20486\n\
                node@sha256:2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a";
    let matches = scan_cpu(&scanner, text, "Dockerfile");
    assert_eq!(
        matches.len(),
        0,
        "Docker image digests must not be detected"
    );
}

#[test]
fn subresource_integrity_hash_not_secret() {
    let scanner = build_scanner();
    let text = "<script src=\"https://cdn.example.com/lib.js\"\n\
                  integrity=\"sha256-9f3c1a7e2b8d4056c1e9a7b3f0d6428e5a1c9b7e3f2d8064a5c1e9b7f3d20486\"\n\
                  crossorigin=\"anonymous\"></script>";
    let matches = scan_cpu(&scanner, text, "index.html");
    assert_eq!(
        matches.len(),
        0,
        "Subresource Integrity hashes must not be detected"
    );
}

// ============================================================================
// GIT AND VERSION CONTROL HASHES
// ============================================================================

#[test]
fn git_commit_hash_in_changelog_not_secret() {
    let scanner = build_scanner();
    let text = "## [1.2.0] - 2026-06-09\n\n\
                ### Fixed\n\
                - Fixed issue #123 (commit: 5a8f3c9e2b1d4e7a9c6f3d2a1e5b8c0f4a2d9e7c)\n\
                - Improved performance (commit: 2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b)";
    let matches = scan_cpu(&scanner, text, "CHANGELOG.md");
    assert_eq!(
        matches.len(),
        0,
        "Git commit hashes in changelogs must not be detected"
    );
}

#[test]
fn mercurial_changeset_hash_not_secret() {
    let scanner = build_scanner();
    let text = "# Mercurial changeset hashes (from commit log)\n\
                changeset: 5a8f3c9e2b1d4e7a9c6f3d2a1e5b8c0f4a2d9e7c\n\
                user: dev@example.com\n\
                date: Mon Jun 09 12:00:00 2026 +0000";
    let matches = scan_cpu(&scanner, text, "hg_log.txt");
    assert_eq!(
        matches.len(),
        0,
        "Mercurial changeset hashes must not be detected"
    );
}

#[test]
fn svn_revision_number_not_secret() {
    let scanner = build_scanner();
    let text = "# SVN revision log\n\
                r12345 | dev | 2026-06-09T12:00:00.000000Z | 1 line\n\
                Fix: update component\n\
                \n\
                r12346 | dev | 2026-06-09T12:30:00.000000Z | 2 lines\n\
                Improve: performance optimization";
    let matches = scan_cpu(&scanner, text, "svn_log.txt");
    assert_eq!(
        matches.len(),
        0,
        "SVN revision numbers must not be detected"
    );
}

// ============================================================================
// BOUNDARY CASES AND ADVERSARIAL PATTERNS
// ============================================================================

#[test]
fn high_entropy_hex_similar_to_secret_not_secret() {
    let scanner = build_scanner();
    // High-entropy hex string but too long, wrong format, or context indicates non-secret
    let text = "# Random hex data (NOT a credential)\n\
                random_hex_data_128 = \"9f3c1a7e2b8d4056c1e9a7b3f0d6428e5a1c9b7e3f2d8064a5c1e9b7f3d204865a8f3c9e2b1d4e7a9c6f3d2a1e5b8c0f4a2d9e7c2b1d4e7a9c6f3d2a1e5b8c0f4a2d9e7c\"";
    let matches = scan_cpu(&scanner, text, "test_data.toml");
    // Focus on credential count, not detector attribution
    let cred_set = credential_set(&matches);
    assert!(
        cred_set.is_empty()
            || cred_set
                .iter()
                .all(|c| c.contains("_data") || c.contains("example") || c.contains("test")),
        "Long hex strings in labeled non-secret context must not trigger high-confidence matches"
    );
}

#[test]
fn repeated_hex_pattern_not_secret() {
    let scanner = build_scanner();
    let text = "// Filler pattern (low entropy)\n\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
                bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n\
                // Test pattern\n\
                1111111111111111111111111111111111111111";
    let matches = scan_cpu(&scanner, text, "pattern_test.txt");
    assert_eq!(
        matches.len(),
        0,
        "Repeated character patterns (low entropy) must not be detected"
    );
}

#[test]
fn sequential_hex_not_secret() {
    let scanner = build_scanner();
    let text = "# Sequential patterns\n\
                sequential_a = \"0123456789abcdef0123456789abcdef\"\n\
                sequential_b = \"fedcba9876543210fedcba9876543210\"";
    let matches = scan_cpu(&scanner, text, "seq_patterns.txt");
    assert_eq!(
        matches.len(),
        0,
        "Sequential hex patterns must not be detected"
    );
}

#[test]
fn mixed_case_uuid_like_pattern_not_secret() {
    let scanner = build_scanner();
    let text = "id_1 = \"AbCdEf12-34Gh-56Ij-78Kl-90MnOpQrStUv\"\n\
                id_2 = \"12345678-90ab-cdef-ghij-klmnopqrstuv\"";
    let matches = scan_cpu(&scanner, text, "ids.toml");
    assert_eq!(
        matches.len(),
        0,
        "UUID-like patterns with non-hex chars must not be detected"
    );
}

// ============================================================================
// PARITY TESTS: CPU == GPU on all above cases
// ============================================================================

#[test]
fn sha256_parity_cpu_gpu() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    let scanner = build_scanner();
    let text = "commit 9f3c1a7e2b8d4056c1e9a7b3f0d6428e5a1c9b7e3f2d8064a5c1e9b7f3d20486";
    let cpu = scan_cpu(&scanner, text, "log.txt");
    let gpu = scan_gpu(&scanner, text, "log.txt");
    assert_eq!(
        cpu.len(),
        gpu.len(),
        "SHA256 hash: CPU={}, GPU={}, must be identical",
        cpu.len(),
        gpu.len()
    );
}

#[test]
fn uuid_parity_cpu_gpu() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    let scanner = build_scanner();
    let text = "User ID: 550e8400-e29b-41d4-a716-446655440000";
    let cpu = scan_cpu(&scanner, text, "users.json");
    let gpu = scan_gpu(&scanner, text, "users.json");
    assert_eq!(
        cpu.len(),
        gpu.len(),
        "UUID pattern: CPU={}, GPU={}, must be identical",
        cpu.len(),
        gpu.len()
    );
}

#[test]
fn base64_parity_cpu_gpu() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    let scanner = build_scanner();
    let text = "data = \"aGVsbG8gd29ybGQ=\"";
    let cpu = scan_cpu(&scanner, text, "config.json");
    let gpu = scan_gpu(&scanner, text, "config.json");
    assert_eq!(
        cpu.len(),
        gpu.len(),
        "Base64: CPU={}, GPU={}, must be identical",
        cpu.len(),
        gpu.len()
    );
}

#[test]
fn example_placeholder_parity_cpu_gpu() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    let scanner = build_scanner();
    let text = "key_id = \"AKIAIOSFODNN7EXAMPLE\"\n\
                api_url = \"https://example.com/api\"";
    let cpu = scan_cpu(&scanner, text, "readme.md");
    let gpu = scan_gpu(&scanner, text, "readme.md");
    assert_eq!(
        cpu.len(),
        gpu.len(),
        "Example placeholders: CPU={}, GPU={}, must be identical",
        cpu.len(),
        gpu.len()
    );
}

#[test]
fn semver_parity_cpu_gpu() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    let scanner = build_scanner();
    let text = "version = \"1.2.3\"\ncompatible_with = \"^18.2.0\"";
    let cpu = scan_cpu(&scanner, text, "package.json");
    let gpu = scan_gpu(&scanner, text, "package.json");
    assert_eq!(
        cpu.len(),
        gpu.len(),
        "Semver versions: CPU={}, GPU={}, must be identical",
        cpu.len(),
        gpu.len()
    );
}

// ============================================================================
// CLIENT-SAFE DETECTOR ALLOWLIST (for borderline cases)
// ============================================================================

#[test]
fn client_safe_detectors_allowed_in_example_context() {
    let scanner = build_scanner();
    // Some patterns may legitimately fire but should only be CLIENT-SAFE tier
    let text = "# Example configuration\n\
                database_password = \"Tx8vQp2zNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ\"\n\
                api_key = \"sk_test_4eC39HqLyjWDarjtT1zdp7dc\"";
    let matches = scan_cpu(&scanner, text, "example_config.env");

    // If there are findings, they must all be CLIENT-SAFE (no High-confidence FPs in examples)
    for m in &matches {
        // CLIENT-SAFE detectors typically have low confidence or are test/example patterns
        assert!(
            m.detector_id.contains("test")
                || m.detector_id.contains("example")
                || m.detector_id.contains("placeholder"),
            "Found detector: {} in example context; must be CLIENT-SAFE",
            m.detector_id.as_ref()
        );
    }
}