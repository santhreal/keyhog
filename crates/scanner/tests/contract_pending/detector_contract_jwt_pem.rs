//! JWT and PEM private key detector integration tests with GPU/CPU parity.
//!
//! Tests JWT token detection (valid 3-part base64url with header alg checks)
//! and PEM private key detection (RSA, EC, and OPENSSH BEGIN blocks).
//! Validates both positive credentials are found, negative cases don't match,
//! and GPU backend produces identical findings to SIMD CPU backend.

#[path = "support/mod.rs"]
mod support;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::collections::BTreeSet;
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

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    CompiledScanner::compile(detectors).expect("compile scanner")
}

/// Cross-backend finding comparison: (credential, file_path, offset) tuple.
fn collect_findings(results: &[Vec<RawMatch>]) -> BTreeSet<(String, String, usize)> {
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

// ============================================================================
// JWT TESTS
// ============================================================================

/// JWT-001: Valid canonical JWT (HS256) is detected.
#[test]
fn jwt_canonical_hs256_token_detected() {
    let s = scanner();
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w";
    let chunk = make_chunk(jwt, "auth.rs");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, _, _)| cred == jwt),
        "JWT canonical HS256 must be detected. Found: {:?}",
        findings.iter().map(|(c, _, _)| c).collect::<Vec<_>>()
    );
}

/// JWT-002: JWT inside Bearer token header is extracted.
#[test]
fn jwt_bearer_header_extracted() {
    let s = scanner();
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w";
    let text = format!("Authorization: Bearer {}", jwt);
    let chunk = make_chunk(&text, "header.txt");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, _, _)| cred == jwt),
        "JWT must be extracted from Bearer header"
    );
}

/// JWT-003: JWT with RS256 algorithm is detected.
#[test]
fn jwt_rs256_algorithm_detected() {
    let s = scanner();
    let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POdFOL0W_7Hj7-xyoN_qm0TI1gw2XLvqfFp9Kg6bFn4u9UpMwkNfXKBxfcg2aokH1hlbEJnXV8qvL7UkHm5TkA1WUP2lN1RoQ9S4hLvXJLzBFXGF_RWu3-0-WMqUyVZWwwZX7z72ky3F8TYzQXjUjK7sE3N1G9_v_8PZvwNW9hXSp-H2_7CLGg-pRjVR9_vKLzN0HaLkqUKNLEW42r4kP8xGx-s4v0xN6_p9vLUvfNmLEGW-lqj2ShUcJLNGPFGN2rRxzLRvPsJB7N7W_aW5gLLMLl6PGkzVU_j3MjRWJxOxpKm-6bV9EKH9hLM1UqmVF8MZF7O4GS0gIw";
    let chunk = make_chunk(jwt, "token.json");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, _, _)| cred == jwt),
        "JWT with RS256 algorithm must be detected"
    );
}

/// JWT-004: JWT with HS512 algorithm is detected.
#[test]
fn jwt_hs512_algorithm_detected() {
    let s = scanner();
    let jwt = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.yMJhzWGYJbVFQw1L5nPfHqLpjBrJe3DeFKo_VNWVKVqW_Xp7s2QzV9JE3W7kQsZPE7b2u4xVQqYvIqWt5Y-eFQ";
    let chunk = make_chunk(jwt, "config.yml");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, _, _)| cred == jwt),
        "JWT with HS512 algorithm must be detected"
    );
}

/// JWT-005: JWT in JSON configuration is detected.
#[test]
fn jwt_in_json_config_detected() {
    let s = scanner();
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w";
    let text = format!(r#"{{"token": "{}"}}"#, jwt);
    let chunk = make_chunk(&text, "config.json");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, _, _)| cred == jwt),
        "JWT in JSON must be detected"
    );
}

/// JWT-006: JWT in Python string literal is detected.
#[test]
fn jwt_in_python_string_literal_detected() {
    let s = scanner();
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w";
    let text = format!(r#"TOKEN = "{}""#, jwt);
    let chunk = make_chunk(&text, "config.py");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, _, _)| cred == jwt),
        "JWT in Python string must be detected"
    );
}

/// JWT-007: Incomplete JWT (missing signature) is NOT detected.
#[test]
fn jwt_missing_signature_not_detected() {
    let s = scanner();
    let incomplete_jwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
    let chunk = make_chunk(incomplete_jwt, "bad.txt");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        !findings.iter().any(|(cred, _, _)| cred == incomplete_jwt),
        "Incomplete JWT (only 2 segments) must NOT match"
    );
}

/// JWT-008: JWT header only (single segment) is NOT detected.
#[test]
fn jwt_header_only_not_detected() {
    let s = scanner();
    let header_only = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    let chunk = make_chunk(header_only, "fragment.txt");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        !findings.iter().any(|(cred, _, _)| cred == header_only),
        "JWT header alone must NOT match"
    );
}

/// JWT-009: Prose mention of JWT without real token is NOT detected.
#[test]
fn jwt_prose_mention_not_detected() {
    let s = scanner();
    let text = "RFC 7519 defines JWT format as three base64url segments: eyJhbGci...";
    let chunk = make_chunk(text, "readme.md");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        findings.is_empty(),
        "Prose mention without real JWT must NOT match"
    );
}

/// JWT-010: JWT inside single-line comment is detected.
#[test]
fn jwt_in_single_line_comment_detected() {
    let s = scanner();
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w";
    let text = format!("// token: {}", jwt);
    let chunk = make_chunk(&text, "code.rs");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, _, _)| cred == jwt),
        "JWT in comment must be detected"
    );
}

/// JWT-011: Multiple JWTs in one chunk are all detected.
#[test]
fn jwt_multiple_tokens_all_detected() {
    let s = scanner();
    let jwt1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w";
    let jwt2 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POdFOL0W_7Hj7-xyoN_qm0TI1gw2XLvqfFp9Kg6bFn4u9UpMwkNfXKBxfcg2aokH1hlbEJnXV8qvL7UkHm5TkA1WUP2lN1RoQ9S4hLvXJLzBFXGF_RWu3-0-WMqUyVZWwwZX7z72ky3F8TYzQXjUjK7sE3N1G9_v_8PZvwNW9hXSp-H2_7CLGg-pRjVR9_vKLzN0HaLkqUKNLEW42r4kP8xGx-s4v0xN6_p9vLUvfNmLEGW-lqj2ShUcJLNGPFGN2rRxzLRvPsJB7N7W_aW5gLLMLl6PGkzVU_j3MjRWJxOxpKm-6bV9EKH9hLM1UqmVF8MZF7O4GS0gIw";
    let text = format!("token1={}\ntoken2={}", jwt1, jwt2);
    let chunk = make_chunk(&text, "tokens.env");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, _, _)| cred == jwt1),
        "First JWT must be detected"
    );
    assert!(
        findings.iter().any(|(cred, _, _)| cred == jwt2),
        "Second JWT must be detected"
    );
}

// ============================================================================
// PEM PRIVATE KEY TESTS
// ============================================================================

/// PEM-001: Valid RSA PRIVATE KEY block is detected.
#[test]
fn pem_rsa_private_key_block_detected() {
    let s = scanner();
    let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA7n2K9xR4vQ1mWcZ8hLbF3jD5sT6yU0pN2aG4eH7iO9kB1lM3\nrV5wX8zC0dQ2fS4gJ6kP8mR0tU2wY4aB6cD8eF0gH2iJ4kL6mN8oP0qR2sT4uV6\nwX8yZ0aB2cD4eF6gH8iJ0kL2mN4oP6qR8sT0\n-----END RSA PRIVATE KEY-----";
    let chunk = make_chunk(pem, "id_rsa");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, _, _)| cred.contains("BEGIN RSA PRIVATE KEY")),
        "RSA PRIVATE KEY block must be detected"
    );
}

/// PEM-002: EC PRIVATE KEY block is detected.
#[test]
fn pem_ec_private_key_block_detected() {
    let s = scanner();
    let pem = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIIGlVtLvq3z+mHKFO|u6=Fwpt<-U2>a-)k GJ`nOz;n5oAoGCCqGSM49\nAwEHoUQDQgAEWVs/qulSBpo2/gCcWkUR+d1jJg4tE1YJXOGqJ0G2WbBHYVGVdyXB\nLqMYfDTf0hEzKYfx1cDMxOzKZIYl1LEJoQ==\n-----END EC PRIVATE KEY-----";
    let chunk = make_chunk(pem, "id_ec");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, _, _)| cred.contains("BEGIN EC PRIVATE KEY")),
        "EC PRIVATE KEY block must be detected"
    );
}

/// PEM-003: OPENSSH PRIVATE KEY block is detected.
#[test]
fn pem_openssh_private_key_block_detected() {
    let s = scanner();
    let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUtbm9uZS1ub25lAAAAaAAAABNlY2RzYS1z\naGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAIQDZmfb/sUf89z7A0r3vCEzL04iY\nF2qHT8l1xUfQy5TmSQAAAJBLLhGKSy4RigAAAATZmfb/sUf89z7A0r3vCEzL04iY\nF2qHT8l1xUfQy5TmSQAAAAg=\n-----END OPENSSH PRIVATE KEY-----";
    let chunk = make_chunk(pem, "id_ed25519");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        findings
            .iter()
            .any(|(cred, _, _)| cred.contains("BEGIN OPENSSH PRIVATE KEY")),
        "OPENSSH PRIVATE KEY block must be detected"
    );
}

/// PEM-004: RSA PRIVATE KEY in YAML config (multi-line literal) is detected.
#[test]
fn pem_rsa_in_yaml_literal_detected() {
    let s = scanner();
    let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA7n2K9xR4vQ1mWcZ8hLbF3jD5sT6yU0pN2aG4eH7iO9kB1lM3\nrV5wX8zC0dQ2fS4gJ6kP8mR0tU2wY4aB6cD8eF0gH2iJ4kL6mN8oP0qR2sT4uV6\nwX8yZ0aB2cD4eF6gH8iJ0kL2mN4oP6qR8sT0\n-----END RSA PRIVATE KEY-----";
    let text = format!("tls_key: |\n  {}", pem.replace('\n', "\n  "));
    let chunk = make_chunk(&text, "config.yaml");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, _, _)| cred.contains("BEGIN RSA PRIVATE KEY")),
        "RSA key in YAML literal must be detected"
    );
}

/// PEM-005: PEM key inside JSON quoted string is detected.
#[test]
fn pem_rsa_in_json_quoted_detected() {
    let s = scanner();
    let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA7n2K9xR4vQ1mWcZ8hLbF3jD5sT6yU0pN2aG4eH7iO9kB1lM3\nrV5wX8zC0dQ2fS4gJ6kP8mR0tU2wY4aB6cD8eF0gH2iJ4kL6mN8oP0qR2sT4uV6\nwX8yZ0aB2cD4eF6gH8iJ0kL2mN4oP6qR8sT0\n-----END RSA PRIVATE KEY-----";
    let escaped = pem.replace('\n', "\\n");
    let text = format!(r#"{{"key": "{}"}}"#, escaped);
    let chunk = make_chunk(&text, "creds.json");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        !findings.is_empty(),
        "PEM key in JSON quoted form must be detected (escaped newlines)"
    );
}

/// PEM-006: BEGIN/END markers alone (without body) are NOT detected.
#[test]
fn pem_markers_alone_not_detected() {
    let s = scanner();
    let text = "-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----";
    let chunk = make_chunk(text, "empty.pem");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        findings.is_empty(),
        "Empty PEM block (no body) must NOT match"
    );
}

/// PEM-007: Fake PEM with EXAMPLE marker in body is NOT detected.
#[test]
fn pem_with_example_marker_not_detected() {
    let s = scanner();
    let text = "-----BEGIN RSA PRIVATE KEY-----\nEXAMPLE_DATA_HERE_REPLACEMENT_VALUE\n-----END RSA PRIVATE KEY-----";
    let chunk = make_chunk(text, "template.pem");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        findings.is_empty(),
        "PEM with EXAMPLE marker suppressed by safety gate"
    );
}

/// PEM-008: Placeholder-keyword body does NOT match.
#[test]
fn pem_placeholder_keyword_not_detected() {
    let s = scanner();
    let text = "-----BEGIN RSA PRIVATE KEY-----\nPLACEHOLDER_VALUE_REPLACEMENT_CONTENT\n-----END RSA PRIVATE KEY-----";
    let chunk = make_chunk(text, "placeholder.pem");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        findings.is_empty(),
        "PEM with PLACEHOLDER keyword suppressed by safety gate"
    );
}

/// PEM-009: Multiple PEM blocks in one file are all detected.
#[test]
fn pem_multiple_blocks_all_detected() {
    let s = scanner();
    let rsa = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA7n2K9xR4vQ1mWcZ8hLbF3jD5sT6yU0pN2aG4eH7iO9kB1lM3\nrV5wX8zC0dQ2fS4gJ6kP8mR0tU2wY4aB6cD8eF0gH2iJ4kL6mN8oP0qR2sT4uV6\nwX8yZ0aB2cD4eF6gH8iJ0kL2mN4oP6qR8sT0\n-----END RSA PRIVATE KEY-----";
    let ec = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIIGlVtLvq3z+mHKFO|u6=Fwpt<-U2>a-)k GJ`nOz;n5oAoGCCqGSM49\nAwEHoUQDQgAEWVs/qulSBpo2/gCcWkUR+d1jJg4tE1YJXOGqJ0G2WbBHYVGVdyXB\nLqMYfDTf0hEzKYfx1cDMxOzKZIYl1LEJoQ==\n-----END EC PRIVATE KEY-----";
    let text = format!("{}\n\n{}", rsa, ec);
    let chunk = make_chunk(&text, "keys.pem");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    let has_rsa = findings.iter().any(|(cred, _, _)| cred.contains("BEGIN RSA"));
    let has_ec = findings.iter().any(|(cred, _, _)| cred.contains("BEGIN EC"));
    assert!(has_rsa, "RSA key must be detected");
    assert!(has_ec, "EC key must be detected");
}

/// PEM-010: PEM key inside shell export statement is detected.
#[test]
fn pem_in_shell_export_detected() {
    let s = scanner();
    let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA7n2K9xR4vQ1mWcZ8hLbF3jD5sT6yU0pN2aG4eH7iO9kB1lM3\nrV5wX8zC0dQ2fS4gJ6kP8mR0tU2wY4aB6cD8eF0gH2iJ4kL6mN8oP0qR2sT4uV6\nwX8yZ0aB2cD4eF6gH8iJ0kL2mN4oP6qR8sT0\n-----END RSA PRIVATE KEY-----";
    let text = format!("export TLS_KEY=\"{}\"", pem.replace('\n', "\\n"));
    let chunk = make_chunk(&text, "env.sh");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        !findings.is_empty(),
        "PEM in shell export must be detected"
    );
}

// ============================================================================
// GPU PARITY TESTS
// ============================================================================

/// GPU-PARITY-JWT: GPU backend finds identical JWTs as SIMD CPU.
#[test]
#[cfg(feature = "gpu")]
fn gpu_parity_jwt_tokens() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU available");
        return;
    }
    let s = scanner();
    let jwt1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w";
    let jwt2 = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.yMJhzWGYJbVFQw1L5nPfHqLpjBrJe3DeFKo_VNWVKVqW_Xp7s2QzV9JE3W7kQsZPE7b2u4xVQqYvIqWt5Y-eFQ";
    let chunks = vec![
        make_chunk(jwt1, "auth.rs"),
        make_chunk(&format!("Bearer {}", jwt2), "header.txt"),
    ];
    let simd_results = s.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let gpu_results = s.scan_chunks_with_backend(&chunks, ScanBackend::Gpu);
    let simd_findings = collect_findings(&simd_results);
    let gpu_findings = collect_findings(&gpu_results);
    assert!(
        !gpu_findings.is_empty() || simd_findings.is_empty(),
        "GPU must not silently return empty when SIMD finds tokens"
    );
    assert_eq!(simd_findings, gpu_findings, "GPU and SIMD must find identical JWT credentials");
}

/// GPU-PARITY-PEM: GPU backend finds identical PEM keys as SIMD CPU.
#[test]
#[cfg(feature = "gpu")]
fn gpu_parity_pem_keys() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU available");
        return;
    }
    let s = scanner();
    let rsa = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA7n2K9xR4vQ1mWcZ8hLbF3jD5sT6yU0pN2aG4eH7iO9kB1lM3\nrV5wX8zC0dQ2fS4gJ6kP8mR0tU2wY4aB6cD8eF0gH2iJ4kL6mN8oP0qR2sT4uV6\nwX8yZ0aB2cD4eF6gH8iJ0kL2mN4oP6qR8sT0\n-----END RSA PRIVATE KEY-----";
    let ec = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIIGlVtLvq3z+mHKFO|u6=Fwpt<-U2>a-)k GJ`nOz;n5oAoGCCqGSM49\nAwEHoUQDQgAEWVs/qulSBpo2/gCcWkUR+d1jJg4tE1YJXOGqJ0G2WbBHYVGVdyXB\nLqMYfDTf0hEzKYfx1cDMxOzKZIYl1LEJoQ==\n-----END EC PRIVATE KEY-----";
    let chunks = vec![make_chunk(rsa, "id_rsa"), make_chunk(ec, "id_ec")];
    let simd_results = s.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let gpu_results = s.scan_chunks_with_backend(&chunks, ScanBackend::Gpu);
    let simd_findings = collect_findings(&simd_results);
    let gpu_findings = collect_findings(&gpu_results);
    assert!(
        !gpu_findings.is_empty() || simd_findings.is_empty(),
        "GPU must not silently return empty when SIMD finds PEM keys"
    );
    assert_eq!(simd_findings, gpu_findings, "GPU and SIMD must find identical PEM credentials");
}

/// GPU-PARITY-MIXED: GPU backend finds identical credentials in JWT + PEM mixture.
#[test]
#[cfg(feature = "gpu")]
fn gpu_parity_jwt_and_pem_mixed() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU available");
        return;
    }
    let s = scanner();
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w";
    let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA7n2K9xR4vQ1mWcZ8hLbF3jD5sT6yU0pN2aG4eH7iO9kB1lM3\nrV5wX8zC0dQ2fS4gJ6kP8mR0tU2wY4aB6cD8eF0gH2iJ4kL6mN8oP0qR2sT4uV6\nwX8yZ0aB2cD4eF6gH8iJ0kL2mN4oP6qR8sT0\n-----END RSA PRIVATE KEY-----";
    let mixed = format!("jwt_token: {}\nprivate_key: |\n  {}", jwt, pem.replace('\n', "\n  "));
    let chunk = make_chunk(&mixed, "config.yaml");
    let simd_results = s.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let gpu_results = s.scan_chunks_with_backend(&[chunk], ScanBackend::Gpu);
    let simd_findings = collect_findings(&simd_results);
    let gpu_findings = collect_findings(&gpu_results);
    assert!(
        !gpu_findings.is_empty() || simd_findings.is_empty(),
        "GPU must not silently return empty when SIMD finds mixed credentials"
    );
    assert_eq!(simd_findings, gpu_findings, "GPU and SIMD must find identical mixed JWT + PEM credentials");
}

// ============================================================================
// BOUNDARY & MULTI-LINE TESTS
// ============================================================================

/// BOUNDARY-JWT-001: JWT straddling chunk boundary is detected.
#[test]
fn jwt_boundary_straddled_detected() {
    let s = scanner();
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w";
    let split_at = 60;
    let mut chunk_a = "x".repeat(100);
    chunk_a.push_str(&jwt[..split_at]);
    let chunk_b = jwt[split_at..].to_string() + "y";
    let chunks = vec![
        Chunk {
            data: chunk_a.clone().into(),
            metadata: ChunkMetadata {
                source_type: "test".into(),
                path: Some("file.txt".into()),
                base_offset: 0,
                ..Default::default()
            },
        },
        Chunk {
            data: chunk_b.into(),
            metadata: ChunkMetadata {
                source_type: "test".into(),
                path: Some("file.txt".into()),
                base_offset: chunk_a.len(),
                ..Default::default()
            },
        },
    ];
    let results = s.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, _, _)| cred == jwt),
        "JWT straddling chunk boundary must be detected via reassembly"
    );
}

/// BOUNDARY-PEM-001: PEM block straddling chunk boundary is detected.
#[test]
fn pem_boundary_straddled_detected() {
    let s = scanner();
    let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA7n2K9xR4vQ1mWcZ8hLbF3jD5sT6yU0pN2aG4eH7iO9kB1lM3\nrV5wX8zC0dQ2fS4gJ6kP8mR0tU2wY4aB6cD8eF0gH2iJ4kL6mN8oP0qR2sT4uV6\nwX8yZ0aB2cD4eF6gH8iJ0kL2mN4oP6qR8sT0\n-----END RSA PRIVATE KEY-----";
    let split_at = 80;
    let mut chunk_a = "z".repeat(120);
    chunk_a.push_str(&pem[..split_at]);
    let chunk_b = pem[split_at..].to_string() + "z";
    let chunks = vec![
        Chunk {
            data: chunk_a.clone().into(),
            metadata: ChunkMetadata {
                source_type: "test".into(),
                path: Some("keys.pem".into()),
                base_offset: 0,
                ..Default::default()
            },
        },
        Chunk {
            data: chunk_b.into(),
            metadata: ChunkMetadata {
                source_type: "test".into(),
                path: Some("keys.pem".into()),
                base_offset: chunk_a.len(),
                ..Default::default()
            },
        },
    ];
    let results = s.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        findings
            .iter()
            .any(|(cred, _, _)| cred.contains("BEGIN RSA PRIVATE KEY")),
        "PEM block straddling chunk boundary must be detected"
    );
}

// ============================================================================
// ADVERSARIAL & EDGE CASES
// ============================================================================

/// ADV-JWT-001: JWT with non-printable characters in whitespace is detected.
#[test]
fn jwt_with_whitespace_characters_detected() {
    let s = scanner();
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w";
    let text = format!("token\t=\r\n{}", jwt);
    let chunk = make_chunk(&text, "messy.txt");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, _, _)| cred == jwt),
        "JWT after whitespace variations must be detected"
    );
}

/// ADV-PEM-001: PEM with unusual spacing in BEGIN/END is still detected.
#[test]
fn pem_with_varied_content_detected() {
    let s = scanner();
    let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA7n2K9xR4vQ1mWcZ8hLbF3jD5sT6yU0pN2aG4eH7iO9kB1lM3\nrV5wX8zC0dQ2fS4gJ6kP8mR0tU2wY4aB6cD8eF0gH2iJ4kL6mN8oP0qR2sT4uV6\nwX8yZ0aB2cD4eF6gH8iJ0kL2mN4oP6qR8sT0\n-----END RSA PRIVATE KEY-----";
    let text = format!("key_data:\n  {}", pem.replace('\n', "\n  "));
    let chunk = make_chunk(&text, "indented.yaml");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        findings
            .iter()
            .any(|(cred, _, _)| cred.contains("BEGIN RSA PRIVATE KEY")),
        "Indented PEM block must be detected"
    );
}

/// ADV-JWT-002: JWT URL-encoded in query string is detected.
#[test]
fn jwt_url_encoded_in_query_detected() {
    let s = scanner();
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w";
    let text = format!("https://api.example.com?token={}", jwt);
    let chunk = make_chunk(&text, "url.txt");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, _, _)| cred == jwt),
        "JWT in URL query must be detected"
    );
}

/// ADV-PEM-002: Adversarial OPENSSH block with special characters is detected.
#[test]
fn pem_openssh_with_special_chars_detected() {
    let s = scanner();
    let pem = "-----BEGIN OPENSSH PRIVATE KEY BLOCK-----ci>Pl//3g_i){edMnfn/'I5e?}/oiz@y+mHKFO|u6=Fwpt<-U2>a-)k GJ`nOz;-----END PRIVATE KEY BLOCK-----";
    let chunk = make_chunk(pem, "weird.pem");
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);
    assert!(
        findings
            .iter()
            .any(|(cred, _, _)| cred.contains("OPENSSH PRIVATE KEY") || cred.contains("PRIVATE KEY BLOCK")),
        "OPENSSH block with special chars must be detected"
    );
}
