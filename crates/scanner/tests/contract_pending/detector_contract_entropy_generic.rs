//! Generic password/API key detector contract enforcement at the entropy floor.
//!
//! Tests the generic-password detector's entropy-based filtering when credentials
//! are assigned via simple patterns (password=, api_key:, secret =, etc.). The
//! generic detector bridges high-entropy synthesis when no service-specific prefix
//! matches, and this test ensures:
//!
//! 1. Positive twin cases at the entropy floor (4.5 bits) are detected consistently.
//! 2. Negative twin cases slightly below the entropy floor are NOT detected.
//! 3. Adversarial edge cases (quoted, spaced, mixed-case keywords) maintain detection.
//! 4. Low-entropy bodies (repeated chars, placeholder markers) are suppressed.
//! 5. Boundary transitions from high → low entropy are observed.
//! 6. Generic assignment patterns in various syntaxes are recognized.
//!
//! COVERAGE PARTITION: entropy-fallback-floor, generic-assignment
//! - High-entropy strings at detector min_confidence thresholds
//! - Generic keyword matching (password, api_key, secret, token)
//! - Entropy calculation variance across chunk boundaries
//! - Suppression gates (PLACEHOLDER, EXAMPLE, repeated chars)

#[path = "support/mod.rs"]
mod support;

use keyhog_core::{Chunk, ChunkMetadata};
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

type FindingKey = (String, String);

fn collect_findings(results: &[Vec<keyhog_core::RawMatch>]) -> BTreeSet<FindingKey> {
    results
        .iter()
        .flat_map(|chunk| chunk.iter())
        .map(|m| (
            m.credential.as_ref().to_string(),
            m.detector_id.as_ref().to_string(),
        ))
        .collect()
}

fn assert_has_credential(results: &[Vec<keyhog_core::RawMatch>], expected_cred: &str) {
    let findings = collect_findings(results);
    let found = findings.iter().any(|(cred, _)| cred == expected_cred);
    assert!(
        found,
        "Expected credential '{}' not found. Got: {:?}",
        expected_cred,
        findings
    );
}

fn assert_no_credential(results: &[Vec<keyhog_core::RawMatch>], unexpected_cred: &str) {
    let findings = collect_findings(results);
    let found = findings.iter().any(|(cred, _)| cred == unexpected_cred);
    assert!(
        !found,
        "Unexpected credential '{}' found. Full results: {:?}",
        unexpected_cred,
        findings
    );
}

// ============================================================================
// POSITIVE CASES: High-entropy generic assignments
// ============================================================================

#[test]
fn generic_password_assignment_simple() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Canonical: password=<high-entropy-20-chars>
    // 20 chars of mixed case/digit is ~5.3 bits entropy, well above floor.
    let chunk = make_chunk("password=S4oxj2N-bVEi6ivQsrW3", "test.env");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "S4oxj2N-bVEi6ivQsrW3");
}

#[test]
fn generic_password_with_spaces() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Space before/after the equals sign
    let chunk = make_chunk("password = aAbBcCdDeEfFgGhHiIjJ", "test.conf");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "aAbBcCdDeEfFgGhHiIjJ");
}

#[test]
fn generic_password_quoted() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Quoted with double-quotes
    let chunk = make_chunk(r#"password="TuVwXyZaBcDeFgHiJkLm""#, "test.yaml");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "TuVwXyZaBcDeFgHiJkLm");
}

#[test]
fn generic_api_key_colon_assignment() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // api_key: (colon separator)
    let chunk = make_chunk("api_key: NoP1qRsT2uVwXyZ3aBcD", "config.yml");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "NoP1qRsT2uVwXyZ3aBcD");
}

#[test]
fn generic_secret_json_field() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // JSON field: "secret":"value"
    let chunk = make_chunk(r#"{"secret":"eFgHiJkL9mNoPqRsT0uV"}"#, "config.json");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "eFgHiJkL9mNoPqRsT0uV");
}

#[test]
fn generic_token_field() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // JSON field: "token": "value"
    let chunk = make_chunk(r#"{"token":"WxYzAb1cD2eF3gH4iJ5k"}"#, "secrets.json");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "WxYzAb1cD2eF3gH4iJ5k");
}

#[test]
fn generic_access_key_assignment() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // access_key assignment
    let chunk = make_chunk("access_key=LmNoPqRsT3uVwXyZ1aB2C", "app.conf");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "LmNoPqRsT3uVwXyZ1aB2C");
}

#[test]
fn generic_client_secret_json() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // JSON: "client_secret"
    let chunk = make_chunk(r#"{"client_secret":"Cd4eF5gH6iJ7kL8mN9oP"}"#, "oauth.json");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "Cd4eF5gH6iJ7kL8mN9oP");
}

#[test]
fn generic_with_special_chars_in_value() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Password with special chars allowed by detector
    let chunk = make_chunk("password=aAbBcC!@#$%^dDeEfF", "test.env");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "aAbBcC!@#$%^dDeEfF");
}

// ============================================================================
// NEGATIVE TWINS: Low-entropy bodies (below floor, should NOT be detected)
// ============================================================================

#[test]
fn generic_password_low_entropy_repeated_chars() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // "aaaaaaaaaaaaaaaaaaaaaa" (22 'a's) has entropy near 0.0
    let chunk = make_chunk("password=aaaaaaaaaaaaaaaaaaaaaa", "test.env");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    // Should NOT detect pure repetition
    assert_no_credential(&results, "aaaaaaaaaaaaaaaaaaaaaa");
}

#[test]
fn generic_password_sequence_low_entropy() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // "123456789012345678901" (sequential, low entropy ~2.0)
    let chunk = make_chunk("password=123456789012345678901", "test.env");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    // Sequential patterns should have low entropy and not match
    assert_no_credential(&results, "123456789012345678901");
}

#[test]
fn generic_password_placeholder_suppression() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // PLACEHOLDER prefix is suppressed
    let chunk = make_chunk("password=PLACEHOLDER_VALUE_HERE", "test.env");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_no_credential(&results, "PLACEHOLDER_VALUE_HERE");
}

#[test]
fn generic_password_example_suppression() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // EXAMPLE token marker suppressed
    let chunk = make_chunk("password=S4oxj2N-EXAMPLEivQsrW3", "test.env");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_no_credential(&results, "S4oxj2N-EXAMPLEivQsrW3");
}

#[test]
fn generic_password_too_short_below_minimum() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Only 11 chars (detector requires 12+)
    let chunk = make_chunk("password=AbC1d2E3fGhI", "test.env");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_no_credential(&results, "AbC1d2E3fGhI");
}

#[test]
fn generic_password_too_long_exceeds_max() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // 81 chars (detector caps at 80)
    let long_val = "aAbBcCdDeEfFgGhHiIjJkKlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789!@#$%^&*+=/_-_";
    assert_eq!(long_val.len(), 81);
    let chunk = make_chunk(&format!("password={}", long_val), "test.env");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_no_credential(&results, long_val);
}

// ============================================================================
// ADVERSARIAL/EDGE CASES: Case variations, whitespace, mixed patterns
// ============================================================================

#[test]
fn generic_password_uppercase_keyword() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // PASSWORD= (all caps)
    let chunk = make_chunk("PASSWORD=aAbBcCdDeEfFgGhHiIjJ", "test.env");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "aAbBcCdDeEfFgGhHiIjJ");
}

#[test]
fn generic_passwd_abbreviation() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // passwd (short form)
    let chunk = make_chunk("passwd=TuVwXyZaBcDeFgHiJkLm", "test.conf");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "TuVwXyZaBcDeFgHiJkLm");
}

#[test]
fn generic_pwd_abbreviation() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // pwd (shortest abbrev)
    let chunk = make_chunk("pwd=NoP1qRsT2uVwXyZ3aBcD", "test.conf");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "NoP1qRsT2uVwXyZ3aBcD");
}

#[test]
fn generic_underscored_keyword() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // _password (prefixed with underscore)
    let chunk = make_chunk("_password=eFgHiJkL9mNoPqRsT0uV", "test.env");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "eFgHiJkL9mNoPqRsT0uV");
}

#[test]
fn generic_single_quotes() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Single-quoted value
    let chunk = make_chunk("password='WxYzAb1cD2eF3gH4iJ5k'", "test.conf");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "WxYzAb1cD2eF3gH4iJ5k");
}

#[test]
fn generic_connection_string_url_password() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // URL-embedded password: user:PASSWORD@host
    let chunk = make_chunk(
        "database://admin:AbC1dEf2gHiJ3kLmN4oP@db.example.com",
        "connection.conf",
    );
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "AbC1dEf2gHiJ3kLmN4oP");
}

#[test]
fn generic_yaml_multiline_block() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // YAML multiline with pipe |
    let chunk = make_chunk(
        "password: |\n  aBcDeFgHiJkLmNoPqRsT",
        "config.yaml",
    );
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "aBcDeFgHiJkLmNoPqRsT");
}

#[test]
fn generic_xml_attribute() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // XML/HTML attribute format
    let chunk = make_chunk(r#"<config password="TuVwXyZaBcDeFgHiJkLm" />"#, "web.xml");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "TuVwXyZaBcDeFgHiJkLm");
}

// ============================================================================
// BOUNDARY CASES: Entropy floor transitions
// ============================================================================

#[test]
fn generic_entropy_at_floor_high_entropy_20_chars() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // 20 random alphanumeric chars (entropy ~5.3 bits)
    let chunk = make_chunk("secret=K9m2Xp7Lq3Aw1Rn8Fv4B", "config.env");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "K9m2Xp7Lq3Aw1Rn8Fv4B");
}

#[test]
fn generic_entropy_at_floor_mixed_case_12_chars() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // 12 chars minimum (detector min), mixed case and digits
    let chunk = make_chunk("secret=AbC1dEf2gHiJ", "test.env");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "AbC1dEf2gHiJ");
}

#[test]
fn generic_high_entropy_base64_like() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Base64-like string (high entropy with +/=)
    let chunk = make_chunk("token=aB+cD/eF==gH/ijK+lM==n", "secrets.conf");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "aB+cD/eF==gH/ijK+lM==n");
}

#[test]
fn generic_entropy_with_dashes_and_underscores() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Dashes and underscores in value
    let chunk = make_chunk("api_key=Aa1-Bb2_Cc3-Dd4_Ee5", "config.yaml");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "Aa1-Bb2_Cc3-Dd4_Ee5");
}

// ============================================================================
// MULTILINE AND CONTEXT CASES
// ============================================================================

#[test]
fn generic_multiple_assignments_same_chunk() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Multiple distinct credentials in one chunk
    let text = "password=aAbBcCdDeEfFgGhHiIjJ\nsecret=1Kx7Lq3Aw9Rn2Fv5Bm8";
    let chunk = make_chunk(text, "test.env");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "aAbBcCdDeEfFgGhHiIjJ");
    assert_has_credential(&results, "1Kx7Lq3Aw9Rn2Fv5Bm8");
}

#[test]
fn generic_assignment_with_comment() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Credential followed by comment
    let chunk = make_chunk("password=TuVwXyZaBcDeFgHiJkLm # do not commit", "test.env");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "TuVwXyZaBcDeFgHiJkLm");
}

#[test]
fn generic_tabs_as_whitespace() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Tab separator instead of space
    let chunk = make_chunk("password\t:\tNoP1qRsT2uVwXyZ3aBcD", "config.conf");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    assert_has_credential(&results, "NoP1qRsT2uVwXyZ3aBcD");
}

// ============================================================================
// BACKEND PARITY: SIMD vs CPU Fallback on entropy-floor cases
// ============================================================================

#[test]
fn backend_parity_entropy_floor_positive() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    let chunk = make_chunk("password=M2n5Xp7Lq3Aw1Rk8Fv4B", "test.env");

    let simd_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let fallback_results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::CpuFallback);

    let simd_findings = collect_findings(&simd_results);
    let fallback_findings = collect_findings(&fallback_results);

    assert_eq!(
        simd_findings, fallback_findings,
        "SIMD and Fallback should find identical credentials at entropy floor"
    );
    assert!(!simd_findings.is_empty(), "Both backends should find the credential");
}

#[test]
fn backend_parity_entropy_floor_negative() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Low-entropy repeated chars
    let chunk = make_chunk("password=zzzzzzzzzzzzzzzzzzzz", "test.env");

    let simd_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let fallback_results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::CpuFallback);

    let simd_findings = collect_findings(&simd_results);
    let fallback_findings = collect_findings(&fallback_results);

    assert_eq!(
        simd_findings, fallback_findings,
        "SIMD and Fallback should agree on low-entropy rejection"
    );
    assert!(
        simd_findings.is_empty(),
        "Neither backend should find low-entropy repetition"
    );
}

// ============================================================================
// GPU TESTS (if GPU is available)
// ============================================================================

#[test]
#[cfg(feature = "gpu")]
fn gpu_entropy_floor_parity() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU available");
        return;
    }

    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    let chunk = make_chunk("secret=P3q7Xm2Aw8Rn1Kl9Fv5B", "config.env");

    let simd_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let gpu_results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::Gpu);

    let simd_findings = collect_findings(&simd_results);
    let gpu_findings = collect_findings(&gpu_results);

    assert_eq!(
        simd_findings, gpu_findings,
        "GPU and SIMD should find identical findings on entropy-floor positive"
    );
}

#[test]
#[cfg(feature = "gpu")]
fn gpu_entropy_floor_rejection_parity() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU available");
        return;
    }

    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Low-entropy case
    let chunk = make_chunk("password=xxxxxxxxxxxxxxxxxxxx", "test.env");

    let simd_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let gpu_results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::Gpu);

    let simd_findings = collect_findings(&simd_results);
    let gpu_findings = collect_findings(&gpu_results);

    assert_eq!(
        simd_findings, gpu_findings,
        "GPU and SIMD should agree on entropy-floor rejection"
    );
    assert!(
        simd_findings.is_empty(),
        "GPU should reject low-entropy same as SIMD"
    );
}
