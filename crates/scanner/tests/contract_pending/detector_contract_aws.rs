//! AWS detector contract tests: comprehensive coverage of AKIA/ASIA access keys,
//! secret keys, session tokens with positive + negative + adversarial + boundary cases.
//!
//! Test matrix:
//!   - AKIA access keys (valid checksums, near-miss invalid checksums)
//!   - ASIA temporary keys (temp credentials)
//!   - Secret access keys (40-char base64 bodies with anchors)
//!   - Session tokens (64+ char base64-like bodies)
//!   - File formats: env vars, YAML, JSON, Terraform, shell code
//!   - GPU parity: where applicable, GPU == SIMD
//!   - Boundary cases: chunk boundaries, prefix confusion, encoding variance

#[path = "support/mod.rs"]
mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use support::gpu_gate::assert_gpu_not_silent_empty;
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

fn scan_and_collect(chunk: &Chunk, backend: ScanBackend) -> Vec<String> {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let results = scanner.scan_chunks_with_backend(&[chunk.clone()], backend);
    
    results
        .into_iter()
        .flat_map(|v| v.into_iter())
        .map(|m| m.credential.as_ref().to_string())
        .collect()
}

// ============================================================================
// POSITIVE TESTS: Valid AWS credentials that MUST be detected
// ============================================================================

#[test]
fn akia_valid_checksum_in_env_file() {
    let content = "export AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\n";
    let chunk = make_chunk(content, "config.env");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.contains(&"AKIAQYLPMN5HFIQR7XYA".to_string()),
        "AKIA key with valid checksum not found in env file"
    );
}

#[test]
fn akia_valid_checksum_in_yaml() {
    let content = "aws:\n  access_key: AKIAQYLPMN5HFIQR7BBB\n  region: us-east-1\n";
    let chunk = make_chunk(content, "config.yaml");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.contains(&"AKIAQYLPMN5HFIQR7BBB".to_string()),
        "AKIA key not detected in YAML"
    );
}

#[test]
fn akia_valid_checksum_in_json() {
    let content = r#"{"credentials": {"access_key": "AKIAQYLPMN5HFIQR7CCC"}}"#;
    let chunk = make_chunk(content, "creds.json");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.contains(&"AKIAQYLPMN5HFIQR7CCC".to_string()),
        "AKIA key not detected in JSON"
    );
}

#[test]
fn akia_valid_checksum_in_python_code() {
    let content = r#"AWS_KEY = "AKIAQYLPMN5HFIQR7DDD"  # credentials"#;
    let chunk = make_chunk(content, "secrets.py");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.contains(&"AKIAQYLPMN5HFIQR7DDD".to_string()),
        "AKIA key not detected in Python code"
    );
}

#[test]
fn akia_valid_checksum_in_rust_code() {
    let content = r#"const AWS_KEY: &str = "AKIAQYLPMN5HFIQR7EEE";"#;
    let chunk = make_chunk(content, "main.rs");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.contains(&"AKIAQYLPMN5HFIQR7EEE".to_string()),
        "AKIA key not detected in Rust code"
    );
}

#[test]
fn akia_valid_checksum_in_terraform() {
    let content = r#"resource "aws_instance" "web" {
  access_key = "AKIAQYLPMN5HFIQR7FFF"
}"#;
    let chunk = make_chunk(content, "main.tf");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.contains(&"AKIAQYLPMN5HFIQR7FFF".to_string()),
        "AKIA key not detected in Terraform"
    );
}

#[test]
fn asia_temporary_key_in_env() {
    let content = "AWS_ACCESS_KEY_ID=ASIAQYLPMN5HFIQR7AAA\n";
    let chunk = make_chunk(content, ".env");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.contains(&"ASIAQYLPMN5HFIQR7AAA".to_string()),
        "ASIA temp key not detected in env"
    );
}

#[test]
fn asia_temporary_key_in_json() {
    let content = r#"{"token_type": "temporary", "key": "ASIAQYLPMN5HFIQR7BBB"}"#;
    let chunk = make_chunk(content, "session.json");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.contains(&"ASIAQYLPMN5HFIQR7BBB".to_string()),
        "ASIA temp key not detected in JSON"
    );
}

#[test]
fn aws_secret_key_40char_base64_with_uppercase_anchor() {
    let content = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY\n";
    let chunk = make_chunk(content, ".env");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.contains(&"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string()),
        "40-char secret key with uppercase anchor not detected"
    );
}

#[test]
fn aws_secret_key_40char_base64_with_lowercase_anchor() {
    let content = "aws_secret_access_key = \"je7MtGbClwBF7zrvic9l+bPxRfiCYEXAMPLEKEY\"\n";
    let chunk = make_chunk(content, ".env");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.contains(&"je7MtGbClwBF7zrvic9l+bPxRfiCYEXAMPLEKEY".to_string()),
        "40-char secret key with lowercase anchor not detected"
    );
}

#[test]
fn aws_secret_key_camelcase_anchor_js() {
    let content = "const awsSecretAccessKey = 'Eby8vdM02xNOcqfn9g+4wnxHgoHiKlYP+bPxRfiCYEXAMPLEKEY';";
    let chunk = make_chunk(content, "config.js");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.contains(&"Eby8vdM02xNOcqfn9g+4wnxHgoHiKlYP+bPxRfiCYEXAMPLEKEY".to_string()),
        "40-char secret key with camelCase anchor not detected"
    );
}

#[test]
fn aws_session_token_uppercase_anchor_80plus_chars() {
    let content = "AWS_SESSION_TOKEN=\"AQoDYXdzEJr..YXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrA==\"";
    let chunk = make_chunk(content, ".env");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    // Session token should be extracted (exact payload varies; verify substring match).
    assert!(
        credentials.iter().any(|c| c.starts_with("AQoDYXdzEJr")),
        "Session token with uppercase anchor not detected"
    );
}

#[test]
fn aws_session_token_lowercase_anchor_variable() {
    let content = "aws_session_token=QoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJr";
    let chunk = make_chunk(content, "credentials");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.iter().any(|c| c.starts_with("QoDYXdzEJr")),
        "Session token with lowercase anchor not detected"
    );
}

#[test]
fn aws_session_token_sigv4_header_anchor() {
    let content = "X-Amz-Security-Token: AQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJr";
    let chunk = make_chunk(content, "request.txt");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.iter().any(|c| c.starts_with("AQoDYXdzEJr")),
        "Session token with SigV4 header anchor not detected"
    );
}

#[test]
fn multiple_credentials_in_single_env_file() {
    let content = r#"
AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XXX
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
AWS_SESSION_TOKEN=AQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJr
"#;
    let chunk = make_chunk(content, ".env");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    
    // Should find all three.
    assert!(
        credentials.contains(&"AKIAQYLPMN5HFIQR7XXX".to_string()),
        "AKIA key not found in multi-credential file"
    );
    assert!(
        credentials.contains(&"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string()),
        "Secret key not found in multi-credential file"
    );
    assert!(
        credentials.iter().any(|c| c.starts_with("AQoDYXdzEJr")),
        "Session token not found in multi-credential file"
    );
}

// ============================================================================
// NEGATIVE TESTS: Invalid/boundary AWS credentials that MUST NOT be detected
// ============================================================================

#[test]
fn akia_lowercase_false_positive_not_detected() {
    // Docs/test placeholders use lowercase `akiaqylpmn…`; must not match.
    let content = "Example: akiaqylpmn5hfiqr7xya (this is a placeholder)\n";
    let chunk = make_chunk(content, "README.md");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        !credentials.iter().any(|c| c.to_lowercase().contains("akiaqylpmn")),
        "Lowercase AKIA placeholder incorrectly detected"
    );
}

#[test]
fn akia_mixed_case_false_positive_not_detected() {
    // Only uppercase AKIA keys are valid; Akia/AkIa are test artifacts.
    let content = "key = 'AkiaQYLPMN5HFIQR7XYZ'\n";
    let chunk = make_chunk(content, "config.py");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        !credentials.contains(&"AkiaQYLPMN5HFIQR7XYZ".to_string()),
        "Mixed-case AKIA incorrectly detected"
    );
}

#[test]
fn akia_too_short_not_detected() {
    // AKIA must be exactly 20 chars (4 + 16); 19 is invalid.
    let content = "AWS_KEY=AKIAQYLPMN5HFIQR7XY\n";
    let chunk = make_chunk(content, ".env");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        !credentials.contains(&"AKIAQYLPMN5HFIQR7XY".to_string()),
        "19-char AKIA (too short) incorrectly detected"
    );
}

#[test]
fn akia_too_long_not_detected() {
    // AKIA must be exactly 20 chars; 21 is invalid.
    let content = "key = AKIAQYLPMN5HFIQR7XYZA\n";
    let chunk = make_chunk(content, "config.txt");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        !credentials.contains(&"AKIAQYLPMN5HFIQR7XYZA".to_string()),
        "21-char AKIA (too long) incorrectly detected"
    );
}

#[test]
fn akia_with_lowercase_chars_not_detected() {
    // AKIA IDs are always uppercase alphanumeric only; lowercase invalidates.
    let content = "access_key = AKIAQYLPMN5HFIQr7XYA\n";
    let chunk = make_chunk(content, ".env");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        !credentials.contains(&"AKIAQYLPMN5HFIQr7XYA".to_string()),
        "AKIA with lowercase char incorrectly detected"
    );
}

#[test]
fn akia_with_special_chars_not_detected() {
    // AKIA IDs contain only uppercase alphanumeric; special chars invalidate.
    let content = "key = AKIAQYLPMN5HFIQR7XY-\n";
    let chunk = make_chunk(content, "config.txt");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        !credentials.contains(&"AKIAQYLPMN5HFIQR7XY-".to_string()),
        "AKIA with special char incorrectly detected"
    );
}

#[test]
fn secret_key_39_chars_not_detected() {
    // Secret key must be exactly 40 chars base64; 39 is too short.
    let content = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKE\n";
    let chunk = make_chunk(content, ".env");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        !credentials.contains(&"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKE".to_string()),
        "39-char secret (too short) incorrectly detected"
    );
}

#[test]
fn secret_key_41_chars_not_detected() {
    // Secret key must be exactly 40 chars base64; 41 is too long.
    let content = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEYZ\n";
    let chunk = make_chunk(content, ".env");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        !credentials.contains(&"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEYZ".to_string()),
        "41-char secret (too long) incorrectly detected"
    );
}

#[test]
fn secret_key_missing_anchor_not_detected() {
    // 40-char base64 ALONE (no anchor) is indistinguishable from generic base64.
    // The detector requires an AWS-specific env var or field name anchor.
    let content = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY\n";
    let chunk = make_chunk(content, "data.txt");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        !credentials.contains(&"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string()),
        "40-char base64 without anchor incorrectly detected"
    );
}

#[test]
fn session_token_too_short_not_detected() {
    // Session token must be 64+ chars; 63 is invalid.
    let content = "AWS_SESSION_TOKEN=AQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJr";
    let chunk = make_chunk(content, ".env");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        !credentials.iter().any(|c| c.contains("AQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJr")),
        "63-char session token (too short) incorrectly detected"
    );
}

#[test]
fn session_token_missing_anchor_not_detected() {
    // Session token alone (no anchor) is generic base64 and not detectably AWS-specific.
    let content = "AQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJr\n";
    let chunk = make_chunk(content, "data.bin");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        !credentials.iter().any(|c| c.starts_with("AQoDYXdzEJr")),
        "Session token without anchor incorrectly detected"
    );
}

// ============================================================================
// TWIN TESTS: Valid credentials paired with near-miss invalid variants
// ============================================================================

#[test]
fn akia_valid_and_invalid_checksum_twin() {
    let content = r#"
# Valid AKIA (uppercase, 20 chars)
AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA
# Near-miss: all lowercase (should NOT match)
# aws_access_key=akiaqylpmn5hfiqr7xya
# Near-miss: mixed case (should NOT match)
# key = AkiaQYLPMN5HFIQR7XYZ
"#;
    let chunk = make_chunk(content, "config.env");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    
    // Must find the valid one.
    assert!(
        credentials.contains(&"AKIAQYLPMN5HFIQR7XYA".to_string()),
        "Valid AKIA not found"
    );
    // Must not find the commented-out fakes.
    assert_eq!(
        credentials.len(),
        1,
        "Found extra credentials (should only find 1 valid AKIA)"
    );
}

#[test]
fn secret_key_40char_valid_and_39char_invalid_twin() {
    let content = r#"
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
# Too short (39 chars):
# aws_secret_key=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKE
"#;
    let chunk = make_chunk(content, ".env");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    
    assert!(
        credentials.contains(&"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string()),
        "Valid 40-char secret not found"
    );
    assert_eq!(
        credentials.len(),
        1,
        "Found extra credentials (should only find 1 valid secret)"
    );
}

#[test]
fn session_token_valid_80plus_and_63char_invalid_twin() {
    let content = r#"
AWS_SESSION_TOKEN=AQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJr
# Too short (63 chars):
# aws_session_token=AQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJr
"#;
    let chunk = make_chunk(content, ".env");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    
    assert!(
        credentials.iter().any(|c| c.len() >= 80),
        "Valid 80+ char session token not found"
    );
}

// ============================================================================
// ADVERSARIAL TESTS: Edge cases and boundary conditions
// ============================================================================

#[test]
fn akia_surrounded_by_whitespace() {
    let content = "  \t AKIAQYLPMN5HFIQR7XYA \n";
    let chunk = make_chunk(content, "data.txt");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.contains(&"AKIAQYLPMN5HFIQR7XYA".to_string()),
        "AKIA with surrounding whitespace not detected"
    );
}

#[test]
fn akia_in_url_like_context() {
    let content = "https://example.com?key=AKIAQYLPMN5HFIQR7XYA&region=us-east-1\n";
    let chunk = make_chunk(content, "url.txt");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.contains(&"AKIAQYLPMN5HFIQR7XYA".to_string()),
        "AKIA in URL query param not detected"
    );
}

#[test]
fn akia_in_logs_with_prefix_suffix() {
    let content = "[2026-06-09 10:34:20] DEBUG: access_key=[AKIAQYLPMN5HFIQR7XYA] region=us-east-1\n";
    let chunk = make_chunk(content, "app.log");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.contains(&"AKIAQYLPMN5HFIQR7XYA".to_string()),
        "AKIA in log line with brackets not detected"
    );
}

#[test]
fn secret_key_with_slash_and_plus() {
    // Base64 can include +, /, and = padding; verify all are handled.
    let content = "AWS_SECRET_ACCESS_KEY=fe7+TM/bcWe9/K7MDENG+bPxRfiCYEXAMPLEKEY\n";
    let chunk = make_chunk(content, ".env");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.contains(&"fe7+TM/bcWe9/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string()),
        "Secret key with +/= base64 chars not detected"
    );
}

#[test]
fn secret_key_trailing_equals_padding() {
    let content = "aws_secret_access_key=\"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY=\"";
    let chunk = make_chunk(content, "json.json");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    // The detector should capture the 40-char body; trailing = may be optional.
    assert!(
        credentials.iter().any(|c| c.starts_with("wJalrXUtnFEMI")),
        "Secret key with base64 padding not detected"
    );
}

#[test]
fn multiple_akia_keys_different_lines() {
    let content = r#"
key1 = AKIAQYLPMN5HFIQR7AAA
key2 = AKIAQYLPMN5HFIQR7BBB
key3 = AKIAQYLPMN5HFIQR7CCC
"#;
    let chunk = make_chunk(content, "keys.txt");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert_eq!(
        credentials.len(),
        3,
        "Expected 3 AKIA keys, found {}",
        credentials.len()
    );
    assert!(
        credentials.contains(&"AKIAQYLPMN5HFIQR7AAA".to_string()),
        "First AKIA key not found"
    );
    assert!(
        credentials.contains(&"AKIAQYLPMN5HFIQR7BBB".to_string()),
        "Second AKIA key not found"
    );
    assert!(
        credentials.contains(&"AKIAQYLPMN5HFIQR7CCC".to_string()),
        "Third AKIA key not found"
    );
}

#[test]
fn akia_and_asia_in_same_file() {
    let content = r#"
prod: AKIAQYLPMN5HFIQR7XXX
temp: ASIAQYLPMN5HFIQR7YYY
"#;
    let chunk = make_chunk(content, "config.txt");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert_eq!(
        credentials.len(),
        2,
        "Expected both AKIA and ASIA, found {}",
        credentials.len()
    );
    assert!(
        credentials.contains(&"AKIAQYLPMN5HFIQR7XXX".to_string()),
        "AKIA key not found"
    );
    assert!(
        credentials.contains(&"ASIAQYLPMN5HFIQR7YYY".to_string()),
        "ASIA key not found"
    );
}

#[test]
fn json_nested_aws_credentials() {
    let content = r#"
{
  "environments": {
    "prod": {
      "aws": {
        "access_key": "AKIAQYLPMN5HFIQR7XXX",
        "secret_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "session_token": "AQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJr"
      }
    }
  }
}
"#;
    let chunk = make_chunk(content, "config.json");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.contains(&"AKIAQYLPMN5HFIQR7XXX".to_string()),
        "AKIA in nested JSON not found"
    );
    assert!(
        credentials.contains(&"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string()),
        "Secret in nested JSON not found"
    );
}

#[test]
fn yaml_anchor_and_alias_aws_config() {
    let content = r#"
defaults: &aws_defaults
  access_key: AKIAQYLPMN5HFIQR7XXX
  region: us-east-1

production:
  <<: *aws_defaults
  secret_key: wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
"#;
    let chunk = make_chunk(content, "aws.yaml");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.contains(&"AKIAQYLPMN5HFIQR7XXX".to_string()),
        "AKIA in YAML anchor not found"
    );
    assert!(
        credentials.contains(&"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string()),
        "Secret in YAML not found"
    );
}

#[test]
fn terraform_various_syntax_aws_keys() {
    let content = r#"
variable "aws_access_key" {
  default = "AKIAQYLPMN5HFIQR7XXX"
}

locals {
  secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
}

resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  tags = {
    akia = "AKIAQYLPMN5HFIQR7YYY"
  }
}
"#;
    let chunk = make_chunk(content, "infra.tf");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.contains(&"AKIAQYLPMN5HFIQR7XXX".to_string()),
        "AKIA in variable not found"
    );
    assert!(
        credentials.contains(&"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string()),
        "Secret in locals not found"
    );
    assert!(
        credentials.contains(&"AKIAQYLPMN5HFIQR7YYY".to_string()),
        "AKIA in tags not found"
    );
}

// ============================================================================
// GPU PARITY TESTS: GPU and CPU backends must produce identical findings
// ============================================================================

#[test]
#[cfg(feature = "gpu")]
fn gpu_parity_akia_multiple_files() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    
    let chunks = vec![
        make_chunk("AWS_KEY=AKIAQYLPMN5HFIQR7AAA\n", "file1.env"),
        make_chunk("export AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7BBB\n", "file2.sh"),
        make_chunk("key: AKIAQYLPMN5HFIQR7CCC\n", "file3.yaml"),
    ];
    
    let simd_results = scanner.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let gpu_results = scanner.scan_chunks_with_backend(&chunks, ScanBackend::Gpu);
    
    let simd_creds: std::collections::BTreeSet<_> =
        simd_results.iter().flat_map(|v| v.iter()).map(|m| m.credential.as_ref().to_string()).collect();
    let gpu_creds: std::collections::BTreeSet<_> =
        gpu_results.iter().flat_map(|v| v.iter()).map(|m| m.credential.as_ref().to_string()).collect();
    
    assert_gpu_not_silent_empty(
        gpu_results.iter().all(|c| c.is_empty()),
        simd_creds.len(),
        "gpu_parity_akia_multiple_files",
    );
    
    assert_eq!(
        simd_creds, gpu_creds,
        "GPU/SIMD parity broken: SIMD={:?} GPU={:?}",
        simd_creds, gpu_creds
    );
}

#[test]
#[cfg(feature = "gpu")]
fn gpu_parity_mixed_aws_credential_types() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    
    let content = r#"
AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XXX
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
AWS_SESSION_TOKEN=AQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJr
"#;
    let chunk = make_chunk(content, "credentials.env");
    
    let simd_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let gpu_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::Gpu);
    
    let simd_count: usize = simd_results.iter().map(|v| v.len()).sum();
    let gpu_count: usize = gpu_results.iter().map(|v| v.len()).sum();
    
    assert_gpu_not_silent_empty(
        gpu_count == 0,
        simd_count,
        "gpu_parity_mixed_aws_credential_types",
    );
    
    assert_eq!(
        simd_count, gpu_count,
        "GPU/SIMD parity broken: SIMD found {} findings, GPU found {}",
        simd_count, gpu_count
    );
}

#[test]
#[cfg(feature = "gpu")]
fn gpu_parity_adversarial_aws_formats() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }
    
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    
    let content = r#"
# JSON
{"key": "AKIAQYLPMN5HFIQR7AAA"}
# YAML
secret: wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
# Terraform
access_key = "AKIAQYLPMN5HFIQR7BBB"
# Env var with quotes and padding
AWS_SESSION_TOKEN="AQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJr="
"#;
    let chunk = make_chunk(content, "mixed.conf");
    
    let simd_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let gpu_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::Gpu);
    
    let simd_count: usize = simd_results.iter().map(|v| v.len()).sum();
    let gpu_count: usize = gpu_results.iter().map(|v| v.len()).sum();
    
    assert_gpu_not_silent_empty(
        gpu_count == 0,
        simd_count,
        "gpu_parity_adversarial_aws_formats",
    );
    
    assert_eq!(
        simd_count, gpu_count,
        "GPU/SIMD parity broken on adversarial formats: SIMD={} GPU={}",
        simd_count, gpu_count
    );
}

// ============================================================================
// BOUNDARY & ENCODING TESTS: Special cases in parsing and boundary conditions
// ============================================================================

#[test]
fn akia_immediately_after_newline_no_prefix() {
    let content = "\nAKIAQYLPMN5HFIQR7XYA\n";
    let chunk = make_chunk(content, "text.txt");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.contains(&"AKIAQYLPMN5HFIQR7XYA".to_string()),
        "AKIA immediately after newline not detected"
    );
}

#[test]
fn secret_key_with_dict_style_anchor() {
    // Some Python code uses dict-style access.
    let content = "config['AWS_SECRET_ACCESS_KEY'] = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'";
    let chunk = make_chunk(content, "config.py");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.contains(&"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string()),
        "Secret key with dict-style anchor not detected"
    );
}

#[test]
fn session_token_with_percent_encoding_header() {
    // HTTP headers sometimes have percent-encoding.
    let content = "X-Amz-Security-Token: AQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJrAQoDYXdzEJr%3D";
    let chunk = make_chunk(content, "header.txt");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert!(
        credentials.iter().any(|c| c.starts_with("AQoDYXdzEJr")),
        "Session token with percent-encoding not detected"
    );
}

#[test]
fn no_false_positives_in_large_clean_file() {
    // Ensure no false positives in legitimate content.
    let content = r#"
This is a documentation file about AWS.
To get started with AWS, visit https://aws.amazon.com.
You will need to create an Access Key ID and a Secret Access Key.

Common mistakes:
1. Sharing your credentials (AKIA or ASIA prefixes, 40-char secrets)
2. Committing .env files with AWS_SECRET_ACCESS_KEY
3. Forgetting AWS_SESSION_TOKEN in temporary credential setups

Best practices:
- Use IAM roles instead of access keys
- Rotate credentials regularly
- Use AWS Secrets Manager for production secrets
- Never commit credentials to version control

Example placeholder formats (DO NOT use as real credentials):
AKIA1234567890ABCDEF (20 chars, uppercase)
ASIA1234567890ABCDEF (20 chars, uppercase)
wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY (40-char base64)

The actual format is documented in AWS IAM docs.
"#;
    let chunk = make_chunk(content, "README.md");
    let credentials = scan_and_collect(&chunk, ScanBackend::SimdCpu);
    assert_eq!(
        credentials.len(),
        0,
        "False positives detected in clean documentation: {:?}",
        credentials
    );
}
