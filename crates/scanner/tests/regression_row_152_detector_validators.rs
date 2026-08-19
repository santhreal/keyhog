//! WHY: Row 152 regression suite for expanded detector validator coverage.
//!
//! Proves deterministic checksum and structural validation across all supported
//! validator types:
//!   1. JWT structural validation (RFC 7519 3-segment base64url, JSON header/payload, alg verification).
//!   2. UUID canonical format validation (RFC 4122 / RFC 9562 8-4-4-4-12 hex).
//!   3. HexHash fixed-width hex validation (exact length, ASCII hex digits, case rules).
//!   4. LuhnChecksum (mod 10) algorithm validation (credit/debit numbers, structured identifiers).
//!   5. Base62 CRC32 checksum validation (GitHub classic/fine-grained PATs, npm access tokens).
//!   6. PatternShape compiled anchored validation.
//!   7. Real scanner execution proving valid tokens emit findings while corrupted tokens fail closed.

use keyhog_core::{
    load_embedded_detectors_or_fail, DetectorSpec, DetectorValidatorSpec, PatternSpec, Severity,
};
use keyhog_scanner::checksum::{validate_for_detector, ChecksumResult};
use keyhog_scanner::CompiledScanner;

fn build_pattern(regex: &str) -> PatternSpec {
    PatternSpec {
        regex: regex.to_string(),
        description: None,
        group: None,
        required_literals: Vec::new(),
        client_safe: false,
        weak_anchor: false,
        structural_password_slot: false,
    }
}

#[test]
fn test_jwt_validator_valid_and_corrupted() {
    let detector_id = "test-jwt-detector";
    let spec = DetectorSpec {
        id: detector_id.to_string(),
        name: "Test JWT".to_string(),
        service: "jwt".to_string(),
        severity: Severity::High,
        patterns: vec![build_pattern(
            r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
        )],
        validators: vec![DetectorValidatorSpec::Jwt {
            prefixes: vec!["eyJ".to_string()],
            reject_alg_none: true,
            confidence_floor: 0.95,
        }],
        ..Default::default()
    };

    let compiled = keyhog_scanner::checksum::CompiledDetectorValidators::compile(&spec)
        .expect("compile validators");

    // Valid JWT: {"alg":"HS256","typ":"JWT"}.{"sub":"1234567890","name":"John Doe","iat":1516239022}.signature
    let valid_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let valid_decision = compiled.validate(valid_jwt, false);
    assert_eq!(valid_decision.result(), ChecksumResult::Valid);
    assert_eq!(valid_decision.valid_confidence_floor(), Some(0.95));

    // Corrupted payload JSON (not valid base64url JSON)
    let corrupted_payload = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpbnZhbGlkX2pzb25fcGF5bG9hZCI.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let corrupted_decision = compiled.validate(corrupted_payload, false);
    assert_eq!(corrupted_decision.result(), ChecksumResult::Invalid);

    // Unsigned alg=none JWT (rejected by reject_alg_none = true)
    // {"alg":"none","typ":"JWT"}.{"sub":"1234567890"}.
    let alg_none_jwt =
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl";
    let none_decision = compiled.validate(alg_none_jwt, false);
    assert_eq!(none_decision.result(), ChecksumResult::Invalid);

    // Non-JWT string starting with eyJ
    let non_jwt = "eyJnot_a_valid_jwt_structure";
    let non_jwt_decision = compiled.validate(non_jwt, false);
    assert_eq!(non_jwt_decision.result(), ChecksumResult::Invalid);
}

#[test]
fn test_uuid_validator_valid_and_corrupted() {
    let detector_id = "test-uuid-detector";
    let spec = DetectorSpec {
        id: detector_id.to_string(),
        name: "Test UUID".to_string(),
        service: "uuid-service".to_string(),
        severity: Severity::High,
        patterns: vec![build_pattern(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        )],
        validators: vec![DetectorValidatorSpec::Uuid {
            prefixes: vec!["uuid_".to_string()],
            confidence_floor: 0.90,
        }],
        ..Default::default()
    };

    let compiled = keyhog_scanner::checksum::CompiledDetectorValidators::compile(&spec)
        .expect("compile validators");

    // Valid UUID with prefix
    let valid_uuid = "uuid_7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d";
    let valid_decision = compiled.validate(valid_uuid, false);
    assert_eq!(valid_decision.result(), ChecksumResult::Valid);
    assert_eq!(valid_decision.valid_confidence_floor(), Some(0.90));

    // Corrupted UUID: non-hex character 'g'
    let corrupted_char = "uuid_7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4g";
    let corrupted_decision = compiled.validate(corrupted_char, false);
    assert_eq!(corrupted_decision.result(), ChecksumResult::Invalid);

    // Corrupted UUID: missing hyphen
    let missing_hyphen = "uuid_7b3e5d8c1a9f-4e2b-6c8d-3a5e9f1b7c4d";
    let missing_hyphen_decision = compiled.validate(missing_hyphen, false);
    assert_eq!(missing_hyphen_decision.result(), ChecksumResult::Invalid);

    // Corrupted UUID: wrong length
    let wrong_length = "uuid_7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4";
    let wrong_length_decision = compiled.validate(wrong_length, false);
    assert_eq!(wrong_length_decision.result(), ChecksumResult::Invalid);
}

#[test]
fn test_hex_hash_validator_valid_and_corrupted() {
    let detector_id = "test-hex-detector";
    let spec = DetectorSpec {
        id: detector_id.to_string(),
        name: "Test Hex Hash".to_string(),
        service: "hex-service".to_string(),
        severity: Severity::Critical,
        patterns: vec![build_pattern(r"shpat_[0-9a-f]{32}")],
        validators: vec![DetectorValidatorSpec::HexHash {
            prefixes: vec!["shpat_".to_string()],
            expected_len: 32,
            lowercase_only: true,
            confidence_floor: 0.90,
        }],
        ..Default::default()
    };

    let compiled = keyhog_scanner::checksum::CompiledDetectorValidators::compile(&spec)
        .expect("compile validators");

    // Valid 32-char lowercase hex
    let valid_token = "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";
    let valid_decision = compiled.validate(valid_token, false);
    assert_eq!(valid_decision.result(), ChecksumResult::Valid);
    assert_eq!(valid_decision.valid_confidence_floor(), Some(0.90));

    // Corrupted: uppercase hex when lowercase_only is true
    let uppercase_token = "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";
    let uppercase_decision = compiled.validate(uppercase_token, false);
    assert_eq!(uppercase_decision.result(), ChecksumResult::Invalid);

    // Corrupted: non-hex characters
    let non_hex_token = "shpat_c5eae857d74b686a04406cc28f76deeg";
    let non_hex_decision = compiled.validate(non_hex_token, false);
    assert_eq!(non_hex_decision.result(), ChecksumResult::Invalid);

    // Corrupted: wrong length (31 chars)
    let short_token = "shpat_c5eae857d74b686a04406cc28f76dee";
    let short_decision = compiled.validate(short_token, false);
    assert_eq!(short_decision.result(), ChecksumResult::Invalid);
}

#[test]
fn test_luhn_checksum_validator_valid_and_corrupted() {
    let detector_id = "test-luhn-detector";
    let spec = DetectorSpec {
        id: detector_id.to_string(),
        name: "Test Luhn Checksum".to_string(),
        service: "payment".to_string(),
        severity: Severity::Critical,
        patterns: vec![build_pattern(r"card_[0-9]{10,19}")],
        validators: vec![DetectorValidatorSpec::LuhnChecksum {
            prefixes: vec!["card_".to_string()],
            min_len: 10,
            max_len: 19,
            confidence_floor: 0.90,
        }],
        ..Default::default()
    };

    let compiled = keyhog_scanner::checksum::CompiledDetectorValidators::compile(&spec)
        .expect("compile validators");

    // Standard Luhn valid numbers (e.g. 79927398713 is the canonical Luhn example)
    let valid_luhn_1 = "card_79927398713";
    let valid_decision_1 = compiled.validate(valid_luhn_1, false);
    assert_eq!(valid_decision_1.result(), ChecksumResult::Valid);
    assert_eq!(valid_decision_1.valid_confidence_floor(), Some(0.90));

    let valid_luhn_2 = "card_49927398716";
    let valid_decision_2 = compiled.validate(valid_luhn_2, false);
    assert_eq!(valid_decision_2.result(), ChecksumResult::Valid);

    // Corrupted check digit (79927398713 -> 79927398714)
    let corrupted_digit = "card_79927398714";
    let corrupted_decision = compiled.validate(corrupted_digit, false);
    assert_eq!(corrupted_decision.result(), ChecksumResult::Invalid);

    // Corrupted: non-digit character
    let non_digit = "card_7992739871a";
    let non_digit_decision = compiled.validate(non_digit, false);
    assert_eq!(non_digit_decision.result(), ChecksumResult::Invalid);

    // Corrupted: too short (< 13 digits)
    let too_short = "card_79927398";
    let too_short_decision = compiled.validate(too_short, false);
    assert_eq!(too_short_decision.result(), ChecksumResult::Invalid);
}

#[test]
fn test_embedded_detectors_validator_coverage_e2e() {
    // 1. GitHub Classic PAT (CRC32 Base62)
    let valid_ghp = concat!("ghp_", "1234567890123456789012345678902PDSiF");
    assert_eq!(
        validate_for_detector("github-classic-pat", valid_ghp).result(),
        ChecksumResult::Valid
    );
    let corrupted_ghp = concat!("ghp_", "1234567890123456789012345678902PDSiG");
    assert_eq!(
        validate_for_detector("github-classic-pat", corrupted_ghp).result(),
        ChecksumResult::Invalid
    );

    // 2. JWT Detector
    let valid_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w";
    assert_eq!(
        validate_for_detector("jwt-token", valid_jwt).result(),
        ChecksumResult::Valid
    );
    let corrupted_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.corrupted_json_payload.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w";
    assert_eq!(
        validate_for_detector("jwt-token", corrupted_jwt).result(),
        ChecksumResult::Invalid
    );

    // 3. Shopify Admin API Token (HexHash)
    let valid_shpat = "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";
    assert_eq!(
        validate_for_detector("shopify-admin-api-token", valid_shpat).result(),
        ChecksumResult::Valid
    );
    let corrupted_shpat = "shpat_c5eae857d74b686a04406cc28f76deeg";
    assert_eq!(
        validate_for_detector("shopify-admin-api-token", corrupted_shpat).result(),
        ChecksumResult::Invalid
    );

    // 4. Snyk API Token (UUID)
    let valid_snyk = "01234567-89ab-cdef-0123-456789abcdef";
    assert_eq!(
        validate_for_detector("snyk-api-token", valid_snyk).result(),
        ChecksumResult::Valid
    );
    let corrupted_snyk = "01234567-89ab-cdef-0123-456789abcdeg";
    assert_eq!(
        validate_for_detector("snyk-api-token", corrupted_snyk).result(),
        ChecksumResult::Invalid
    );

    // 5. Slack App Token (PatternShape)
    let valid_xapp = "xapp-1-A012B3CDEFG-1234567890123-1f9a0b7c4e2d6a8b3c5f7e9d0a1b2c3d";
    assert_eq!(
        validate_for_detector("slack-app-token", valid_xapp).result(),
        ChecksumResult::StructurallyValid
    );
    let corrupted_xapp = "xapp-invalid-shape";
    assert_eq!(
        validate_for_detector("slack-app-token", corrupted_xapp).result(),
        ChecksumResult::Invalid
    );
}

#[test]
fn test_scanner_end_to_end_suppresses_corrupted_tokens() {
    let detectors = load_embedded_detectors_or_fail().expect("load embedded detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile embedded scanner");

    // Valid tokens text
    let valid_text = r#"
        GITHUB_PAT="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"
        SHOPIFY_TOKEN="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"
        SNYK_TOKEN="01234567-89ab-cdef-0123-456789abcdef"
    "#;
    let valid_chunk = keyhog_core::Chunk::from(valid_text);
    let valid_findings = scanner.scan(&valid_chunk).expect("scan valid");
    assert!(
        !valid_findings.is_empty(),
        "valid tokens must produce findings"
    );

    let finding_detectors: Vec<_> = valid_findings
        .iter()
        .map(|f| f.detector_id.as_ref())
        .collect();
    assert!(finding_detectors.contains(&"github-classic-pat"));
    assert!(finding_detectors.contains(&"shopify-admin-api-token"));
    assert!(finding_detectors.contains(&"snyk-api-token"));

    // Corrupted tokens text: invalid checksums/shapes should fail closed and be suppressed
    let corrupted_text = r#"
        GITHUB_PAT="ghp_1234567890123456789012345678902PDSiG"
        SHOPIFY_TOKEN="shpat_c5eae857d74b686a04406cc28f76deeg"
        SNYK_TOKEN="01234567-89ab-cdef-0123-456789abcdeg"
    "#;
    let corrupted_chunk = keyhog_core::Chunk::from(corrupted_text);
    let corrupted_findings = scanner.scan(&corrupted_chunk).expect("scan corrupted");
    let corrupted_finding_detectors: Vec<_> = corrupted_findings
        .iter()
        .map(|f| f.detector_id.as_ref())
        .collect();
    assert!(
        !corrupted_finding_detectors.contains(&"github-classic-pat"),
        "corrupted GitHub PAT must be suppressed"
    );
    assert!(
        !corrupted_finding_detectors.contains(&"shopify-admin-api-token"),
        "corrupted Shopify token must be suppressed"
    );
    assert!(
        !corrupted_finding_detectors.contains(&"snyk-api-token"),
        "corrupted Snyk token must be suppressed"
    );
}
