use keyhog_scanner::confidence::is_sensitive_path;
use keyhog_scanner::entropy::*;
use keyhog_scanner::telemetry::{self, DogfoodEvent, ScanTelemetry};
use keyhog_scanner::testing::entropy_keywords::{is_candidate_plausible, is_secret_plausible};
use keyhog_scanner::testing::entropy_scanner::{
    candidate_plausibility_rejection_reason, credential_keyword_context,
};
use keyhog_scanner::testing::generic_entropy_floor_for_test;
use keyhog_scanner::testing::is_likely_innocuous_line_for_test as innocuous_line;
use std::sync::Arc;

fn find_secrets(
    text: &str,
    min_length: usize,
    context_lines: usize,
    entropy_threshold: f64,
) -> Vec<EntropyMatch> {
    let secret_keywords = vec![
        "API_KEY".to_string(),
        "DB_PASSWORD".to_string(),
        "SECRET".to_string(),
        "TOKEN".to_string(),
    ];
    let test_keywords = vec!["test".to_string()];
    let placeholder_keywords = vec![
        "placeholder".to_string(),
        "change_me".to_string(),
        "xxxx".to_string(),
    ];
    find_entropy_secrets(
        text,
        min_length,
        context_lines,
        entropy_threshold,
        &secret_keywords,
        &test_keywords,
        &placeholder_keywords,
    )
}

#[test]
fn entropy_constant_string() {
    assert!(shannon_entropy(b"aaaaaaaaaa") < 0.1);
}

#[test]
fn entropy_random_string() {
    // High entropy string (looks like an API key)
    let key = b"aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJ";
    assert!(shannon_entropy(key) > 4.0);
}

#[test]
fn entropy_hex_hash() {
    let hash = b"d41d8cd98f00b204e9800998ecf8427e";
    let e = shannon_entropy(hash);
    // Hex hashes have moderate entropy (only 16 possible chars)
    assert!(e > 3.0);
    assert!(e < 5.0);
}

#[test]
fn find_secrets_near_keywords() {
    let text = r#"
# Config
DATABASE_URL=postgres://localhost/mydb
API_KEY=aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL
DEBUG=true
"#;
    let matches = find_secrets(text, 16, 2, HIGH_ENTROPY_THRESHOLD);
    assert!(
        !matches.is_empty(),
        "should find high-entropy string near API_KEY"
    );
    assert_eq!(matches[0].value, "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL");
    // The matched value should be the API key content.
    assert!(
        matches.iter().any(|m| m.entropy > 4.0),
        "should have high entropy match"
    );
}

#[test]
fn skip_placeholders() {
    let text = r#"
API_KEY=YOUR_API_KEY_HERE
SECRET=change_me_placeholder
TOKEN=xxxxxxxxxxxxxxxxxxxx
"#;
    let matches = find_secrets(text, 16, 2, HIGH_ENTROPY_THRESHOLD);
    assert!(matches.is_empty());
}

#[test]
fn plausible_secret_filter() {
    assert!(!is_secret_plausible("https://example.com/api", &[]));
    assert!(!is_secret_plausible("/usr/local/bin/python", &[]));
    assert!(!is_secret_plausible("your_api_key_here", &[]));
    assert!(is_secret_plausible("aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJ", &[]));
}

#[test]
fn empty_secret_keyword_is_ignored_not_matched_at_every_offset() {
    let matches = find_entropy_secrets(
        "debug = not-a-secret\n",
        8,
        2,
        HIGH_ENTROPY_THRESHOLD,
        &["".to_string()],
        &[],
        &[],
    );

    assert!(matches.is_empty());
}

#[test]
fn empty_placeholder_keyword_is_ignored_not_a_panic_or_global_placeholder() {
    assert!(is_secret_plausible(
        "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJ",
        &["".to_string()]
    ));
}

#[test]
fn candidate_mode_skips_strict_secret_checks() {
    assert!(is_candidate_plausible("0123456789abcdef", &[]));
    assert!(!is_secret_plausible("0123456789abcdef", &[]));
}

#[test]
fn entropy_generation_rejection_stage_is_named() {
    let ctx = credential_keyword_context("api_key");
    // 32-hex is detector-owned key material for `api_key`; SHA-1 width is the
    // canonical digest negative that must still name this rejection stage.
    let canonical = "356a192b7913b04c54574d18c28d46e6395428ab";
    assert_eq!(
        candidate_plausibility_rejection_reason(
            canonical,
            shannon_entropy(canonical.as_bytes()),
            &ctx,
            &[],
        ),
        Some("entropy_canonical_non_secret_shape")
    );

    let low_entropy = "aaaaaaaaaaaaaaaa";
    assert_eq!(
        candidate_plausibility_rejection_reason(
            low_entropy,
            shannon_entropy(low_entropy.as_bytes()),
            &ctx,
            &[],
        ),
        Some("entropy_below_floor")
    );
}

#[test]
fn structured_dotted_shape_does_not_bypass_entropy_floor() {
    let ctx = credential_keyword_context("api_key");
    let repeated_segments = format!("{}.{}.{}", "A".repeat(24), "B".repeat(7), "C".repeat(30));
    let entropy = shannon_entropy(repeated_segments.as_bytes());
    assert!(entropy < HIGH_ENTROPY_THRESHOLD);
    assert_eq!(
        candidate_plausibility_rejection_reason(&repeated_segments, entropy, &ctx, &[]),
        Some("entropy_below_floor"),
        "credential-shaped dots grant only a length allowance, never a low-entropy bypass"
    );
}

#[test]
fn generic_entropy_floor_uses_the_supplied_active_spec() {
    let custom = keyhog_core::DetectorSpec {
        id: "generic-custom".to_string(),
        entropy_high: Some(4.5),
        entropy_floor: vec![
            keyhog_core::EntropyFloorBucket {
                max_len: Some(12),
                floor: 1.25,
            },
            keyhog_core::EntropyFloorBucket {
                max_len: None,
                floor: 2.75,
            },
        ],
        ..Default::default()
    };

    assert_eq!(generic_entropy_floor_for_test(&custom, 4.5, 12), 1.25);
    assert_eq!(generic_entropy_floor_for_test(&custom, 4.5, 13), 2.75);
    assert_eq!(
        generic_entropy_floor_for_test(&custom, 6.0, 12),
        6.0,
        "a stricter Tier-A threshold composes above the active detector floor"
    );
}

#[test]
fn entropy_generation_rejection_is_dogfood_visible() {
    let _guard = super::telemetry_serial::lock();
    let low_entropy = "abc123ABCabc123ABC12";
    let secret_keywords = vec!["API_KEY".to_string()];
    let trace = Arc::new(ScanTelemetry::new());

    telemetry::testing::reset();
    trace.enable_dogfood();
    let _ = telemetry::with_scan_telemetry(&trace, || {
        find_entropy_secrets(
            &format!("API_KEY={low_entropy}\n"),
            8,
            0,
            HIGH_ENTROPY_THRESHOLD,
            &secret_keywords,
            &[],
            &[],
        )
    });
    let reasons: Vec<String> = trace
        .drain()
        .dogfood_events
        .into_iter()
        .filter_map(|event| match event {
            // canonical keyhog_core::redact keeps edge = (len/8).clamp(1,4)
            // bytes per side (02d6150d9/17f4f2084 capped short-secret exposure);
            // this 20-byte candidate redacts to "ab...12", so the prefix guard is
            // the canonical 2-byte edge, not the old fixed 4.
            DogfoodEvent::ShapeSuppressed {
                credential_redacted,
                reason,
                ..
            } if credential_redacted.starts_with("ab") => Some(reason.into_owned()),
            _ => None,
        })
        .collect();
    assert_eq!(reasons, vec!["entropy_secret_plausibility_rejected"]);

    telemetry::testing::reset();
    let trace = Arc::new(ScanTelemetry::new());
    let _ = telemetry::with_scan_telemetry(&trace, || {
        find_entropy_secrets(
            &format!("API_KEY={low_entropy}\n"),
            8,
            0,
            HIGH_ENTROPY_THRESHOLD,
            &secret_keywords,
            &[],
            &[],
        )
    });
    assert!(
        trace.drain().dogfood_events.is_empty(),
        "dogfood-off entropy generation rejection must not emit trace events"
    );
}

#[test]
fn isolated_bare_rejection_is_dogfood_visible() {
    let _guard = super::telemetry_serial::lock();
    let canonical_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let trace = Arc::new(ScanTelemetry::new());

    telemetry::testing::reset();
    trace.enable_dogfood();
    let matches = telemetry::with_scan_telemetry(&trace, || {
        find_secrets(
            &format!("{canonical_sha256}\n"),
            16,
            0,
            HIGH_ENTROPY_THRESHOLD,
        )
    });
    assert!(
        matches.is_empty(),
        "canonical isolated bare token must stay suppressed; matches={matches:?}"
    );
    let reasons: Vec<String> = trace
        .drain()
        .dogfood_events
        .into_iter()
        .filter_map(|event| match event {
            DogfoodEvent::ShapeSuppressed {
                credential_redacted,
                reason,
                ..
            } if credential_redacted.starts_with("e3b0") => Some(reason.into_owned()),
            _ => None,
        })
        .collect();
    assert_eq!(reasons, vec!["entropy_canonical_non_secret_shape"]);

    telemetry::testing::reset();
    let trace = Arc::new(ScanTelemetry::new());
    let _ = telemetry::with_scan_telemetry(&trace, || {
        find_secrets(
            &format!("{canonical_sha256}\n"),
            16,
            0,
            HIGH_ENTROPY_THRESHOLD,
        )
    });
    assert!(
        trace.drain().dogfood_events.is_empty(),
        "dogfood-off isolated bare rejection must not emit trace events"
    );
}

#[test]
fn entropy_extraction_rejection_is_dogfood_visible() {
    let _guard = super::telemetry_serial::lock();
    let placeholder = "YOUR_API_KEY_HERE";
    let secret_keywords = vec!["API_KEY".to_string()];
    let placeholder_keywords = vec!["placeholder".to_string()];
    let trace = Arc::new(ScanTelemetry::new());

    telemetry::testing::reset();
    trace.enable_dogfood();
    let matches = telemetry::with_scan_telemetry(&trace, || {
        find_entropy_secrets(
            &format!("API_KEY={placeholder}\n"),
            8,
            0,
            HIGH_ENTROPY_THRESHOLD,
            &secret_keywords,
            &[],
            &placeholder_keywords,
        )
    });
    assert!(
        matches.is_empty(),
        "placeholder fixture must stay suppressed"
    );
    let reasons: Vec<String> = trace
        .drain()
        .dogfood_events
        .into_iter()
        .filter_map(|event| match event {
            // "YOUR_API_KEY_HERE" (17 bytes) redacts to "YO...RE" under the
            // canonical edge = (len/8).clamp(1,4) = 2; the old fixed 4-byte
            // prefix predates the short-secret exposure cap (02d6150d9).
            DogfoodEvent::ShapeSuppressed {
                credential_redacted,
                reason,
                ..
            } if credential_redacted.starts_with("YO") => Some(reason.into_owned()),
            _ => None,
        })
        .collect();
    assert_eq!(reasons, vec!["entropy_candidate_plausibility_rejected"]);

    telemetry::testing::reset();
    let trace = Arc::new(ScanTelemetry::new());
    let _ = telemetry::with_scan_telemetry(&trace, || {
        find_entropy_secrets(
            &format!("API_KEY={placeholder}\n"),
            8,
            0,
            HIGH_ENTROPY_THRESHOLD,
            &secret_keywords,
            &[],
            &placeholder_keywords,
        )
    });
    assert!(
        trace.drain().dogfood_events.is_empty(),
        "dogfood-off entropy extraction rejection must not emit trace events"
    );
}

#[test]
fn entropy_concatenation_fragment_skip_is_dogfood_visible() {
    let _guard = super::telemetry_serial::lock();
    let fragment = "\"abcDEF1234567890\" +";
    let secret_keywords = vec!["API_KEY".to_string()];
    let trace = Arc::new(ScanTelemetry::new());

    telemetry::testing::reset();
    trace.enable_dogfood();
    let matches = telemetry::with_scan_telemetry(&trace, || {
        find_entropy_secrets(
            &format!("API_KEY hint\n{fragment}\n"),
            8,
            1,
            HIGH_ENTROPY_THRESHOLD,
            &secret_keywords,
            &[],
            &[],
        )
    });
    assert!(
        matches.is_empty(),
        "concatenation-fragment fixture must stay suppressed"
    );
    let reasons: Vec<String> = trace
        .drain()
        .dogfood_events
        .into_iter()
        .filter_map(|event| match event {
            DogfoodEvent::ShapeSuppressed { reason, .. } => Some(reason.into_owned()),
            _ => None,
        })
        .collect();
    assert_eq!(reasons, vec!["entropy_concatenation_fragment_line"]);

    telemetry::testing::reset();
    let trace = Arc::new(ScanTelemetry::new());
    let _ = telemetry::with_scan_telemetry(&trace, || {
        find_entropy_secrets(
            &format!("API_KEY hint\n{fragment}\n"),
            8,
            1,
            HIGH_ENTROPY_THRESHOLD,
            &secret_keywords,
            &[],
            &[],
        )
    });
    assert!(
        trace.drain().dogfood_events.is_empty(),
        "dogfood-off concatenation-fragment skip must not emit trace events"
    );
}

#[test]
fn plausibility_uses_shared_placeholder_markers() {
    for value in [
        "YOUR_API_KEY_HERE",
        "REPLACE_ME_WITH_TOKEN",
        "INSERT_HERE_SECRET_VALUE",
        "AKIA1234567890ABCDEF",
        "<paste-token-here>",
    ] {
        assert!(
            !is_candidate_plausible(value, &[]),
            "placeholder marker {value:?} must fail candidate plausibility"
        );
    }

    assert!(
        !is_candidate_plausible("operator_seeded_marker", &["seeded".to_string()]),
        "operator placeholder keywords must still participate in plausibility"
    );
}

#[test]
fn detect_db_password_hex() {
    let text = "DB_PASSWORD=8ae31cacf141669ddfb5da\n";
    let matches = find_secrets(text, 8, 2, HIGH_ENTROPY_THRESHOLD);
    assert!(
        !matches.is_empty(),
        "Should detect hex password near DB_PASSWORD keyword. Got 0 matches."
    );
    assert!(
        matches[0].value.contains("8ae31cac"),
        "Should extract the password value"
    );
}

#[test]
fn entropy_match_offsets_are_cumulative() {
    let text = "first=line\nAPI_KEY=aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL\n";
    let matches = find_secrets(text, 16, 2, HIGH_ENTROPY_THRESHOLD);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].value, "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL");
    assert_eq!(matches[0].offset, "first=line\n".len());
}

#[test]
fn entropy_match_offsets_are_byte_accurate_for_crlf() {
    let secret = "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL";
    let text = "first=line\r\nAPI_KEY=aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL\r\n";
    let matches = find_secrets(text, 16, 2, HIGH_ENTROPY_THRESHOLD);
    let hit = matches
        .iter()
        .find(|candidate| candidate.value == secret)
        .unwrap_or_else(|| panic!("CRLF fixture must report {secret:?}; matches={matches:?}"));
    assert_eq!(
        hit.offset,
        "first=line\r\n".len(),
        "CRLF line starts must be byte offsets into the original text, not text.lines() lengths"
    );
}

#[test]
fn entropy_empty_input_is_zero() {
    assert_eq!(shannon_entropy(b""), 0.0);
}

#[test]
fn entropy_single_unique_byte_is_zero() {
    assert_eq!(shannon_entropy(b"zzzzzzzz"), 0.0);
}

#[test]
fn entropy_all_byte_values_is_near_eight() {
    let all_bytes: Vec<u8> = (0u8..=255).collect();
    let entropy = shannon_entropy(&all_bytes);
    assert!((entropy - 8.0).abs() < 1e-9, "entropy was {}", entropy);
}

#[test]
fn entropy_huge_repeated_input_stays_low() {
    let repeated = vec![b'A'; 100_000];
    assert_eq!(shannon_entropy(&repeated), 0.0);
}

#[test]
fn normalized_entropy_empty_input_is_zero() {
    assert_eq!(normalized_entropy(b""), 0.0);
}

#[test]
fn normalized_entropy_single_unique_byte_is_zero() {
    assert_eq!(normalized_entropy(b"aaaaaaaaaaaaaaaa"), 0.0);
}

#[test]
fn normalized_entropy_binary_pattern_reaches_one() {
    let entropy = normalized_entropy(b"abababababababab");
    assert!((entropy - 1.0).abs() < 1e-9, "entropy was {}", entropy);
}

#[test]
fn normalized_entropy_all_unique_bytes_reaches_one() {
    let all_bytes: Vec<u8> = (0u8..=255).collect();
    let entropy = normalized_entropy(&all_bytes);
    assert!((entropy - 1.0).abs() < 1e-9, "entropy was {}", entropy);
}

#[test]
fn normalized_entropy_stays_bounded_for_large_mixed_input() {
    let mut data = Vec::with_capacity(16_000);
    for _ in 0..500 {
        data.extend_from_slice(b"abc123XYZ!@#$%^&*()");
    }
    let entropy = normalized_entropy(&data);
    assert!((0.0..=1.0).contains(&entropy), "entropy was {}", entropy);
}

#[test]
fn entropy_is_appropriate_for_stdin() {
    assert!(is_entropy_appropriate(None, false));
}

#[test]
fn entropy_is_appropriate_for_config_extensions_case_insensitively() {
    assert!(is_entropy_appropriate(Some("CONFIG/SETTINGS.YAML"), false));
    assert!(is_entropy_appropriate(Some("keys/server.PEM"), false));
    assert!(is_entropy_appropriate(Some("infra/secrets.TFVARS"), false));
}

#[test]
fn entropy_is_appropriate_for_sensitive_filenames_only() {
    assert!(is_entropy_appropriate(Some("/tmp/.npmrc.backup"), false));
    assert!(is_entropy_appropriate(
        Some("nested/docker-compose.prod"),
        false
    ));
    assert!(is_entropy_appropriate(Some("config/apikeys.txt"), false));
}

#[test]
fn entropy_is_not_appropriate_for_source_files_even_with_config_substrings() {
    assert!(!is_entropy_appropriate(
        Some("src/docker_auth_config_test.go"),
        false
    ));
    assert!(!is_entropy_appropriate(
        Some("lib/application_yaml_parser.rs"),
        false
    ));
    assert!(!is_entropy_appropriate(Some("src/main.rs"), false));
}

#[test]
fn source_entropy_lift_requires_same_line_credential_assignment_surface() {
    let text = r#"
pub fn gpu_tokenize_and_classify() {
    let mut scratch = TokenizationScratch::default();
}
"#;
    let secret_keywords = vec!["TOKEN".to_string(), "SECRET".to_string()];
    assert!(
        !is_entropy_appropriate_with_content(
            Some("vyre-libs/src/parsing/c/preprocess/gpu_pipeline/tokenization.rs"),
            false,
            text,
            &secret_keywords,
        ),
        "source files must not enable entropy merely because ordinary code contains Token/secret words next to '='"
    );
}

#[test]
fn source_entropy_lift_preserves_real_credential_assignment_surface() {
    let text = r#"const apiKey = "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL";"#;
    let secret_keywords = vec!["API_KEY".to_string(), "TOKEN".to_string()];
    assert!(
        is_entropy_appropriate_with_content(Some("src/config.ts"), false, text, &secret_keywords),
        "source files with direct credential assignments must still enable entropy"
    );
}

#[test]
fn source_entropy_lift_accepts_nested_object_credential_field() {
    let text =
        r#"const client = new Client({ token: "JwbAykwNNL4zIbfQOSw6FvkB5uYAFzOQidAQ9PTG" });"#;
    let secret_keywords = vec!["API_KEY".to_string(), "TOKEN".to_string()];
    assert!(
        is_entropy_appropriate_with_content(Some("src/client.js"), false, text, &secret_keywords),
        "source entropy lift must recognize credential object fields after an outer assignment"
    );
}

#[test]
fn entropy_is_appropriate_for_source_files_when_allowed() {
    assert!(is_entropy_appropriate(Some("src/main.rs"), true));
    assert!(is_entropy_appropriate(Some("lib/app.py"), true));
    assert!(is_entropy_appropriate(Some("src/components/App.tsx"), true));
}

#[test]
fn entropy_secret_scan_empty_input_returns_no_matches() {
    assert!(find_secrets("", 16, 2, HIGH_ENTROPY_THRESHOLD).is_empty());
}

#[test]
fn keyword_free_scan_detects_long_high_entropy_strings() {
    let secret = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@";
    let text = format!("prefix\n  value: \"{secret}\"\nsuffix\n");
    let matches = find_secrets(&text, 16, 0, HIGH_ENTROPY_THRESHOLD);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].value, secret);
    assert_eq!(matches[0].keyword, "none (high-entropy)");
    assert_eq!(matches[0].line, 2);
}

#[test]
fn keyword_free_scan_detects_isolated_bare_high_entropy_token() {
    let secret = "Zx9Cv8Bn7Mq6Pw5Er4Ty3Ui2Op1As0DfGh";
    let matches = find_secrets(secret, 16, 0, HIGH_ENTROPY_THRESHOLD);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].value, secret);
    assert_eq!(matches[0].keyword, "none (isolated-token)");
    assert_eq!(matches[0].line, 1);
    assert_eq!(matches[0].offset, 0);
}

#[test]
fn keyword_free_scan_detects_isolated_bare_mixed_alnum_token_below_global_floor() {
    let secret = "KP4QX7RM2SN5TB8VW3YZ";
    let matches = find_secrets(secret, 16, 0, HIGH_ENTROPY_THRESHOLD);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].value, secret);
    assert_eq!(matches[0].keyword, "none (isolated-token)");
    assert!(matches[0].entropy < HIGH_ENTROPY_THRESHOLD);
}

#[test]
fn keyword_free_scan_detects_embedded_isolated_bare_mixed_alnum_token() {
    let secret = "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn";
    let prefix = "prefixFiller0123456789".repeat(12);
    let text = format!("{prefix} {secret}\n");
    let matches = find_secrets(&text, 16, 0, HIGH_ENTROPY_THRESHOLD);
    let hit = matches
        .iter()
        .find(|m| m.value == secret)
        .unwrap_or_else(|| panic!("embedded isolated token must surface; matches={matches:?}"));
    assert_eq!(hit.keyword, "none (isolated-token)");
    assert_eq!(hit.line, 1);
    assert_eq!(hit.offset, prefix.len() + 1);
}

#[test]
fn keyword_free_embedded_isolated_scan_rejects_program_identifier_twin() {
    let text = "prefix ClientSecretConfigValue2\n";
    assert!(
        find_secrets(&text, 16, 0, HIGH_ENTROPY_THRESHOLD).is_empty(),
        "source-shaped identifiers must not become keyword-free isolated secrets"
    );
}

#[test]
fn keyword_free_scan_detects_isolated_slash_bearing_base64_token() {
    let secret = "ev0BsFtSD7S/4VWYObxiEhME3hJBXeYzR43jgiB1";
    let matches = find_secrets(secret, 16, 0, HIGH_ENTROPY_THRESHOLD);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].value, secret);
    assert_eq!(matches[0].keyword, "none (isolated-token)");
}

#[test]
fn keyword_free_scan_detects_isolated_lowercase_underscore_token() {
    let secret = "kp4qx7rm_sn5tb8vw_3yzkp4qx";
    let matches = find_secrets(secret, 16, 0, HIGH_ENTROPY_THRESHOLD);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].value, secret);
    assert_eq!(matches[0].keyword, "none (isolated-token)");
}

#[test]
fn keyword_free_scan_detects_isolated_mixed_underscore_token() {
    let secret = "H_ZM9TBrKrmGsNmjQ8mT";
    let matches = find_secrets(secret, 16, 0, HIGH_ENTROPY_THRESHOLD);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].value, secret);
    assert_eq!(matches[0].keyword, "none (isolated-token)");
}

#[test]
fn authorization_call_arg_extracts_quoted_token_in_source_context() {
    let secret = "KP4QX7RM2SN5TB8VW3YZ";
    let text = format!("response = requests.get(url, headers={{'Authorization': '{secret}'}})\n");
    let secret_keywords = vec!["auth".to_string(), "authorization".to_string()];
    let test_keywords = vec!["test".to_string()];
    let placeholder_keywords = vec!["placeholder".to_string()];
    let matches = find_entropy_secrets(
        &text,
        16,
        1,
        HIGH_ENTROPY_THRESHOLD,
        &secret_keywords,
        &test_keywords,
        &placeholder_keywords,
    );
    assert!(
        matches.iter().any(|m| m.value == secret),
        "matches={matches:?}"
    );
}

#[test]
fn credential_context_base64_token_with_internal_plus_generates_entropy_candidate() {
    let secret = "AAAAAAAAANJBBC5jNOBdCOFDBQNPD+tCRBTDUSELFGGIHHEVWPZXYabkMocK";
    let matches = find_secrets(
        &format!("export TOKEN={secret}\n"),
        16,
        1,
        HIGH_ENTROPY_THRESHOLD,
    );
    assert!(
        matches.iter().any(|m| m.value == secret),
        "credential-owned base64-like token with one internal plus must be generated; matches={matches:?}"
    );
}

#[test]
fn keyword_free_isolated_bare_token_rejects_canonical_non_secret_shapes() {
    let text = "\
550e8400-e29b-41d4-a716-446655440000
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
deadbeefcafebabe01234567
ABCDE-FGHIJ-KLMNO-PQRST-UVWXY
my-service-prod-key-name-here
";
    assert!(find_secrets(text, 16, 0, HIGH_ENTROPY_THRESHOLD).is_empty());
}

#[test]
fn keyword_free_scan_rejects_short_high_entropy_strings() {
    let text = "ZxCvBn123!@#As";
    assert!(find_secrets(text, 16, 0, HIGH_ENTROPY_THRESHOLD).is_empty());
}

#[test]
fn duplicate_secret_value_is_reported_once() {
    let secret = "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL";
    let text = format!("API_KEY={secret}\nTOKEN={secret}\n");
    let matches = find_secrets(&text, 16, 1, HIGH_ENTROPY_THRESHOLD);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].value, secret);
}

#[test]
fn import_statements_with_keywords_are_ignored() {
    let text = "import API_KEY from \"aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL\"\n";
    assert!(find_secrets(text, 16, 1, HIGH_ENTROPY_THRESHOLD).is_empty());
}

#[test]
fn url_like_values_are_rejected_even_in_keyword_context() {
    let text = "DATABASE_URL=https://example.com/super/secret/path/value\n";
    assert!(find_secrets(text, 16, 1, HIGH_ENTROPY_THRESHOLD).is_empty());
}

#[test]
fn context_lines_zero_limits_scan_to_keyword_line() {
    let secret = "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL";
    let text = format!("API_KEY=placeholder\n\"{secret}\"\n");
    assert!(find_secrets(&text, 16, 0, HIGH_ENTROPY_THRESHOLD).is_empty());
}

#[test]
fn context_lines_include_neighboring_lines() {
    let secret = "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL";
    let text = format!("API_KEY=placeholder\n  value: \"{secret}\"\n");
    let matches = find_secrets(&text, 16, 1, HIGH_ENTROPY_THRESHOLD);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].value, secret);
    assert_eq!(matches[0].line, 2);
}

#[test]
fn special_character_placeholders_are_rejected() {
    let text = "SECRET=<replace-with-real-secret>\nTOKEN=${{ secrets.API_TOKEN }}\n";
    assert!(find_secrets(text, 8, 1, HIGH_ENTROPY_THRESHOLD).is_empty());
}

#[test]
fn large_input_preserves_line_and_offset_for_match() {
    let filler = "abcd1234\n".repeat(2000);
    // The prior fixture contained `&`, which clean_candidate_value treats as a
    // truncation boundary (stops at whitespace | `&` | `<`), so the extracted
    // candidate was the prefix up to `&` rather than the full secret string.
    // This fixture uses `!` instead of `&` so the whole 56-char value is
    // extracted and the line/offset assertions can verify large-input tracking.
    let secret = "QwErTy123!@#ZxCvBn456$%^AsDfGh789!*(YuIoP0)_+LmNoPqRsTuV";
    assert_eq!(secret.len(), 56, "test invariant: 56-char secret");
    let text = format!("{filler}API_KEY={secret}\n");
    let matches = find_secrets(&text, 16, 0, HIGH_ENTROPY_THRESHOLD);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].value, secret);
    assert_eq!(matches[0].line, 2001);
    assert_eq!(matches[0].offset, filler.len());
}

#[test]
fn entropy_is_not_appropriate_for_noisy_extensions() {
    assert!(!is_entropy_appropriate(Some("package-lock.json"), false));
    assert!(!is_entropy_appropriate(Some("yarn.lock"), false));
    assert!(!is_entropy_appropriate(Some("app.min.js"), false));
    assert!(!is_entropy_appropriate(Some("styles.min.css"), false));
    assert!(!is_entropy_appropriate(Some("bundle.js.map"), false));
    assert!(!is_entropy_appropriate(Some("cache.json"), false));
}

#[test]
fn entropy_sensitive_paths_use_confidence_owner() {
    assert!(is_sensitive_path(".env"));
    assert!(is_sensitive_path(".env.local"));
    assert!(is_sensitive_path("config/credentials.json"));
    assert!(is_sensitive_path("server.pem"));
    assert!(is_sensitive_path("secrets.tfvars"));
    assert!(!is_sensitive_path("README.md"));
    assert!(!is_sensitive_path("package.json"));
}

#[test]
fn import_lines_are_skipped_in_entropy_scan() {
    let text = r#"import { something } from "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkLmnop123"
require("bK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkLmnop456")
use crate::cK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkLmnop789"#;
    assert!(find_secrets(text, 16, 0, HIGH_ENTROPY_THRESHOLD).is_empty());
}

#[test]
fn url_lines_are_skipped_in_entropy_scan() {
    let text = r#"https://aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkLmnop123.example.com
ftp://bK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkLmnop456.example.com"#;
    assert!(find_secrets(text, 16, 0, HIGH_ENTROPY_THRESHOLD).is_empty());
}

#[test]
fn hash_lines_are_skipped_in_entropy_scan() {
    let text = r#"sha256:aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkLmnop123
abc123def4567890abcdef1234567890abcdef12"#;
    assert!(find_secrets(text, 16, 0, HIGH_ENTROPY_THRESHOLD).is_empty());
}

#[test]
fn uuid_values_are_rejected() {
    let text = "API_KEY=550e8400-e29b-41d4-a716-446655440000\n";
    assert!(find_secrets(text, 16, 1, HIGH_ENTROPY_THRESHOLD).is_empty());
}

#[test]
fn sha_hash_values_are_rejected() {
    let text = "SECRET=7c4a8d09ca3762af61e59520943dc26494f8941b\n";
    assert!(find_secrets(text, 16, 1, HIGH_ENTROPY_THRESHOLD).is_empty());
}

#[test]
fn base64_image_values_are_rejected() {
    let text = "IMAGE=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==\n";
    assert!(find_secrets(text, 16, 1, HIGH_ENTROPY_THRESHOLD).is_empty());
}

#[test]
fn keyword_free_uses_custom_threshold() {
    let secret = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@";
    let text = format!("prefix\n  value: \"{secret}\"\nsuffix\n");
    // With default VERY_HIGH_ENTROPY_THRESHOLD (5.8) the secret should match
    let matches = find_entropy_secrets_with_threshold(
        &text,
        16,
        0,
        HIGH_ENTROPY_THRESHOLD,
        VERY_HIGH_ENTROPY_THRESHOLD,
        &[],
        &[],
        &[],
        None,
    );
    assert_eq!(matches.len(), 1);

    // With an extremely high threshold it should not match
    let no_matches = find_entropy_secrets_with_threshold(
        &text,
        16,
        0,
        HIGH_ENTROPY_THRESHOLD,
        8.0,
        &[],
        &[],
        &[],
        None,
    );
    assert!(no_matches.is_empty());
}

#[test]
fn credential_keyword_context_honors_conservative_entropy_threshold() {
    let value = "aAbBcCdDeEfFgGhH12345678";
    let text = format!("api_key = \"{value}\"\n");

    let default_matches = find_secrets(&text, 16, 1, HIGH_ENTROPY_THRESHOLD);
    assert_eq!(default_matches.len(), 1);
    assert_eq!(default_matches[0].value, value);

    let conservative = find_secrets(&text, 16, 1, 6.0);
    assert!(
        conservative.is_empty(),
        "credential-keyword entropy context must honor raised entropy_threshold; got {conservative:?}"
    );

    let maximum = find_secrets(&text, 16, 1, 8.0);
    assert!(
        maximum.is_empty(),
        "threshold 8.0 must suppress moderate-entropy keyword-anchored values; got {maximum:?}"
    );
}

#[test]
fn entropy_simd_agreement() {
    use keyhog_scanner::entropy::shannon_entropy as shannon_entropy_scalar;
    use keyhog_scanner::testing::entropy_fast::shannon_entropy_simd;
    use proptest::prelude::*;

    let mut runner = proptest::test_runner::TestRunner::default();
    runner
        .run(&(prop::collection::vec(any::<u8>(), 32..4096)), |data| {
            let simd = shannon_entropy_simd(&data);
            let scalar = shannon_entropy_scalar(&data);
            if (simd - scalar).abs() > 1e-7 {
                return Err(proptest::test_runner::TestCaseError::fail(format!(
                    "SIMD and scalar entropy should agree. SIMD: {}, scalar: {}",
                    simd, scalar
                )));
            }
            Ok(())
        })
        .unwrap();
}

// ---- is_likely_innocuous_line: hash-digest lines are dropped case-insensitively ----

#[test]
fn innocuous_sha256_label_lowercase_is_dropped() {
    assert!(innocuous_line("sha256:1a2b3c4d5e6f"));
}

#[test]
fn innocuous_sha256_label_uppercase_is_dropped() {
    // certutil / ssh-keygen emit upper-case labels; previously leaked through.
    assert!(innocuous_line("SHA256:1a2b3c4d5e6f"));
}

#[test]
fn innocuous_sha256_label_mixed_case_is_dropped() {
    assert!(innocuous_line("Sha256:1a2b3c4d5e6f"));
    assert!(innocuous_line("sHa256:1a2b3c4d5e6f"));
}

#[test]
fn innocuous_sha512_label_both_cases_is_dropped() {
    assert!(innocuous_line("sha512:abcdef0123456789"));
    assert!(innocuous_line("SHA512:abcdef0123456789"));
}

#[test]
fn innocuous_sha1_label_both_cases_is_dropped() {
    assert!(innocuous_line("sha1:0123456789abcdef"));
    assert!(innocuous_line("SHA1:0123456789abcdef"));
}

#[test]
fn innocuous_md5_label_both_cases_is_dropped() {
    assert!(innocuous_line("md5:d41d8cd98f00b204"));
    assert!(innocuous_line("MD5:d41d8cd98f00b204"));
}

#[test]
fn innocuous_git_sha_label_both_cases_is_dropped() {
    assert!(innocuous_line("git-sha:1234567890abcdef"));
    assert!(innocuous_line("GIT-SHA:1234567890abcdef"));
}

#[test]
fn innocuous_label_inside_quotes_is_dropped() {
    // The line trims surrounding quotes/commas before the label check.
    assert!(innocuous_line("\"sha256:abcdef0123\""));
    assert!(innocuous_line("'SHA256:abcdef0123',"));
}

#[test]
fn innocuous_label_requires_the_colon_not_an_underscore() {
    // `SHA256_KEY:` is a credential-shaped assignment, NOT a digest label - the
    // case-insensitive widening must not swallow it.
    assert!(!innocuous_line("SHA256_KEY: sk_live_realtoken12345"));
    assert!(!innocuous_line("sha256_secret = deadbeefdeadbeef"));
}

#[test]
fn innocuous_bare_40_hex_lowercase_is_dropped() {
    assert!(innocuous_line(&"a".repeat(40)));
}

#[test]
fn innocuous_bare_40_hex_uppercase_is_dropped() {
    assert!(innocuous_line(&"A".repeat(40)));
}

#[test]
fn innocuous_bare_40_hex_mixed_case_is_dropped() {
    // is_ascii_hexdigit accepts either case; a git SHA-1 can be rendered mixed.
    assert!(innocuous_line(&"aB".repeat(20)));
}

#[test]
fn innocuous_bare_hex_of_wrong_length_is_not_dropped() {
    // 39 and 41 hex are not the git-SHA-1 length and carry no algo label.
    assert!(!innocuous_line(&"a".repeat(39)));
    assert!(!innocuous_line(&"a".repeat(41)));
}

#[test]
fn innocuous_import_like_declarations_are_dropped() {
    assert!(innocuous_line("import os"));
    assert!(innocuous_line("from typing import Optional"));
    assert!(innocuous_line("use crate::scanner::Engine;"));
    assert!(innocuous_line("package main"));
    assert!(innocuous_line("include config.php"));
    assert!(innocuous_line("#include <stdio.h>"));
    assert!(innocuous_line("require('dotenv')"));
}

#[test]
fn innocuous_plain_http_uris_are_dropped() {
    assert!(innocuous_line("https://example.com/path"));
    assert!(innocuous_line("http://localhost:8080/health"));
}

#[test]
fn innocuous_plain_ftp_file_ssh_git_uris_are_dropped() {
    assert!(innocuous_line("ftp://mirror.example.org/pub"));
    assert!(innocuous_line("file:///etc/hosts"));
    assert!(innocuous_line("ssh://git@github.com/org/repo.git"));
    assert!(innocuous_line("git://git.example.com/repo.git"));
}

#[test]
fn innocuous_real_credential_assignment_is_not_dropped() {
    // A genuine secret-bearing line must NOT be treated as innocuous.
    assert!(!innocuous_line("API_KEY=sk_live_51H8xToKenValue0123456789"));
    assert!(!innocuous_line("db_password: hunter2secretvalue"));
}

#[test]
fn innocuous_random_prose_is_not_dropped() {
    assert!(!innocuous_line("the quick brown fox jumps over"));
}

#[test]
fn innocuous_empty_and_whitespace_is_not_dropped() {
    assert!(!innocuous_line(""));
    assert!(!innocuous_line("    "));
}

#[test]
fn innocuous_label_prefix_only_no_false_substring_match() {
    // The label must be a PREFIX (after quote-trim), not merely contained: a
    // value that only mentions `sha256:` mid-line is not dropped by this arm.
    assert!(!innocuous_line("token=abc-sha256:notadigest"));
}

/// Per-detector entropy-gate wiring (moved out of an inline `plausibility.rs`
/// test to satisfy the `entropy_plausibility_no_inline_tests` folder contract).
/// Every generic entropy detector's embedded TOML must supply `entropy_high`
/// plus a complete plausibility block in valid Shannon bands.
#[test]
fn generic_detectors_declare_valid_per_detector_entropy_floors() {
    // Literals (not the `detector_ids` consts) because those consts are
    // `pub(crate)` and unreachable from this external test crate; a rename would
    // fail this test loudly, which is the intended drift signal.
    for id in [
        "generic-secret",
        "generic-api-key",
        "generic-keyword-secret",
        "generic-password",
    ] {
        let spec = keyhog_core::detector_spec_by_id(id)
            .unwrap_or_else(|| panic!("{id} must be an embedded detector"));
        let entropy_high = spec
            .entropy_high
            .unwrap_or_else(|| panic!("{id} must set entropy_high in its TOML"));
        let mixed = spec
            .plausibility
            .unwrap_or_else(|| panic!("{id} must set plausibility in its TOML"))
            .mixed_alnum_floor;
        assert!(
            (3.0..=6.0).contains(&entropy_high),
            "{id} entropy_high {entropy_high} outside the valid Shannon band"
        );
        assert!(
            (3.0..=6.0).contains(&mixed),
            "{id} mixed_alnum_floor {mixed} outside the valid Shannon band"
        );
    }
    // An unknown id must not acquire another detector's policy.
    assert!(
        keyhog_core::detector_spec_by_id("definitely-not-a-detector-xyz").is_none(),
        "an unknown id must resolve no detector policy"
    );
}
