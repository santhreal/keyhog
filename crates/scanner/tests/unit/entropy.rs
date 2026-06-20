use keyhog_scanner::entropy::*;
use keyhog_scanner::testing::entropy_keywords::{is_candidate_plausible, is_secret_plausible};

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
fn candidate_mode_skips_strict_secret_checks() {
    assert!(is_candidate_plausible("0123456789abcdef", &[]));
    assert!(!is_secret_plausible("0123456789abcdef", &[]));
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
fn sensitive_files_are_detected() {
    assert!(is_sensitive_file(Some(".env")));
    assert!(is_sensitive_file(Some("server.pem")));
    assert!(is_sensitive_file(Some("secrets.tfvars")));
    assert!(!is_sensitive_file(Some("README.md")));
    assert!(!is_sensitive_file(Some("package.json")));
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
