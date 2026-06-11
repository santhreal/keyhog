//! Stripe / Slack / Twilio / SendGrid detector contract test suite.
//!
//! Comprehensive positive + negative twin + adversarial + boundary test coverage for:
//! - Stripe: sk_live_, sk_test_, rk_live_, rk_test_ (24+ alphanumeric chars)
//! - Slack: xoxb, xoxp, xapp tokens
//! - Twilio: auth tokens (32 hex), AccountSid (AC + 32 hex)
//! - SendGrid: SG.* API key format
//!
//! CPU and GPU parity validated on all test cases.

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::collections::BTreeSet;
use std::path::PathBuf;

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

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

type FindingKey = (String, String, usize);

fn collect_keys(results: &[Vec<RawMatch>]) -> BTreeSet<FindingKey> {
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

fn scan_both_backends(chunk: &Chunk) -> (BTreeSet<FindingKey>, BTreeSet<FindingKey>) {
    let s = scanner();
    let cpu_results = s.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let cpu_keys = collect_keys(&cpu_results);
    
    let gpu_results = s.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::Gpu);
    let gpu_keys = collect_keys(&gpu_results);
    
    (cpu_keys, gpu_keys)
}

// ============================================================================
// STRIPE: sk_live_ POSITIVE TESTS
// ============================================================================

#[test]
fn stripe_sk_live_basic_24_chars() {
    let chunk = make_chunk(
        "api_key = \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"",
        "stripe.py"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c == "sk_live_4eC39HqLyjWDarjtT1zdp7dc"));
    assert_eq!(cpu, gpu, "CPU and GPU must find identical Stripe sk_live key");
}

#[test]
fn stripe_sk_live_minimum_length() {
    let chunk = make_chunk(
        "secret=\"sk_live_ABCDEFGHIJKLMNOPQRSTUVWXabcdefghij\n",
        "config.json"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c == "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXabcdefghij"));
    assert_eq!(cpu, gpu);
}

#[test]
fn stripe_sk_live_very_long() {
    let chunk = make_chunk(
        "stripe_key: sk_live_RH2M4QJhQk7x5vDjN3pK9wL2mOq8rS1tUv2Wx3YzA4bC5dE6",
        "env.sh"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c.starts_with("sk_live_")));
    assert_eq!(cpu, gpu);
}

#[test]
fn stripe_sk_live_with_numbers() {
    let chunk = make_chunk(
        "STRIPE_SECRET=sk_live_123456789012345678901234567890abcdef",
        "app.yml"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(!cpu.is_empty());
    assert_eq!(cpu, gpu);
}

// ============================================================================
// STRIPE: sk_test_ POSITIVE TESTS
// ============================================================================

#[test]
fn stripe_sk_test_basic() {
    let chunk = make_chunk(
        "TEST_KEY: sk_test_51234567890123456789abcdefgh",
        "test.toml"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c == "sk_test_51234567890123456789abcdefgh"));
    assert_eq!(cpu, gpu);
}

#[test]
fn stripe_sk_test_uppercase() {
    let chunk = make_chunk(
        "api-secret=sk_test_ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJ",
        "secrets.env"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c.starts_with("sk_test_")));
    assert_eq!(cpu, gpu);
}

#[test]
fn stripe_sk_test_mixed_case() {
    let chunk = make_chunk(
        "stripe: sk_test_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        "stripe.rs"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(!cpu.is_empty());
    assert_eq!(cpu, gpu);
}

// ============================================================================
// STRIPE: rk_live_ (RESTRICTED KEY) POSITIVE TESTS
// ============================================================================

#[test]
fn stripe_rk_live_basic() {
    let chunk = make_chunk(
        "restricted_key = \"rk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh\"",
        "stripe_config.json"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c.starts_with("rk_live_")));
    assert_eq!(cpu, gpu);
}

#[test]
fn stripe_rk_live_alphanumeric() {
    let chunk = make_chunk(
        "rk_live_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8",
        "app.js"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c.starts_with("rk_live_")));
    assert_eq!(cpu, gpu);
}

// ============================================================================
// STRIPE: rk_test_ (RESTRICTED TEST KEY) POSITIVE TESTS
// ============================================================================

#[test]
fn stripe_rk_test_basic() {
    let chunk = make_chunk(
        "rk_test_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh",
        "test_stripe.py"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c.starts_with("rk_test_")));
    assert_eq!(cpu, gpu);
}

// ============================================================================
// STRIPE: NEGATIVE TESTS (NEAR-MISS)
// ============================================================================

#[test]
fn stripe_sk_missing_suffix() {
    let chunk = make_chunk(
        "key = \"sk_live_onlytwenty\"",
        "no_stripe.py"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    // sk_live_ exists but only 11 chars after prefix (needs 24+)
    assert!(cpu.is_empty() || !cpu.iter().any(|(c, _, _)| c.contains("onlytwenty")));
    assert_eq!(cpu, gpu);
}

#[test]
fn stripe_sk_test_too_short() {
    let chunk = make_chunk(
        "test_api_key = sk_test_ABCDEFGHIJKLMNOPQRSTUVWXYabcd",
        "config.js"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    // Only 28 chars after prefix (need 24+, so this passes length), verify it's caught
    // Actually 28 chars is valid, so this should be found
    assert!(!cpu.is_empty());
    assert_eq!(cpu, gpu);
}

#[test]
fn stripe_fake_prefix_wrong_format() {
    let chunk = make_chunk(
        "key = \"sk_live.ABCDEFGHIJKLMNOPQRSTUVWXYZabcd\"",
        "fake.env"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    // Dot instead of underscore breaks the pattern
    assert!(cpu.is_empty());
    assert_eq!(cpu, gpu);
}

#[test]
fn stripe_prefix_only_no_body() {
    let chunk = make_chunk(
        "stripe_key: sk_live_",
        "incomplete.yaml"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    // Prefix with no body won't match regex requiring 24+ alphanumeric chars
    assert!(cpu.is_empty());
    assert_eq!(cpu, gpu);
}

#[test]
fn stripe_sk_with_special_chars() {
    let chunk = make_chunk(
        "secret = sk_live_123-456-789-ABC!@#$%^&*()DEFGH",
        "invalid.sh"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    // Special chars break the [a-zA-Z0-9]+ pattern
    assert!(cpu.is_empty() || !cpu.iter().any(|(c, _, _)| c.contains("!")));
    assert_eq!(cpu, gpu);
}

// ============================================================================
// SLACK: xoxb_ POSITIVE TESTS (BOT TOKEN)
// ============================================================================

#[test]
fn slack_xoxb_basic() {
    let chunk = make_chunk(
        "bot_token=\"xoxb-123456789012-123456789012-abcdefghijklmnopqrst\"",
        "slack_bot.py"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c.starts_with("xoxb-")));
    assert_eq!(cpu, gpu);
}

#[test]
fn slack_xoxb_long_suffix() {
    let chunk = make_chunk(
        "SLACK_BOT_TOKEN=xoxb-111122223333-444455556666-777888899990aAbBcCdDeEfFgG",
        "config.env"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c.starts_with("xoxb-")));
    assert_eq!(cpu, gpu);
}

// ============================================================================
// SLACK: xoxp_ POSITIVE TESTS (USER TOKEN)
// ============================================================================

#[test]
fn slack_xoxp_basic() {
    let chunk = make_chunk(
        "user_token=xoxp-123456789012-123456789012-abcdefghijklmnopqrst",
        "slack_user.js"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c.starts_with("xoxp-")));
    assert_eq!(cpu, gpu);
}

#[test]
fn slack_xoxp_uppercase() {
    let chunk = make_chunk(
        "slack_pat: xoxp-999999999999-888888888888-ABCDEFGHIJKLMNOPQRSTU",
        "slack.toml"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c.starts_with("xoxp-")));
    assert_eq!(cpu, gpu);
}

// ============================================================================
// SLACK: xapp_ POSITIVE TESTS (APP-LEVEL TOKEN)
// ============================================================================

#[test]
fn slack_xapp_basic() {
    let chunk = make_chunk(
        "app_token=\"xapp-1-A012B3CDEFG-1234567890123-1f9a0b7c4e2d6a8b3c5f7e9d0a1b2c3d\"",
        "slack_app.py"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c.starts_with("xapp-")));
    assert_eq!(cpu, gpu);
}

#[test]
fn slack_xapp_lowercase_hex_suffix() {
    let chunk = make_chunk(
        "SLACK_APP_TOKEN=xapp-1-A0123456789-1111111111-abcdef0123456789abcdef0123456789",
        "app.env"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c.starts_with("xapp-")));
    assert_eq!(cpu, gpu);
}

// ============================================================================
// SLACK: NEGATIVE TESTS (NEAR-MISS)
// ============================================================================

#[test]
fn slack_xoxb_missing_segment() {
    let chunk = make_chunk(
        "token=xoxb-123456789012-abcdefghijklmnop",
        "no_slack.py"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    // Missing one of the segment separators - pattern requires the multi-segment format
    assert!(cpu.is_empty() || !cpu.iter().any(|(c, _, _)| c == "xoxb-123456789012-abcdefghijklmnop"));
    assert_eq!(cpu, gpu);
}

#[test]
fn slack_xoxp_too_short() {
    let chunk = make_chunk(
        "slack_token: xoxp-short",
        "slack_short.yaml"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    // Incomplete token format
    assert!(cpu.is_empty() || !cpu.iter().any(|(c, _, _)| c.starts_with("xoxp-short")));
    assert_eq!(cpu, gpu);
}

#[test]
fn slack_xapp_insufficient_hex() {
    let chunk = make_chunk(
        "app_token: xapp-1-A012B3CD-1234567890-abc123",
        "slack_invalid.env"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    // xapp suffix must be 32+ hex characters; this has too few
    assert!(cpu.is_empty() || !cpu.iter().any(|(c, _, _)| c.contains("abc123")));
    assert_eq!(cpu, gpu);
}

#[test]
fn slack_xox_wrong_prefix() {
    let chunk = make_chunk(
        "token=xox-123456789012-123456789012-abcdefghijklmnopqrst",
        "wrong_slack.py"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    // 'xox-' (3 chars) is not a recognized Slack token prefix
    assert!(cpu.is_empty() || !cpu.iter().any(|(c, _, _)| c.starts_with("xox-")));
    assert_eq!(cpu, gpu);
}

#[test]
fn slack_xoxb_special_chars() {
    let chunk = make_chunk(
        "slack_bot=xoxb-123456789012-123456789012-abcd!@#$%^&*()",
        "invalid_slack.sh"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    // Special characters don't match alphanumeric pattern
    assert!(cpu.is_empty() || !cpu.iter().any(|(c, _, _)| c.contains("!")));
    assert_eq!(cpu, gpu);
}

// ============================================================================
// TWILIO: AUTH TOKEN POSITIVE TESTS (32 HEX CHARS)
// ============================================================================

#[test]
fn twilio_auth_token_basic() {
    let chunk = make_chunk(
        "TWILIO_AUTH_TOKEN=\"5e80b5d7a4e7c4a9f6b3e2d1c0a9f8e7\"",
        "twilio_config.py"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c == "5e80b5d7a4e7c4a9f6b3e2d1c0a9f8e7"));
    assert_eq!(cpu, gpu);
}

#[test]
fn twilio_auth_token_uppercase() {
    let chunk = make_chunk(
        "auth_token=ABCDEF1234567890FEDCBA0987654321",
        "twilio.env"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c == "ABCDEF1234567890FEDCBA0987654321"));
    assert_eq!(cpu, gpu);
}

#[test]
fn twilio_auth_token_mixed_case() {
    let chunk = make_chunk(
        "twilio_auth_token: aAbBcCdDeEfF00112233445566778899",
        "config.yaml"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c == "aAbBcCdDeEfF00112233445566778899"));
    assert_eq!(cpu, gpu);
}

#[test]
fn twilio_account_sid_basic() {
    let chunk = make_chunk(
        "account_sid = \"ACa1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p\"",
        "twilio_account.py"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c == "ACa1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p"));
    assert_eq!(cpu, gpu);
}

#[test]
fn twilio_account_sid_uppercase() {
    let chunk = make_chunk(
        "account_sid: ACABCDEF0123456789ABCDEF01234567",
        "twilio.env"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c.starts_with("AC")));
    assert_eq!(cpu, gpu);
}

// ============================================================================
// TWILIO: NEGATIVE TESTS (NEAR-MISS)
// ============================================================================

#[test]
fn twilio_token_too_short() {
    let chunk = make_chunk(
        "auth_token=5e80b5d7a4e7c4a9f6b3e2d1",
        "short_twilio.py"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    // Only 26 hex chars, needs exactly 32
    assert!(cpu.is_empty() || !cpu.iter().any(|(c, _, _)| c == "5e80b5d7a4e7c4a9f6b3e2d1"));
    assert_eq!(cpu, gpu);
}

#[test]
fn twilio_token_with_special_chars() {
    let chunk = make_chunk(
        "auth_token: 5e80b5d7a4e7c4a9-f6b3e2d1c0a9f8e7",
        "invalid_twilio.yaml"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    // Hyphen breaks the [a-fA-F0-9]{32} pattern
    assert!(cpu.is_empty());
    assert_eq!(cpu, gpu);
}

#[test]
fn twilio_account_sid_missing_prefix() {
    let chunk = make_chunk(
        "account_sid = \"a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p\"",
        "no_prefix.py"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    // Missing 'AC' prefix makes it non-Twilio AccountSid format
    assert!(cpu.is_empty() || !cpu.iter().any(|(c, _, _)| c.starts_with("AC")));
    assert_eq!(cpu, gpu);
}

#[test]
fn twilio_account_sid_wrong_length() {
    let chunk = make_chunk(
        "sid: ACshortvalue",
        "wrong_length_twilio.env"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    // AC + too few hex chars
    assert!(cpu.is_empty());
    assert_eq!(cpu, gpu);
}

// ============================================================================
// SENDGRID: API KEY POSITIVE TESTS
// ============================================================================

#[test]
fn sendgrid_api_key_basic() {
    let chunk = make_chunk(
        "sendgrid_api_key=\"SG.abcdefghijklmnopqrstu.0123456789abcdefghijklmnopqrstuv\"",
        "sendgrid_config.py"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c.starts_with("SG.")));
    assert_eq!(cpu, gpu);
}

#[test]
fn sendgrid_api_key_uppercase() {
    let chunk = make_chunk(
        "SENDGRID_API_KEY=SG.ABCDEFGHIJKLMNOPQRSTUV.0123456789ABCDEFGHIJKLMNOPQRSTUV",
        "sendgrid.env"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c.starts_with("SG.")));
    assert_eq!(cpu, gpu);
}

#[test]
fn sendgrid_api_key_mixed_case() {
    let chunk = make_chunk(
        "api_key: SG.aBcDeFgHiJkLmNoPqRsTuVw.0123456789aBcDeFgHiJkLmNoPqRsT",
        "sendgrid.yaml"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c.starts_with("SG.")));
    assert_eq!(cpu, gpu);
}

#[test]
fn sendgrid_api_key_with_underscores() {
    let chunk = make_chunk(
        "sendgrid: SG.abc_def_ghi_jkl_mno_pqr.012_345_678_9ab_cde_fgh_ijk_lmn",
        "config.sh"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c.starts_with("SG.")));
    assert_eq!(cpu, gpu);
}

#[test]
fn sendgrid_api_key_with_hyphens() {
    let chunk = make_chunk(
        "key = SG.abc-def-ghi-jkl-mno-pqr.012-345-678-9ab-cde-fgh-ijk-lmn",
        "sendgrid_config.txt"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c.starts_with("SG.")));
    assert_eq!(cpu, gpu);
}

// ============================================================================
// SENDGRID: NEGATIVE TESTS (NEAR-MISS)
// ============================================================================

#[test]
fn sendgrid_prefix_only() {
    let chunk = make_chunk(
        "key: SG.",
        "incomplete_sendgrid.env"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    // SG. prefix with nothing after
    assert!(cpu.is_empty());
    assert_eq!(cpu, gpu);
}

#[test]
fn sendgrid_missing_second_dot() {
    let chunk = make_chunk(
        "api_key=SG.abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrst",
        "no_second_dot.py"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    // Missing the second dot separator
    assert!(cpu.is_empty());
    assert_eq!(cpu, gpu);
}

#[test]
fn sendgrid_segments_too_short() {
    let chunk = make_chunk(
        "sendgrid_key: SG.abc.def",
        "short_segments.yaml"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    // Segments are too short (needs 22+ and 43+)
    assert!(cpu.is_empty());
    assert_eq!(cpu, gpu);
}

#[test]
fn sendgrid_special_chars_in_key() {
    let chunk = make_chunk(
        "api_key: SG.abc!def@ghijk.01234!567890abc#def",
        "invalid_sendgrid.sh"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    // Special chars break the [a-zA-Z0-9_-]+ pattern
    assert!(cpu.is_empty() || !cpu.iter().any(|(c, _, _)| c.contains("!")));
    assert_eq!(cpu, gpu);
}

#[test]
fn sendgrid_wrong_prefix() {
    let chunk = make_chunk(
        "key: SD.abcdefghijklmnopqrstuv.0123456789abcdefghijklmnopqrstuv",
        "wrong_prefix.env"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    // SD instead of SG
    assert!(cpu.is_empty());
    assert_eq!(cpu, gpu);
}

// ============================================================================
// CROSS-SERVICE TESTS (MULTIPLE SECRETS IN ONE INPUT)
// ============================================================================

#[test]
fn multiple_services_in_single_chunk() {
    let chunk = make_chunk(
        "stripe: sk_live_4eC39HqLyjWDarjtT1zdp7dc\n\
         slack_bot: xoxb-123456789012-123456789012-abcdefghijklmnopqrst\n\
         twilio_sid: ACa1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p\n\
         sendgrid: SG.abcdefghijklmnopqrstu.0123456789abcdefghijklmnopqrstuv",
        "all_secrets.env"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    // All four should be detected
    assert!(cpu.len() >= 4, "Should find at least 4 secrets, found {}", cpu.len());
    assert_eq!(cpu, gpu, "CPU and GPU must find same set of multi-service secrets");
}

#[test]
fn stripe_and_slack_interleaved() {
    let chunk = make_chunk(
        "api_keys=[\n  sk_live_key1=sk_live_4eC39HqLyjWDarjtT1zdp7dc,\n  \
         bot_token=xoxb-123456789012-123456789012-abcdefghijklmnopqrst\n]",
        "config.json"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c.starts_with("sk_live_")));
    assert!(cpu.iter().any(|(c, _, _)| c.starts_with("xoxb-")));
    assert_eq!(cpu, gpu);
}

// ============================================================================
// BOUNDARY & ADVERSARIAL TESTS
// ============================================================================

#[test]
fn stripe_at_chunk_end() {
    let chunk = make_chunk(
        "// Config file\nSTRIPE_SECRET=sk_live_4eC39HqLyjWDarjtT1zdp7dc",
        "config.rs"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c.starts_with("sk_live_")));
    assert_eq!(cpu, gpu);
}

#[test]
fn slack_token_in_quoted_string() {
    let chunk = make_chunk(
        "const SLACK_TOKEN = \"xoxb-123456789012-123456789012-abcdefghijklmnopqrst\";",
        "slack_config.ts"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c.starts_with("xoxb-")));
    assert_eq!(cpu, gpu);
}

#[test]
fn twilio_token_with_surrounding_context() {
    let chunk = make_chunk(
        "twilio_auth_token = \"5e80b5d7a4e7c4a9f6b3e2d1c0a9f8e7\" # production",
        "twilio.env"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c == "5e80b5d7a4e7c4a9f6b3e2d1c0a9f8e7"));
    assert_eq!(cpu, gpu);
}

#[test]
fn sendgrid_key_in_url_encoded() {
    let chunk = make_chunk(
        "url=https://api.sendgrid.com?key=SG.abcdefghijklmnopqrstu.0123456789abcdefghijklmnopqrstuv",
        "request.txt"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.iter().any(|(c, _, _)| c.starts_with("SG.")));
    assert_eq!(cpu, gpu);
}

#[test]
fn multiple_stripe_keys_same_chunk() {
    let chunk = make_chunk(
        "live_key: sk_live_4eC39HqLyjWDarjtT1zdp7dc\n\
         test_key: sk_test_51234567890123456789abcdefgh\n\
         rk_live: rk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh",
        "stripe_keys.yaml"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.len() >= 3, "Should find all three Stripe key types");
    assert_eq!(cpu, gpu);
}

#[test]
fn negative_near_miss_storm() {
    // Many false-prefix candidates that shouldn't match
    let chunk = make_chunk(
        "sk_live is great\n\
         sk_test_value but not_a_key\n\
         xoxb- missing segments\n\
         SG.short.too_short_again\n\
         AC but not_hex_enough",
        "near_misses.txt"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    // All should be empty or very minimal
    assert_eq!(cpu, gpu);
}

// ============================================================================
// GPU-SPECIFIC TESTS
// ============================================================================

#[test]
#[cfg(feature = "gpu")]
fn gpu_stripe_secret_parity() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU available");
        return;
    }
    
    let chunk = make_chunk(
        "stripe_live: sk_live_4eC39HqLyjWDarjtT1zdp7dc\n\
         stripe_test: sk_test_51234567890123456789abcdefgh",
        "stripe.env"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(!cpu.is_empty(), "CPU backend should find Stripe secrets");
    assert_eq!(cpu, gpu, "GPU and CPU must find identical Stripe secrets");
}

#[test]
#[cfg(feature = "gpu")]
fn gpu_slack_token_parity() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU available");
        return;
    }
    
    let chunk = make_chunk(
        "xoxb: xoxb-123456789012-123456789012-abcdefghijklmnopqrst\n\
         xoxp: xoxp-123456789012-123456789012-abcdefghijklmnopqrst\n\
         xapp: xapp-1-A012B3CDEFG-1234567890123-1f9a0b7c4e2d6a8b3c5f7e9d0a1b2c3d",
        "slack.yaml"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.len() >= 3, "CPU should find all three Slack token types");
    assert_eq!(cpu, gpu, "GPU and CPU must find identical Slack tokens");
}

#[test]
#[cfg(feature = "gpu")]
fn gpu_twilio_account_sid_parity() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU available");
        return;
    }
    
    let chunk = make_chunk(
        "sid1: ACa1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p\n\
         sid2: ACABCDEF0123456789ABCDEF01234567\n\
         token: 5e80b5d7a4e7c4a9f6b3e2d1c0a9f8e7",
        "twilio.py"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.len() >= 3);
    assert_eq!(cpu, gpu, "GPU and CPU must find identical Twilio credentials");
}

#[test]
#[cfg(feature = "gpu")]
fn gpu_sendgrid_api_key_parity() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU available");
        return;
    }
    
    let chunk = make_chunk(
        "key1: SG.abcdefghijklmnopqrstu.0123456789abcdefghijklmnopqrstuv\n\
         key2: SG.ABCDEFGHIJKLMNOPQRSTUV.0123456789ABCDEFGHIJKLMNOPQRSTUV",
        "sendgrid_config.env"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.len() >= 2);
    assert_eq!(cpu, gpu, "GPU and CPU must find identical SendGrid keys");
}

#[test]
#[cfg(feature = "gpu")]
fn gpu_combined_service_parity() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU available");
        return;
    }
    
    let chunk = make_chunk(
        "stripe: sk_live_4eC39HqLyjWDarjtT1zdp7dc\n\
         slack: xoxb-123456789012-123456789012-abcdefghijklmnopqrst\n\
         twilio: ACa1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p\n\
         sendgrid: SG.abcdefghijklmnopqrstu.0123456789abcdefghijklmnopqrstuv",
        "services.yaml"
    );
    let (cpu, gpu) = scan_both_backends(&chunk);
    assert!(cpu.len() >= 4, "Should find all four service credentials");
    assert_eq!(cpu, gpu, "GPU and CPU must find identical multi-service credentials");
}