//! Part 2 of massive, handwritten, deep adversarial integration test suite.
//!
//! Every test in this suite is fully handwritten to validate Keyhog's secret
//! scanning, pre-filtering, and ML scoring capabilities against hostile inputs,
//! evasion methods, and edge cases.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent, assert_detector_silent_across_chunk_boundary};

// =========================================================================
// 1. CLOUDFLARE API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv2_cloudflare_token_normal_must_fire() {
    assert_detector_fires(
        "cloudflare-api-token",
        "c21a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a",
        "c21a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a",
    );
}

#[test]
fn adv2_cloudflare_token_too_short_must_silent() {
    assert_detector_silent("cloudflare-api-token", "c21a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f");
}

#[test]
fn adv2_cloudflare_token_too_long_must_silent() {
    assert_detector_silent("cloudflare-api-token", "c21a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a123");
}

#[test]
fn adv2_cloudflare_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cloudflare-api-token",
        "c21a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e\u{200B}9f0a",
        "c21a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a",
    );
}

#[test]
fn adv2_cloudflare_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "cloudflare-api-token",
        "c21a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d\u{200D}8e9f0a",
        "c21a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a",
    );
}

#[test]
fn adv2_cloudflare_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cloudflare-api-token",
        "c21a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9\u{00AD}f0a",
        "c21a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a",
    );
}

#[test]
fn adv2_cloudflare_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "cloudflare-api-token",
        "c21a3b\u{FEFF}4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a",
        "c21a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a",
    );
}

#[test]
fn adv2_cloudflare_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "cloudflare-api-token",
        "c21a3b4c5d6e7f8a9b0c1d2e3f4a5b6\u{2060}c7d8e9f0a",
        "c21a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a",
    );
}

// =========================================================================
// 2. DATADOG API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv2_datadog_key_normal_must_fire() {
    assert_detector_fires(
        "datadog-api-key",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv2_datadog_key_invalid_chars_must_silent() {
    assert_detector_silent("datadog-api-key", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d!");
}

#[test]
fn adv2_datadog_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "datadog-api-key",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2\u{200B}c3d4",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv2_datadog_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "datadog-api-key",
        "a1b2c3d4e5f6a1b2c\u{200C}3d4e5f6a1b2c3d4",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv2_datadog_key_evade_bidi_override_must_fire() {
    assert_detector_fires(
        "datadog-api-key",
        "a1b2c3d4e5f6a1b2c\u{202E}3d4e5f6a1b2c3d4",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv2_datadog_key_evade_bidi_isolate_must_fire() {
    assert_detector_fires(
        "datadog-api-key",
        "a1b2c3d4e5f6a1b2c\u{2066}3d4e5f6a1b2c3d4",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

// =========================================================================
// 3. AIRTABLE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv2_airtable_key_normal_must_fire() {
    assert_detector_fires(
        "airtable-api-key",
        "key12345678901234",
        "key12345678901234",
    );
}

#[test]
fn adv2_airtable_key_wrong_prefix_must_silent() {
    assert_detector_silent("airtable-api-key", "kez12345678901234");
}

#[test]
fn adv2_airtable_key_evade_zwsp_prefix_must_fire() {
    assert_detector_fires(
        "airtable-api-key",
        "ke\u{200B}y12345678901234",
        "key12345678901234",
    );
}

#[test]
fn adv2_airtable_key_evade_homoglyph_e_must_fire() {
    // Cyrillic 'е' instead of Latin 'e'
    assert_detector_fires(
        "airtable-api-key",
        "k\u{0435}y12345678901234",
        "key12345678901234",
    );
}

#[test]
fn adv2_airtable_key_evade_homoglyph_y_must_fire() {
    // Cyrillic 'у' instead of Latin 'y'
    assert_detector_fires(
        "airtable-api-key",
        "ke\u{0443}12345678901234",
        "key12345678901234",
    );
}

// =========================================================================
// 4. OPENAI API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv2_openai_key_normal_must_fire() {
    assert_detector_fires(
        "openai-api-key",
        "sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4",
        "sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4",
    );
}

#[test]
fn adv2_openai_key_wrong_prefix_must_silent() {
    assert_detector_silent("openai-api-key", "sk-prof-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4");
}

#[test]
fn adv2_openai_key_evade_zwsp_dash_must_fire() {
    assert_detector_fires(
        "openai-api-key",
        "sk\u{200B}-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4",
        "sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4",
    );
}

#[test]
fn adv2_openai_key_evade_soft_hyphen_dash_must_fire() {
    assert_detector_fires(
        "openai-api-key",
        "sk\u{00AD}proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4",
        "sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4",
    );
}

#[test]
fn adv2_openai_key_evade_homoglyph_o_must_fire() {
    // Cyrillic 'о' U+043E
    assert_detector_fires(
        "openai-api-key",
        "sk-pr\u{043E}j-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4",
        "sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4",
    );
}

// =========================================================================
// 5. SENDGRID API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv2_sendgrid_key_normal_must_fire() {
    assert_detector_fires(
        "sendgrid-api-key",
        "SG.a1b2c3d4e5f6g7h8i9j0k1.a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v",
        "SG.a1b2c3d4e5f6g7h8i9j0k1.a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v",
    );
}

#[test]
fn adv2_sendgrid_key_wrong_dot_must_silent() {
    assert_detector_silent(
        "sendgrid-api-key",
        "SG-a1b2c3d4e5f6g7h8i9j0k1.a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v",
    );
}

#[test]
fn adv2_sendgrid_key_evade_zwsp_dot_must_fire() {
    assert_detector_fires(
        "sendgrid-api-key",
        "SG\u{200B}.a1b2c3d4e5f6g7h8i9j0k1.a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v",
        "SG.a1b2c3d4e5f6g7h8i9j0k1.a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v",
    );
}

#[test]
fn adv2_sendgrid_key_evade_homoglyph_s_must_fire() {
    // Cyrillic 'Ѕ' U+0405
    assert_detector_fires(
        "sendgrid-api-key",
        "\u{0405}G.a1b2c3d4e5f6g7h8i9j0k1.a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v",
        "SG.a1b2c3d4e5f6g7h8i9j0k1.a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v",
    );
}

// =========================================================================
// 6. ADVERSARIAL COMBINATIONS AND HYBRIDS
// =========================================================================

#[test]
fn adv2_hybrid_aws_access_key_zwsp_and_homoglyph_must_fire() {
    // Both zero-width space and Cyrillic homoglyph in single credential
    // Cyrillic 'А' (U+0410) and ZWSP (U+200B)
    assert_detector_fires(
        "aws-access-key",
        "\u{0410}KIA\u{200B}QYLPMN5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv2_hybrid_github_pat_zwj_and_homoglyph_must_fire() {
    // Cyrillic 'о' (U+043E) and Zero-width joiner (U+200D)
    assert_detector_fires(
        "github-classic-pat",
        "gh\u{043E}_nJ7tK5mN9q\u{200D}L2rX4sB6vY8zW0pQ3xZ1eD2cR4",
        "ghp_nJ7tK5mN9qL2rX4sB6vY8zW0pQ3xZ1eD2cR4",
    );
}

#[test]
fn adv2_hybrid_stripe_secret_key_soft_hyphen_and_homoglyph_must_fire() {
    // Cyrillic 'е' (U+0435) and soft hyphen (U+00AD)
    assert_detector_fires(
        "stripe-secret-key",
        "sk_liv\u{0435}_\u{00AD}51A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6",
        "sk_live_51A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6",
    );
}

#[test]
fn adv2_hybrid_slack_bot_token_bidi_and_homoglyph_must_fire() {
    // Cyrillic 'х' (U+0445) and BIDI Right-to-Left Override (U+202E)
    assert_detector_fires(
        "slack-bot-token",
        "\u{0445}oxb\u{202E}-123456789012-345678901234-a1b2c3d4e5f6g7h8i9j0k1l2",
        "xoxb-123456789012-345678901234-a1b2c3d4e5f6g7h8i9j0k1l2",
    );
}

// =========================================================================
// 7. ADDITIONAL EVASION BOUNDARIES AND CORNER CASES
// =========================================================================

#[test]
fn adv2_aws_access_key_backspace_control_must_fire() {
    // Backspace control char (U+0008) at the very beginning of the key
    assert_detector_fires("aws-access-key", "\u{0008}AKIAQYLPMN5HFIQR7XYA", "AKIAQYLPMN5HFIQR7XYA");
}

#[test]
fn adv2_aws_access_key_tab_control_must_fire() {
    // Horizontal Tab control char (U+0009) in the middle of key
    assert_detector_fires("aws-access-key", "AKIA\u{0009}QYLPMN5HFIQR7XYA", "AKIAQYLPMN5HFIQR7XYA");
}

#[test]
fn adv2_aws_access_key_carriage_return_control_must_fire() {
    // Carriage return control char (U+000D) in the middle of key
    assert_detector_fires("aws-access-key", "AKIA\u{000D}QYLPMN5HFIQR7XYA", "AKIAQYLPMN5HFIQR7XYA");
}

#[test]
fn adv2_aws_access_key_vertical_tab_control_must_fire() {
    // Vertical Tab control char (U+000B) in the middle of key
    assert_detector_fires("aws-access-key", "AKIA\u{000B}QYLPMN5HFIQR7XYA", "AKIAQYLPMN5HFIQR7XYA");
}

#[test]
fn adv2_aws_access_key_form_feed_control_must_fire() {
    // Form feed control char (U+000C) in the middle of key
    assert_detector_fires("aws-access-key", "AKIA\u{000C}QYLPMN5HFIQR7XYA", "AKIAQYLPMN5HFIQR7XYA");
}

#[test]
fn adv2_aws_access_key_trailing_null_byte_must_fire() {
    // Null byte control char (U+0000) at the end of the key
    assert_detector_fires("aws-access-key", "AKIAQYLPMN5HFIQR7XYA\u{0000}", "AKIAQYLPMN5HFIQR7XYA");
}

#[test]
fn adv2_aws_access_key_trailing_backspace_must_fire() {
    // Backspace control char (U+0008) at the end of the key
    assert_detector_fires("aws-access-key", "AKIAQYLPMN5HFIQR7XYA\u{0008}", "AKIAQYLPMN5HFIQR7XYA");
}

#[test]
fn adv2_aws_access_key_leading_and_trailing_zwsp_must_fire() {
    // Leading and trailing ZWSPs (U+200B) surrounding the key
    assert_detector_fires("aws-access-key", "\u{200B}AKIAQYLPMN5HFIQR7XYA\u{200B}", "AKIAQYLPMN5HFIQR7XYA");
}
