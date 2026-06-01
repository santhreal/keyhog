//! Massive, handwritten, deep adversarial integration test suite.
//!
//! Every test in this suite is fully handwritten to validate Keyhog's secret
//! scanning, pre-filtering, and ML scoring capabilities against hostile inputs,
//! evasion methods, and edge cases.

use super::oracle_support::{
    assert_detector_fires, assert_detector_silent, assert_detector_silent_across_chunk_boundary,
};

// =========================================================================
// 1. AWS ACCESS KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv_aws_access_key_normal_must_fire() {
    assert_detector_fires(
        "aws-access-key",
        "AKIAQYLPMN5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv_aws_access_key_lowercase_must_silent() {
    assert_detector_silent("aws-access-key", "akiaqylpmn5hfiqr7xya");
}

#[test]
fn adv_aws_access_key_too_short_must_silent() {
    assert_detector_silent("aws-access-key", "AKIAQYLPMN5HFIQR");
}

#[test]
fn adv_aws_access_key_too_long_must_silent() {
    assert_detector_silent("aws-access-key", "AKIAQYLPMN5HFIQR7XYAEXTRAS");
}

#[test]
fn adv_aws_access_key_evade_zero_width_space_must_fire() {
    // Evasion via zero-width space (U+200B) inside key must be normalized and fire
    assert_detector_fires(
        "aws-access-key",
        "AKIA\u{200B}QYLPMN5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv_aws_access_key_evade_soft_hyphen_must_fire() {
    // Evasion via soft hyphen (U+00AD) inside key must be normalized and fire
    assert_detector_fires(
        "aws-access-key",
        "AKIA\u{00AD}QYLPMN5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv_aws_access_key_invalid_chars_must_silent() {
    assert_detector_silent("aws-access-key", "AKIAQYLPMN5HFIQR7XY!");
}

// =========================================================================
// 2. GITHUB CLASSIC PAT ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv_github_pat_normal_must_fire() {
    assert_detector_fires(
        "github-classic-pat",
        "ghp_nJ7tK5mN9qL2rX4sB6vY8zW0pQ3xZ1eD2cR4",
        "ghp_nJ7tK5mN9qL2rX4sB6vY8zW0pQ3xZ1eD2cR4",
    );
}

#[test]
fn adv_github_pat_no_prefix_must_silent() {
    assert_detector_silent("github-classic-pat", "nJ7tK5mN9qL2rX4sB6vY8zW0pQ3xZ1eD2cR4");
}

#[test]
fn adv_github_pat_wrong_prefix_must_silent() {
    assert_detector_silent(
        "github-classic-pat",
        "gha_nJ7tK5mN9qL2rX4sB6vY8zW0pQ3xZ1eD2cR4",
    );
}

#[test]
fn adv_github_pat_evade_backspace_must_fire() {
    // Evasion via backspace control char (U+0008) must be normalized and fire
    assert_detector_fires(
        "github-classic-pat",
        "ghp_nJ7tK5mN9q\u{0008}L2rX4sB6vY8zW0pQ3xZ1eD2cR4",
        "ghp_nJ7tK5mN9qL2rX4sB6vY8zW0pQ3xZ1eD2cR4",
    );
}

#[test]
fn adv_github_pat_evade_null_byte_must_fire() {
    // Evasion via null byte (U+0000) must be normalized and fire
    assert_detector_fires(
        "github-classic-pat",
        "ghp_nJ7tK5mN9qL2rX4sB6vY8z\u{0000}W0pQ3xZ1eD2cR4",
        "ghp_nJ7tK5mN9qL2rX4sB6vY8zW0pQ3xZ1eD2cR4",
    );
}

#[test]
fn adv_github_pat_whitespace_split_must_silent() {
    assert_detector_silent(
        "github-classic-pat",
        "ghp_nJ7tK5mN9qL2rX4sB6vY8z W0pQ3xZ1eD2cR4",
    );
}

// =========================================================================
// 3. GOOGLE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv_google_api_key_normal_must_fire() {
    assert_detector_fires(
        "google-api-key",
        "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q",
        "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q",
    );
}

#[test]
fn adv_google_api_key_wrong_start_must_silent() {
    assert_detector_silent("google-api-key", "AIzbSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q");
}

#[test]
fn adv_google_api_key_too_short_must_silent() {
    assert_detector_silent("google-api-key", "AIzaSyA1B2C3D4E5F6G7H8I9J0");
}

#[test]
fn adv_google_api_key_evade_homoglyph_a_must_fire() {
    // Evasion via Cyrillic homoglyph 'А' (U+0410) instead of Latin 'A'
    assert_detector_fires(
        "google-api-key",
        "\u{0410}IzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q",
        "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q",
    );
}

#[test]
fn adv_google_api_key_evade_homoglyph_i_must_fire() {
    // Evasion via Cyrillic homoglyph 'І' (U+0406) instead of Latin 'I'
    assert_detector_fires(
        "google-api-key",
        "A\u{0406}zaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q",
        "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q",
    );
}

// =========================================================================
// 4. STRIPE SECRET KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv_stripe_secret_key_normal_must_fire() {
    assert_detector_fires(
        "stripe-secret-key",
        "sk_live_51A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6",
        "sk_live_51A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6",
    );
}

#[test]
fn adv_stripe_secret_key_wrong_mode_must_silent() {
    assert_detector_silent(
        "stripe-secret-key",
        "sk_prod_51A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6",
    );
}

#[test]
fn adv_stripe_secret_key_evade_zwsp_prefix_must_fire() {
    // Evasion via zero-width space in the prefix 'sk_live_'
    assert_detector_fires(
        "stripe-secret-key",
        "sk_l\u{200B}ive_51A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6",
        "sk_live_51A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6",
    );
}

// =========================================================================
// 5. SLACK BOT TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv_slack_bot_token_normal_must_fire() {
    assert_detector_fires(
        "slack-bot-token",
        "xoxb-123456789012-345678901234-a1b2c3d4e5f6g7h8i9j0k1l2",
        "xoxb-123456789012-345678901234-a1b2c3d4e5f6g7h8i9j0k1l2",
    );
}

#[test]
fn adv_slack_bot_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "slack-bot-token",
        "xoxa-123456789012-345678901234-a1b2c3d4e5f6g7h8i9j0k1l2",
    );
}

#[test]
fn adv_slack_bot_token_evade_soft_hyphen_dash_evaded_must_stay_silent() {
    // Evasion via soft hyphen (U+00AD) instead of physical dash '-'
    assert_detector_silent("slack-bot-token", "xoxb\u{00AD}123456789012\u{00AD}345678901234\u{00AD}a1b2c3d4e5f6g7h8i9j0k1l2");
}

// =========================================================================
// 6. HEROKU API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv_heroku_api_key_normal_bare_must_stay_silent() {
    assert_detector_silent("heroku-api-key", "01234567-89ab-cdef-0123-456789abcdef");
}

#[test]
fn adv_heroku_api_key_invalid_hex_must_silent() {
    assert_detector_silent("heroku-api-key", "01234567-89ab-cdef-0123-456789abcdeg");
}

#[test]
fn adv_heroku_api_key_evade_zwsp_dash_bare_must_stay_silent() {
    // Evasion via zero-width space next to UUID dashes
    assert_detector_silent("heroku-api-key", "01234567-\u{200B}89ab-cdef-0123-456789abcdef");
}

// =========================================================================
// 7. FIREBASE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv_firebase_api_key_normal_must_fire() {
    assert_detector_fires(
        "firebase-api-key",
        "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q",
        "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q",
    );
}

#[test]
fn adv_firebase_api_key_wrong_length_must_silent() {
    assert_detector_silent("firebase-api-key", "AIzaSyA1B2C3D4E5F6G7H8");
}

// =========================================================================
// 8. DISCORD BOT TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv_discord_bot_token_normal_must_fire() {
    assert_detector_fires(
        "discord-bot-token",
        "ODQxMjg5Mzk0NTY3MTY4MDAw.YIpweg.a1b2c3d4e5f6g7h8i9j0k1l2m3n",
        "ODQxMjg5Mzk0NTY3MTY4MDAw.YIpweg.a1b2c3d4e5f6g7h8i9j0k1l2m3n",
    );
}

#[test]
fn adv_discord_bot_token_invalid_base64_must_silent() {
    assert_detector_silent(
        "discord-bot-token",
        "ODQxMjg5Mzk0NTY3MTY4MDAw!.YIpweg.a1b2c3d4e5f6g7h8i9j0k1l2m3n",
    );
}

// =========================================================================
// 9. COALESCED CHUNK BOUNDARY INTEGRATION TESTS
// =========================================================================

#[test]
fn adv_aws_access_key_chunk_boundary_must_not_fire_near_miss() {
    assert_detector_silent_across_chunk_boundary("aws-access-key", "AKIAQYLPMN5HFIQR7XY");
}

#[test]
fn adv_github_pat_chunk_boundary_must_not_fire_near_miss() {
    assert_detector_silent_across_chunk_boundary(
        "github-classic-pat",
        "ghp_nJ7tK5mN9qL2rX4sB6vY8zW0pQ3xZ1eD",
    );
}

#[test]
fn adv_google_api_key_chunk_boundary_must_not_fire_near_miss() {
    assert_detector_silent_across_chunk_boundary(
        "google-api-key",
        "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4",
    );
}

#[test]
fn adv_stripe_secret_key_chunk_boundary_must_not_fire_near_miss() {
    assert_detector_silent_across_chunk_boundary(
        "stripe-secret-key",
        "sk_live_51A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4",
    );
}

#[test]
fn adv_slack_bot_token_chunk_boundary_must_not_fire_near_miss() {
    assert_detector_silent_across_chunk_boundary(
        "slack-bot-token",
        "xoxb-123456789012-345678901234-a1b2c3d4e5f6g7h8i9j0k",
    );
}

#[test]
fn adv_heroku_api_key_chunk_boundary_must_not_fire_near_miss() {
    assert_detector_silent_across_chunk_boundary(
        "heroku-api-key",
        "01234567-89ab-cdef-0123-456789abcd",
    );
}

#[test]
fn adv_discord_bot_token_chunk_boundary_must_not_fire_near_miss() {
    assert_detector_silent_across_chunk_boundary(
        "discord-bot-token",
        "ODQxMjg5Mzk0NTY3MTY4MDAw.YIpweg.a1b2c3d4e5f6g7h8i9j0k1",
    );
}

// =========================================================================
// 10. EVASION & HOMOGLYPH SPECIAL CASES
// =========================================================================

#[test]
fn adv_homoglyph_cyrillic_o_must_fire() {
    // Evasion using Cyrillic homoglyph 'о' (U+043E) in GitHub classic prefix
    assert_detector_fires(
        "github-classic-pat",
        "gh\u{043E}_nJ7tK5mN9qL2rX4sB6vY8zW0pQ3xZ1eD2cR4",
        "ghp_nJ7tK5mN9qL2rX4sB6vY8zW0pQ3xZ1eD2cR4",
    );
}

#[test]
fn adv_homoglyph_cyrillic_e_must_fire() {
    // Evasion using Cyrillic homoglyph 'е' (U+0435) in Stripe prefix
    assert_detector_fires(
        "stripe-secret-key",
        "sk_liv\u{0435}_51A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6",
        "sk_live_51A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6",
    );
}

#[test]
fn adv_homoglyph_cyrillic_x_must_fire() {
    // Evasion using Cyrillic homoglyph 'х' (U+0445) in Slack prefix
    assert_detector_fires(
        "slack-bot-token",
        "\u{0445}oxb-123456789012-345678901234-a1b2c3d4e5f6g7h8i9j0k1l2",
        "xoxb-123456789012-345678901234-a1b2c3d4e5f6g7h8i9j0k1l2",
    );
}

#[test]
fn adv_evasion_combining_tilde_must_fire() {
    // Evasion using Combining Tilde (U+0303) over characters must be normalized
    assert_detector_fires(
        "aws-access-key",
        "A\u{0303}KIAQYLPMN5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv_evasion_combining_ring_must_fire() {
    // Evasion using Combining Ring Above (U+030A) must be normalized
    assert_detector_fires(
        "aws-access-key",
        "AKIAQYLPMN5HFIQR7XY\u{030A}A",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv_evasion_multiple_marks_must_fire() {
    // Evasion using multiple combining marks (Zalgo-like) must be normalized
    assert_detector_fires(
        "github-classic-pat",
        "ghp_\u{0300}\u{0301}\u{0302}nJ7tK5mN9qL2rX4sB6vY8zW0pQ3xZ1eD2cR4",
        "ghp_nJ7tK5mN9qL2rX4sB6vY8zW0pQ3xZ1eD2cR4",
    );
}

#[test]
fn adv_evasion_zero_width_joiner_must_fire() {
    // Evasion via zero-width joiner (U+200D) must be normalized
    assert_detector_fires(
        "github-classic-pat",
        "ghp_nJ7tK5mN9qL2rX4sB6vY8z\u{200D}W0pQ3xZ1eD2cR4",
        "ghp_nJ7tK5mN9qL2rX4sB6vY8zW0pQ3xZ1eD2cR4",
    );
}

#[test]
fn adv_evasion_zero_width_no_break_space_must_fire() {
    // Evasion via zero-width no-break space (U+FEFF) must be normalized
    assert_detector_fires(
        "aws-access-key",
        "AKIA\u{FEFF}QYLPMN5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv_evasion_word_joiner_must_fire() {
    // Evasion via word joiner (U+2060) must be normalized
    assert_detector_fires(
        "stripe-secret-key",
        "sk_live_51A1B2C3D4E5F6G7H8I9J0K1\u{2060}L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6",
        "sk_live_51A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6",
    );
}

#[test]
fn adv_evasion_bidi_override_must_fire() {
    // Evasion using right-to-left override (U+202E) must be normalized
    assert_detector_fires(
        "aws-access-key",
        "AKIA\u{202E}QYLPMN5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv_evasion_bidi_isolate_must_fire() {
    // Evasion using first strong isolate (U+2066) must be normalized
    assert_detector_fires(
        "aws-access-key",
        "AKIA\u{2066}QYLPMN5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv_evasion_bidi_pop_format_must_fire() {
    // Evasion using pop directional formatting (U+202C) must be normalized
    assert_detector_fires(
        "aws-access-key",
        "AKIA\u{202C}QYLPMN5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv_evasion_line_separator_must_fire() {
    // Evasion using line separator (U+2028) must be normalized
    assert_detector_fires(
        "aws-access-key",
        "AKIA\u{2028}QYLPMN5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv_evasion_paragraph_separator_must_fire() {
    // Evasion using paragraph separator (U+2029) must be normalized
    assert_detector_fires(
        "aws-access-key",
        "AKIA\u{2029}QYLPMN5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv_evasion_mongolian_vowel_separator_must_fire() {
    // Evasion using Mongolian Vowel Separator (U+180E) must be normalized
    assert_detector_fires(
        "aws-access-key",
        "AKIA\u{180E}QYLPMN5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv_evasion_thin_space_must_fire() {
    // Evasion using Thin Space (U+2009) must be normalized
    assert_detector_fires(
        "aws-access-key",
        "AKIA\u{2009}QYLPMN5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv_evasion_hair_space_must_fire() {
    // Evasion using Hair Space (U+200A) must be normalized
    assert_detector_fires(
        "aws-access-key",
        "AKIA\u{200A}QYLPMN5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv_evasion_ideographic_space_must_fire() {
    // Evasion using Ideographic Space (U+3000) must be normalized
    assert_detector_fires(
        "aws-access-key",
        "AKIA\u{3000}QYLPMN5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}

#[test]
fn adv_evasion_zero_width_space_multiple_must_fire() {
    // Evasion via multiple zero-width spaces must be normalized
    assert_detector_fires(
        "aws-access-key",
        "AKIA\u{200B}\u{200B}QYLPMN5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}
