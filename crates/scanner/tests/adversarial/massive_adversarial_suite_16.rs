//! Part 16 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates Brightcove, Bright Data, Brightspace, Budibase, BugHerd, Buildkite,
//! BunnyCDN, and Calendly detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. BRIGHTCOVE CLIENT ID ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv16_brightcove_client_id_normal_must_fire() {
    assert_detector_fires(
        "brightcove-api-credentials",
        "brightcove_client_id = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv16_brightcove_client_id_wrong_prefix_must_silent() {
    assert_detector_silent(
        "brightcove-api-credentials",
        "frightcove_client_id = \"0000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv16_brightcove_client_id_evade_zwsp_must_fire() {
    assert_detector_fires(
        "brightcove-api-credentials",
        "brightcove\u{200B}_client_id = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv16_brightcove_client_id_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "brightcove-api-credentials",
        "brightcove_client_id = \"000000000000000000000000000000\u{00AD}0000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv16_brightcove_client_id_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "brightcove-api-credentials",
        "br\u{0457}ghtcove_client_id = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

// =========================================================================
// 2. BRIGHT DATA API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv16_brightdata_api_key_normal_must_fire() {
    assert_detector_fires(
        "brightdata-credentials",
        "brightdata = \"0000000000000000000000000000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
}

#[test]
fn adv16_brightdata_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "brightdata-credentials",
        "drightdata = \"0000000000000000000000000000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv16_brightdata_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "brightdata-credentials",
        "brightdata\u{200B} = \"0000000000000000000000000000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
}

#[test]
fn adv16_brightdata_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "brightdata-credentials",
        "brightdata = \"000000000000000000000000000000000000000000000000000000\u{00AD}0000000000\"",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
}

#[test]
fn adv16_brightdata_api_key_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "brightdata-credentials",
        "br\u{0457}ghtdata = \"0000000000000000000000000000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
}

// =========================================================================
// 3. BRIGHTSPACE APP ID ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv16_brightspace_app_id_normal_must_fire() {
    assert_detector_fires(
        "brightspace-api-credentials",
        "brightspace_app_id = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv16_brightspace_app_id_wrong_prefix_must_silent() {
    assert_detector_silent(
        "brightspace-api-credentials",
        "frightspace_app_id = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv16_brightspace_app_id_evade_zwsp_must_fire() {
    assert_detector_fires(
        "brightspace-api-credentials",
        "brightspace\u{200B}_app_id = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv16_brightspace_app_id_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "brightspace-api-credentials",
        "brightspace_app_id = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv16_brightspace_app_id_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "brightspace-api-credentials",
        "br\u{0457}ghtspace_app_id = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

// =========================================================================
// 4. BUDIBASE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv16_budibase_api_key_normal_must_fire() {
    assert_detector_fires(
        "budibase-credentials",
        "BUDIBASE_API_KEY = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv16_budibase_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "budibase-credentials",
        "FUDIBASE_API_KEY = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv16_budibase_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "budibase-credentials",
        "BUDIBASE\u{200B}_API_KEY = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv16_budibase_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "budibase-credentials",
        "BUDIBASE_API_KEY = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv16_budibase_api_key_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "budibase-credentials",
        "BUD\u{0406}BASE_API_KEY = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

// =========================================================================
// 5. BUGHERD API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv16_bugherd_api_key_normal_must_fire() {
    assert_detector_fires(
        "bugherd-api-key",
        "bugherd_api_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv16_bugherd_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bugherd-api-key",
        "fugherd_api_key = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv16_bugherd_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bugherd-api-key",
        "bugherd\u{200B}_api_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv16_bugherd_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bugherd-api-key",
        "bugherd_api_key = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv16_bugherd_api_key_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "bugherd-api-key",
        "bugh\u{0435}rd_api_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

// =========================================================================
// 6. BUILDKITE AGENT TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv16_buildkite_agent_normal_must_fire() {
    assert_detector_fires(
        "buildkite-agent-token",
        "BUILDKITE_AGENT_TOKEN = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv16_buildkite_agent_wrong_prefix_must_silent() {
    assert_detector_silent(
        "buildkite-agent-token",
        "FUILDKITE_AGENT_TOKEN = \"0000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv16_buildkite_agent_evade_zwsp_must_fire() {
    assert_detector_fires(
        "buildkite-agent-token",
        "BUILDKITE\u{200B}_AGENT_TOKEN = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv16_buildkite_agent_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "buildkite-agent-token",
        "BUILDKITE_AGENT_TOKEN = \"000000000000000000000000000000\u{00AD}0000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv16_buildkite_agent_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "buildkite-agent-token",
        "BU\u{0406}LDKITE_AGENT_TOKEN = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

// =========================================================================
// 7. BUILDKITE API ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv16_buildkite_api_normal_must_fire() {
    assert_detector_fires(
        "buildkite-api-access-token",
        "bkua_00000000000000000000000000000000",
        "bkua_00000000000000000000000000000000",
    );
}

#[test]
fn adv16_buildkite_api_wrong_prefix_must_silent() {
    assert_detector_silent(
        "buildkite-api-access-token",
        "akua_00000000000000000000000000000000",
    );
}

#[test]
fn adv16_buildkite_api_evade_zwsp_must_fire() {
    assert_detector_fires(
        "buildkite-api-access-token",
        "bkua\u{200B}_00000000000000000000000000000000",
        "bkua_00000000000000000000000000000000",
    );
}

#[test]
fn adv16_buildkite_api_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "buildkite-api-access-token",
        "bkua_0000000000000000000000\u{00AD}0000000000",
        "bkua_00000000000000000000000000000000",
    );
}

#[test]
fn adv16_buildkite_api_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "buildkite-api-access-token",
        "bku\u{0430}_00000000000000000000000000000000",
        "bkua_00000000000000000000000000000000",
    );
}

// =========================================================================
// 8. BUNNYCDN API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv16_bunnycdn_normal_must_fire() {
    assert_detector_fires(
        "bunnycdn-api-key",
        "bunny_key = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv16_bunnycdn_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bunnycdn-api-key",
        "funny_key = \"00000000-0000-0000-0000-000000000000\"",
    );
}

#[test]
fn adv16_bunnycdn_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bunnycdn-api-key",
        "bunny\u{200B}_key = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv16_bunnycdn_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bunnycdn-api-key",
        "bunny_key = \"00000000-0000-0000-0000-000000\u{00AD}000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv16_bunnycdn_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "bunnycdn-api-key",
        "bunn\u{0443}_key = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

// =========================================================================
// 9. CALENDLY ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv16_calendly_normal_must_fire() {
    assert_detector_fires(
        "calendly-api-key",
        "calendly_token = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv16_calendly_wrong_prefix_must_silent() {
    assert_detector_silent(
        "calendly-api-key",
        "falendly_token = \"0000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv16_calendly_evade_zwsp_must_fire() {
    assert_detector_fires(
        "calendly-api-key",
        "calendly\u{200B}_token = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv16_calendly_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "calendly-api-key",
        "calendly_token = \"000000000000000000000000000000\u{00AD}0000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv16_calendly_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "calendly-api-key",
        "cal\u{0435}ndly_token = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

// =========================================================================
// 10. CALENDLY WEBHOOK SIGNING KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv16_calendly_webhook_normal_must_fire() {
    assert_detector_fires(
        "calendly-webhook-signing-key",
        "calendly signing_key abcde123456",
        "abcde123456",
    );
}

#[test]
fn adv16_calendly_webhook_wrong_prefix_must_silent() {
    assert_detector_silent(
        "calendly-webhook-signing-key",
        "falendly signing_key abcde123456",
    );
}

#[test]
fn adv16_calendly_webhook_evade_zwsp_must_fire() {
    assert_detector_fires(
        "calendly-webhook-signing-key",
        "calendly\u{200B} signing_key abcde123456",
        "abcde123456",
    );
}

#[test]
fn adv16_calendly_webhook_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "calendly-webhook-signing-key",
        "calendly signing_key abcde\u{00AD}123456",
        "abcde123456",
    );
}

#[test]
fn adv16_calendly_webhook_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "calendly-webhook-signing-key",
        "cal\u{0435}ndly signing_key abcde123456",
        "abcde123456",
    );
}


