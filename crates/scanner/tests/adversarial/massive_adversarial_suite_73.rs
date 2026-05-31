//! Part 73 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates bugherd, buildkite, buildkite, bunnycdn, calendly, campaign, canada, canopy, canva, canvas detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. BUGHERD API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv73_bugherd_api_key_normal_must_fire() {
    assert_detector_fires(
        "bugherd-api-key",
        "BUGHERD_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv73_bugherd_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bugherd-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv73_bugherd_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bugherd-api-key",
        "BUGHERD_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv73_bugherd_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bugherd-api-key",
        "BUGHERD_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv73_bugherd_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "bugherd-api-key",
        "BUGHERD_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv73_bugherd_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "bugherd-api-key",
        "BUGHERD_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv73_bugherd_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "bugherd-api-key",
        "BUGHERD_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv73_bugherd_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "bugherd-api-key",
        "BUGHERD_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv73_bugherd_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "bugherd-api-key",
        "BUGHERD_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv73_bugherd_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "bugherd-api-key",
        "BUGHERD_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv73_bugherd_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "bugherd-api-key",
        "BUGHERD_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv73_bugherd_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "bugherd-api-key",
        "BUGHERD_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 2. BUILDKITE AGENT TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv73_buildkite_agent_token_normal_must_fire() {
    assert_detector_fires(
        "buildkite-agent-token",
        "BUILDKITE_AGENT_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv73_buildkite_agent_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "buildkite-agent-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv73_buildkite_agent_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "buildkite-agent-token",
        "BUILDKITE_AGENT_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200B}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv73_buildkite_agent_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "buildkite-agent-token",
        "BUILDKITE_AGENT_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{00AD}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv73_buildkite_agent_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "buildkite-agent-token",
        "BUILDKITE_AGENT_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200C}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv73_buildkite_agent_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "buildkite-agent-token",
        "BUILDKITE_AGENT_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200D}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv73_buildkite_agent_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "buildkite-agent-token",
        "BUILDKITE_AGENT_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{FEFF}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv73_buildkite_agent_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "buildkite-agent-token",
        "BUILDKITE_AGENT_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{2060}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv73_buildkite_agent_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "buildkite-agent-token",
        "BUILDKITE_AGENT_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{180E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv73_buildkite_agent_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "buildkite-agent-token",
        "BUILDKITE_AGENT_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{202E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv73_buildkite_agent_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "buildkite-agent-token",
        "BUILDKITE_AGENT_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{202C}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv73_buildkite_agent_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "buildkite-agent-token",
        "BUILDKITE_AGENT_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 3. BUILDKITE API ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv73_buildkite_api_access_token_normal_must_fire() {
    assert_detector_fires(
        "buildkite-api-access-token",
        "bkua_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "bkua_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv73_buildkite_api_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "buildkite-api-access-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv73_buildkite_api_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "buildkite-api-access-token",
        "bkua_Kp4Qx7Rm2Sn5T\u{200B}b8Vw3YzKp4Qx7Rm2Sn5",
        "bkua_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv73_buildkite_api_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "buildkite-api-access-token",
        "bkua_Kp4Qx7Rm2Sn5T\u{00AD}b8Vw3YzKp4Qx7Rm2Sn5",
        "bkua_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv73_buildkite_api_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "buildkite-api-access-token",
        "bkua_Kp4Qx7Rm2Sn5T\u{200C}b8Vw3YzKp4Qx7Rm2Sn5",
        "bkua_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv73_buildkite_api_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "buildkite-api-access-token",
        "bkua_Kp4Qx7Rm2Sn5T\u{200D}b8Vw3YzKp4Qx7Rm2Sn5",
        "bkua_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv73_buildkite_api_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "buildkite-api-access-token",
        "bkua_Kp4Qx7Rm2Sn5T\u{FEFF}b8Vw3YzKp4Qx7Rm2Sn5",
        "bkua_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv73_buildkite_api_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "buildkite-api-access-token",
        "bkua_Kp4Qx7Rm2Sn5T\u{2060}b8Vw3YzKp4Qx7Rm2Sn5",
        "bkua_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv73_buildkite_api_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "buildkite-api-access-token",
        "bkua_Kp4Qx7Rm2Sn5T\u{180E}b8Vw3YzKp4Qx7Rm2Sn5",
        "bkua_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv73_buildkite_api_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "buildkite-api-access-token",
        "bkua_Kp4Qx7Rm2Sn5T\u{202E}b8Vw3YzKp4Qx7Rm2Sn5",
        "bkua_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv73_buildkite_api_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "buildkite-api-access-token",
        "bkua_Kp4Qx7Rm2Sn5T\u{202C}b8Vw3YzKp4Qx7Rm2Sn5",
        "bkua_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv73_buildkite_api_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "buildkite-api-access-token",
        "bkua_Kp4Qx7Rm2Sn5T\u{200E}b8Vw3YzKp4Qx7Rm2Sn5",
        "bkua_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 4. BUNNYCDN API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv73_bunnycdn_api_key_normal_must_fire() {
    assert_detector_fires(
        "bunnycdn-api-key",
        "bunnycdn-key=abcdef12-3456-7890-abcd-ef1234567890",
        "abcdef12-3456-7890-abcd-ef1234567890",
    );
}

#[test]
fn adv73_bunnycdn_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bunnycdn-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv73_bunnycdn_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bunnycdn-api-key",
        "bunnycdn-key=abcdef12-3456-7890\u{200B}-abcd-ef1234567890",
        "abcdef12-3456-7890-abcd-ef1234567890",
    );
}

#[test]
fn adv73_bunnycdn_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bunnycdn-api-key",
        "bunnycdn-key=abcdef12-3456-7890\u{00AD}-abcd-ef1234567890",
        "abcdef12-3456-7890-abcd-ef1234567890",
    );
}

#[test]
fn adv73_bunnycdn_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "bunnycdn-api-key",
        "bunnycdn-key=abcdef12-3456-7890\u{200C}-abcd-ef1234567890",
        "abcdef12-3456-7890-abcd-ef1234567890",
    );
}

#[test]
fn adv73_bunnycdn_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "bunnycdn-api-key",
        "bunnycdn-key=abcdef12-3456-7890\u{200D}-abcd-ef1234567890",
        "abcdef12-3456-7890-abcd-ef1234567890",
    );
}

#[test]
fn adv73_bunnycdn_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "bunnycdn-api-key",
        "bunnycdn-key=abcdef12-3456-7890\u{FEFF}-abcd-ef1234567890",
        "abcdef12-3456-7890-abcd-ef1234567890",
    );
}

#[test]
fn adv73_bunnycdn_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "bunnycdn-api-key",
        "bunnycdn-key=abcdef12-3456-7890\u{2060}-abcd-ef1234567890",
        "abcdef12-3456-7890-abcd-ef1234567890",
    );
}

#[test]
fn adv73_bunnycdn_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "bunnycdn-api-key",
        "bunnycdn-key=abcdef12-3456-7890\u{180E}-abcd-ef1234567890",
        "abcdef12-3456-7890-abcd-ef1234567890",
    );
}

#[test]
fn adv73_bunnycdn_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "bunnycdn-api-key",
        "bunnycdn-key=abcdef12-3456-7890\u{202E}-abcd-ef1234567890",
        "abcdef12-3456-7890-abcd-ef1234567890",
    );
}

#[test]
fn adv73_bunnycdn_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "bunnycdn-api-key",
        "bunnycdn-key=abcdef12-3456-7890\u{202C}-abcd-ef1234567890",
        "abcdef12-3456-7890-abcd-ef1234567890",
    );
}

#[test]
fn adv73_bunnycdn_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "bunnycdn-api-key",
        "bunnycdn-key=abcdef12-3456-7890\u{200E}-abcd-ef1234567890",
        "abcdef12-3456-7890-abcd-ef1234567890",
    );
}

// =========================================================================
// 5. CALENDLY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv73_calendly_api_key_normal_must_fire() {
    assert_detector_fires(
        "calendly-api-key",
        "CALENDLY_TOKEN=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv73_calendly_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "calendly-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv73_calendly_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "calendly-api-key",
        "CALENDLY_TOKEN=7b3e5d8c1a9f4e2b6c8d\u{200B}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv73_calendly_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "calendly-api-key",
        "CALENDLY_TOKEN=7b3e5d8c1a9f4e2b6c8d\u{00AD}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv73_calendly_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "calendly-api-key",
        "CALENDLY_TOKEN=7b3e5d8c1a9f4e2b6c8d\u{200C}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv73_calendly_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "calendly-api-key",
        "CALENDLY_TOKEN=7b3e5d8c1a9f4e2b6c8d\u{200D}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv73_calendly_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "calendly-api-key",
        "CALENDLY_TOKEN=7b3e5d8c1a9f4e2b6c8d\u{FEFF}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv73_calendly_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "calendly-api-key",
        "CALENDLY_TOKEN=7b3e5d8c1a9f4e2b6c8d\u{2060}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv73_calendly_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "calendly-api-key",
        "CALENDLY_TOKEN=7b3e5d8c1a9f4e2b6c8d\u{180E}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv73_calendly_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "calendly-api-key",
        "CALENDLY_TOKEN=7b3e5d8c1a9f4e2b6c8d\u{202E}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv73_calendly_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "calendly-api-key",
        "CALENDLY_TOKEN=7b3e5d8c1a9f4e2b6c8d\u{202C}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv73_calendly_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "calendly-api-key",
        "CALENDLY_TOKEN=7b3e5d8c1a9f4e2b6c8d\u{200E}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

// =========================================================================
// 6. CAMPAIGN MONITOR API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv73_campaign_monitor_api_key_normal_must_fire() {
    assert_detector_fires(
        "campaign-monitor-api-key",
        "campaignmonitor_api_key=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv73_campaign_monitor_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "campaign-monitor-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv73_campaign_monitor_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "campaign-monitor-api-key",
        "campaignmonitor_api_key=7b3e5d8c1a9f4e2b6c8d\u{200B}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv73_campaign_monitor_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "campaign-monitor-api-key",
        "campaignmonitor_api_key=7b3e5d8c1a9f4e2b6c8d\u{00AD}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv73_campaign_monitor_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "campaign-monitor-api-key",
        "campaignmonitor_api_key=7b3e5d8c1a9f4e2b6c8d\u{200C}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv73_campaign_monitor_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "campaign-monitor-api-key",
        "campaignmonitor_api_key=7b3e5d8c1a9f4e2b6c8d\u{200D}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv73_campaign_monitor_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "campaign-monitor-api-key",
        "campaignmonitor_api_key=7b3e5d8c1a9f4e2b6c8d\u{FEFF}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv73_campaign_monitor_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "campaign-monitor-api-key",
        "campaignmonitor_api_key=7b3e5d8c1a9f4e2b6c8d\u{2060}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv73_campaign_monitor_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "campaign-monitor-api-key",
        "campaignmonitor_api_key=7b3e5d8c1a9f4e2b6c8d\u{180E}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv73_campaign_monitor_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "campaign-monitor-api-key",
        "campaignmonitor_api_key=7b3e5d8c1a9f4e2b6c8d\u{202E}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv73_campaign_monitor_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "campaign-monitor-api-key",
        "campaignmonitor_api_key=7b3e5d8c1a9f4e2b6c8d\u{202C}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv73_campaign_monitor_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "campaign-monitor-api-key",
        "campaignmonitor_api_key=7b3e5d8c1a9f4e2b6c8d\u{200E}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

// =========================================================================
// 7. CANADA OPEN DATA API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv73_canada_open_data_api_key_normal_must_fire() {
    assert_detector_fires(
        "canada-open-data-api-key",
        "CANADA_API_KEY=7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv73_canada_open_data_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "canada-open-data-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv73_canada_open_data_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "canada-open-data-api-key",
        "CANADA_API_KEY=7b3e5d8c-1a9f-4e2b\u{200B}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv73_canada_open_data_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "canada-open-data-api-key",
        "CANADA_API_KEY=7b3e5d8c-1a9f-4e2b\u{00AD}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv73_canada_open_data_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "canada-open-data-api-key",
        "CANADA_API_KEY=7b3e5d8c-1a9f-4e2b\u{200C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv73_canada_open_data_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "canada-open-data-api-key",
        "CANADA_API_KEY=7b3e5d8c-1a9f-4e2b\u{200D}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv73_canada_open_data_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "canada-open-data-api-key",
        "CANADA_API_KEY=7b3e5d8c-1a9f-4e2b\u{FEFF}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv73_canada_open_data_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "canada-open-data-api-key",
        "CANADA_API_KEY=7b3e5d8c-1a9f-4e2b\u{2060}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv73_canada_open_data_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "canada-open-data-api-key",
        "CANADA_API_KEY=7b3e5d8c-1a9f-4e2b\u{180E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv73_canada_open_data_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "canada-open-data-api-key",
        "CANADA_API_KEY=7b3e5d8c-1a9f-4e2b\u{202E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv73_canada_open_data_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "canada-open-data-api-key",
        "CANADA_API_KEY=7b3e5d8c-1a9f-4e2b\u{202C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv73_canada_open_data_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "canada-open-data-api-key",
        "CANADA_API_KEY=7b3e5d8c-1a9f-4e2b\u{200E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

// =========================================================================
// 8. CANOPY TAX API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv73_canopy_tax_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "canopy-tax-api-credentials",
        "CANOPY_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv73_canopy_tax_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "canopy-tax-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv73_canopy_tax_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "canopy-tax-api-credentials",
        "CANOPY_API_KEY=Kp4Qx7Rm2S\u{200B}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv73_canopy_tax_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "canopy-tax-api-credentials",
        "CANOPY_API_KEY=Kp4Qx7Rm2S\u{00AD}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv73_canopy_tax_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "canopy-tax-api-credentials",
        "CANOPY_API_KEY=Kp4Qx7Rm2S\u{200C}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv73_canopy_tax_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "canopy-tax-api-credentials",
        "CANOPY_API_KEY=Kp4Qx7Rm2S\u{200D}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv73_canopy_tax_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "canopy-tax-api-credentials",
        "CANOPY_API_KEY=Kp4Qx7Rm2S\u{FEFF}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv73_canopy_tax_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "canopy-tax-api-credentials",
        "CANOPY_API_KEY=Kp4Qx7Rm2S\u{2060}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv73_canopy_tax_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "canopy-tax-api-credentials",
        "CANOPY_API_KEY=Kp4Qx7Rm2S\u{180E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv73_canopy_tax_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "canopy-tax-api-credentials",
        "CANOPY_API_KEY=Kp4Qx7Rm2S\u{202E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv73_canopy_tax_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "canopy-tax-api-credentials",
        "CANOPY_API_KEY=Kp4Qx7Rm2S\u{202C}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv73_canopy_tax_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "canopy-tax-api-credentials",
        "CANOPY_API_KEY=Kp4Qx7Rm2S\u{200E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 9. CANVA API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv73_canva_api_token_normal_must_fire() {
    assert_detector_fires(
        "canva-api-token",
        "CANVA_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv73_canva_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "canva-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv73_canva_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "canva-api-token",
        "CANVA_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx\u{200B}7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv73_canva_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "canva-api-token",
        "CANVA_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx\u{00AD}7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv73_canva_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "canva-api-token",
        "CANVA_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx\u{200C}7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv73_canva_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "canva-api-token",
        "CANVA_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx\u{200D}7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv73_canva_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "canva-api-token",
        "CANVA_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx\u{FEFF}7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv73_canva_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "canva-api-token",
        "CANVA_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx\u{2060}7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv73_canva_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "canva-api-token",
        "CANVA_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx\u{180E}7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv73_canva_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "canva-api-token",
        "CANVA_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx\u{202E}7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv73_canva_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "canva-api-token",
        "CANVA_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx\u{202C}7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv73_canva_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "canva-api-token",
        "CANVA_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx\u{200E}7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

// =========================================================================
// 10. CANVAS API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv73_canvas_api_token_normal_must_fire() {
    assert_detector_fires(
        "canvas-api-token",
        "canvas_api_token=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv73_canvas_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "canvas-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv73_canvas_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "canvas-api-token",
        "canvas_api_token=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8\u{200B}Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv73_canvas_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "canvas-api-token",
        "canvas_api_token=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8\u{00AD}Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv73_canvas_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "canvas-api-token",
        "canvas_api_token=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8\u{200C}Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv73_canvas_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "canvas-api-token",
        "canvas_api_token=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8\u{200D}Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv73_canvas_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "canvas-api-token",
        "canvas_api_token=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8\u{FEFF}Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv73_canvas_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "canvas-api-token",
        "canvas_api_token=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8\u{2060}Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv73_canvas_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "canvas-api-token",
        "canvas_api_token=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8\u{180E}Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv73_canvas_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "canvas-api-token",
        "canvas_api_token=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8\u{202E}Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv73_canvas_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "canvas-api-token",
        "canvas_api_token=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8\u{202C}Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}

#[test]
fn adv73_canvas_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "canvas-api-token",
        "canvas_api_token=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8\u{200E}Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S",
    );
}
