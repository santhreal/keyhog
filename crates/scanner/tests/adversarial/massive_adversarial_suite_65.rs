//! Part 65 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates amazon, amplitude, anrok, ansible, anthropic, anydo, anyscale, apify, appdynamics, appium detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. AMAZON MUSIC API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv65_amazon_music_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "amazon-music-api-credentials",
        "AMAZON_MUSIC_CLIENT_ID=amzn.application-oa2-client.7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "amzn.application-oa2-client.7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_amazon_music_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "amazon-music-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv65_amazon_music_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "amazon-music-api-credentials",
        "AMAZON_MUSIC_CLIENT_ID=amzn.application-oa2-client.7b\u{200B}3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "amzn.application-oa2-client.7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_amazon_music_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "amazon-music-api-credentials",
        "AMAZON_MUSIC_CLIENT_ID=amzn.application-oa2-client.7b\u{00AD}3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "amzn.application-oa2-client.7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_amazon_music_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "amazon-music-api-credentials",
        "AMAZON_MUSIC_CLIENT_ID=amzn.application-oa2-client.7b\u{200C}3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "amzn.application-oa2-client.7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_amazon_music_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "amazon-music-api-credentials",
        "AMAZON_MUSIC_CLIENT_ID=amzn.application-oa2-client.7b\u{200D}3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "amzn.application-oa2-client.7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_amazon_music_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "amazon-music-api-credentials",
        "AMAZON_MUSIC_CLIENT_ID=amzn.application-oa2-client.7b\u{FEFF}3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "amzn.application-oa2-client.7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_amazon_music_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "amazon-music-api-credentials",
        "AMAZON_MUSIC_CLIENT_ID=amzn.application-oa2-client.7b\u{2060}3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "amzn.application-oa2-client.7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_amazon_music_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "amazon-music-api-credentials",
        "AMAZON_MUSIC_CLIENT_ID=amzn.application-oa2-client.7b\u{180E}3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "amzn.application-oa2-client.7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_amazon_music_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "amazon-music-api-credentials",
        "AMAZON_MUSIC_CLIENT_ID=amzn.application-oa2-client.7b\u{202E}3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "amzn.application-oa2-client.7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_amazon_music_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "amazon-music-api-credentials",
        "AMAZON_MUSIC_CLIENT_ID=amzn.application-oa2-client.7b\u{202C}3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "amzn.application-oa2-client.7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_amazon_music_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "amazon-music-api-credentials",
        "AMAZON_MUSIC_CLIENT_ID=amzn.application-oa2-client.7b\u{200E}3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "amzn.application-oa2-client.7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 2. AMPLITUDE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv65_amplitude_api_key_normal_must_fire() {
    assert_detector_fires(
        "amplitude-api-key",
        "AMPLITUDE_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_amplitude_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "amplitude-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv65_amplitude_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "amplitude-api-key",
        "AMPLITUDE_API_KEY=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_amplitude_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "amplitude-api-key",
        "AMPLITUDE_API_KEY=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_amplitude_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "amplitude-api-key",
        "AMPLITUDE_API_KEY=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_amplitude_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "amplitude-api-key",
        "AMPLITUDE_API_KEY=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_amplitude_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "amplitude-api-key",
        "AMPLITUDE_API_KEY=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_amplitude_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "amplitude-api-key",
        "AMPLITUDE_API_KEY=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_amplitude_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "amplitude-api-key",
        "AMPLITUDE_API_KEY=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_amplitude_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "amplitude-api-key",
        "AMPLITUDE_API_KEY=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_amplitude_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "amplitude-api-key",
        "AMPLITUDE_API_KEY=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_amplitude_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "amplitude-api-key",
        "AMPLITUDE_API_KEY=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 3. ANROK API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv65_anrok_api_key_normal_must_fire() {
    assert_detector_fires(
        "anrok-api-key",
        "ANROK_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv65_anrok_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("anrok-api-key", "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv65_anrok_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "anrok-api-key",
        "ANROK_API_KEY=Kp4Qx7Rm2Sn5\u{200B}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv65_anrok_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "anrok-api-key",
        "ANROK_API_KEY=Kp4Qx7Rm2Sn5\u{00AD}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv65_anrok_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "anrok-api-key",
        "ANROK_API_KEY=Kp4Qx7Rm2Sn5\u{200C}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv65_anrok_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "anrok-api-key",
        "ANROK_API_KEY=Kp4Qx7Rm2Sn5\u{200D}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv65_anrok_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "anrok-api-key",
        "ANROK_API_KEY=Kp4Qx7Rm2Sn5\u{FEFF}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv65_anrok_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "anrok-api-key",
        "ANROK_API_KEY=Kp4Qx7Rm2Sn5\u{2060}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv65_anrok_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "anrok-api-key",
        "ANROK_API_KEY=Kp4Qx7Rm2Sn5\u{180E}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv65_anrok_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "anrok-api-key",
        "ANROK_API_KEY=Kp4Qx7Rm2Sn5\u{202E}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv65_anrok_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "anrok-api-key",
        "ANROK_API_KEY=Kp4Qx7Rm2Sn5\u{202C}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv65_anrok_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "anrok-api-key",
        "ANROK_API_KEY=Kp4Qx7Rm2Sn5\u{200E}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

// =========================================================================
// 4. ANSIBLE TOWER TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv65_ansible_tower_token_normal_must_fire() {
    assert_detector_fires(
        "ansible-tower-token",
        "TOWER_OAUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv65_ansible_tower_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ansible-tower-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv65_ansible_tower_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ansible-tower-token",
        "TOWER_OAUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200B}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv65_ansible_tower_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ansible-tower-token",
        "TOWER_OAUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{00AD}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv65_ansible_tower_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "ansible-tower-token",
        "TOWER_OAUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200C}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv65_ansible_tower_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "ansible-tower-token",
        "TOWER_OAUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200D}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv65_ansible_tower_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "ansible-tower-token",
        "TOWER_OAUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{FEFF}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv65_ansible_tower_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "ansible-tower-token",
        "TOWER_OAUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{2060}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv65_ansible_tower_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "ansible-tower-token",
        "TOWER_OAUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{180E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv65_ansible_tower_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "ansible-tower-token",
        "TOWER_OAUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{202E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv65_ansible_tower_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "ansible-tower-token",
        "TOWER_OAUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{202C}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv65_ansible_tower_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "ansible-tower-token",
        "TOWER_OAUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 5. ANTHROPIC API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv65_anthropic_api_key_normal_must_fire() {
    assert_detector_fires(
        "anthropic-api-key",
        "ANTHROPIC_API_KEY=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",
        "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",
    );
}

#[test]
fn adv65_anthropic_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "anthropic-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv65_anthropic_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "anthropic-api-key",
        "ANTHROPIC_API_KEY=sk-ant-api03-UpNypxiqd66--KzESwKRmOaZMPHmmJWGCMMzWuI6i\u{200B}puD3w-9-nZ9_9cFIso-A9WEUSQOXHjziIc5M5CGVlNb5g-hcCLzwAA",
        "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",
    );
}

#[test]
fn adv65_anthropic_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "anthropic-api-key",
        "ANTHROPIC_API_KEY=sk-ant-api03-UpNypxiqd66--KzESwKRmOaZMPHmmJWGCMMzWuI6i\u{00AD}puD3w-9-nZ9_9cFIso-A9WEUSQOXHjziIc5M5CGVlNb5g-hcCLzwAA",
        "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",
    );
}

#[test]
fn adv65_anthropic_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "anthropic-api-key",
        "ANTHROPIC_API_KEY=sk-ant-api03-UpNypxiqd66--KzESwKRmOaZMPHmmJWGCMMzWuI6i\u{200C}puD3w-9-nZ9_9cFIso-A9WEUSQOXHjziIc5M5CGVlNb5g-hcCLzwAA",
        "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",
    );
}

#[test]
fn adv65_anthropic_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "anthropic-api-key",
        "ANTHROPIC_API_KEY=sk-ant-api03-UpNypxiqd66--KzESwKRmOaZMPHmmJWGCMMzWuI6i\u{200D}puD3w-9-nZ9_9cFIso-A9WEUSQOXHjziIc5M5CGVlNb5g-hcCLzwAA",
        "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",
    );
}

#[test]
fn adv65_anthropic_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "anthropic-api-key",
        "ANTHROPIC_API_KEY=sk-ant-api03-UpNypxiqd66--KzESwKRmOaZMPHmmJWGCMMzWuI6i\u{FEFF}puD3w-9-nZ9_9cFIso-A9WEUSQOXHjziIc5M5CGVlNb5g-hcCLzwAA",
        "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",
    );
}

#[test]
fn adv65_anthropic_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "anthropic-api-key",
        "ANTHROPIC_API_KEY=sk-ant-api03-UpNypxiqd66--KzESwKRmOaZMPHmmJWGCMMzWuI6i\u{2060}puD3w-9-nZ9_9cFIso-A9WEUSQOXHjziIc5M5CGVlNb5g-hcCLzwAA",
        "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",
    );
}

#[test]
fn adv65_anthropic_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "anthropic-api-key",
        "ANTHROPIC_API_KEY=sk-ant-api03-UpNypxiqd66--KzESwKRmOaZMPHmmJWGCMMzWuI6i\u{180E}puD3w-9-nZ9_9cFIso-A9WEUSQOXHjziIc5M5CGVlNb5g-hcCLzwAA",
        "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",
    );
}

#[test]
fn adv65_anthropic_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "anthropic-api-key",
        "ANTHROPIC_API_KEY=sk-ant-api03-UpNypxiqd66--KzESwKRmOaZMPHmmJWGCMMzWuI6i\u{202E}puD3w-9-nZ9_9cFIso-A9WEUSQOXHjziIc5M5CGVlNb5g-hcCLzwAA",
        "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",
    );
}

#[test]
fn adv65_anthropic_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "anthropic-api-key",
        "ANTHROPIC_API_KEY=sk-ant-api03-UpNypxiqd66--KzESwKRmOaZMPHmmJWGCMMzWuI6i\u{202C}puD3w-9-nZ9_9cFIso-A9WEUSQOXHjziIc5M5CGVlNb5g-hcCLzwAA",
        "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",
    );
}

#[test]
fn adv65_anthropic_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "anthropic-api-key",
        "ANTHROPIC_API_KEY=sk-ant-api03-UpNypxiqd66--KzESwKRmOaZMPHmmJWGCMMzWuI6i\u{200E}puD3w-9-nZ9_9cFIso-A9WEUSQOXHjziIc5M5CGVlNb5g-hcCLzwAA",
        "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",
    );
}

// =========================================================================
// 6. ANYDO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv65_anydo_api_key_normal_must_fire() {
    assert_detector_fires(
        "anydo-api-key",
        "ANYDO_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv65_anydo_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "anydo-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv65_anydo_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "anydo-api-key",
        "ANYDO_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{200B}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv65_anydo_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "anydo-api-key",
        "ANYDO_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{00AD}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv65_anydo_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "anydo-api-key",
        "ANYDO_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{200C}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv65_anydo_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "anydo-api-key",
        "ANYDO_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{200D}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv65_anydo_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "anydo-api-key",
        "ANYDO_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{FEFF}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv65_anydo_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "anydo-api-key",
        "ANYDO_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{2060}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv65_anydo_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "anydo-api-key",
        "ANYDO_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{180E}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv65_anydo_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "anydo-api-key",
        "ANYDO_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{202E}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv65_anydo_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "anydo-api-key",
        "ANYDO_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{202C}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv65_anydo_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "anydo-api-key",
        "ANYDO_API_KEY=Kp4Qx7Rm2Sn5Tb8\u{200E}Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

// =========================================================================
// 7. ANYSCALE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv65_anyscale_api_key_normal_must_fire() {
    assert_detector_fires(
        "anyscale-api-key",
        "anyscale_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7RmKp",
        "anyscale_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7RmKp",
    );
}

#[test]
fn adv65_anyscale_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "anyscale-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv65_anyscale_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "anyscale-api-key",
        "anyscale_Kp4Qx7Rm2S\u{200B}n5Tb8Vw3YzKp4Qx7RmKp",
        "anyscale_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7RmKp",
    );
}

#[test]
fn adv65_anyscale_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "anyscale-api-key",
        "anyscale_Kp4Qx7Rm2S\u{00AD}n5Tb8Vw3YzKp4Qx7RmKp",
        "anyscale_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7RmKp",
    );
}

#[test]
fn adv65_anyscale_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "anyscale-api-key",
        "anyscale_Kp4Qx7Rm2S\u{200C}n5Tb8Vw3YzKp4Qx7RmKp",
        "anyscale_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7RmKp",
    );
}

#[test]
fn adv65_anyscale_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "anyscale-api-key",
        "anyscale_Kp4Qx7Rm2S\u{200D}n5Tb8Vw3YzKp4Qx7RmKp",
        "anyscale_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7RmKp",
    );
}

#[test]
fn adv65_anyscale_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "anyscale-api-key",
        "anyscale_Kp4Qx7Rm2S\u{FEFF}n5Tb8Vw3YzKp4Qx7RmKp",
        "anyscale_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7RmKp",
    );
}

#[test]
fn adv65_anyscale_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "anyscale-api-key",
        "anyscale_Kp4Qx7Rm2S\u{2060}n5Tb8Vw3YzKp4Qx7RmKp",
        "anyscale_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7RmKp",
    );
}

#[test]
fn adv65_anyscale_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "anyscale-api-key",
        "anyscale_Kp4Qx7Rm2S\u{180E}n5Tb8Vw3YzKp4Qx7RmKp",
        "anyscale_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7RmKp",
    );
}

#[test]
fn adv65_anyscale_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "anyscale-api-key",
        "anyscale_Kp4Qx7Rm2S\u{202E}n5Tb8Vw3YzKp4Qx7RmKp",
        "anyscale_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7RmKp",
    );
}

#[test]
fn adv65_anyscale_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "anyscale-api-key",
        "anyscale_Kp4Qx7Rm2S\u{202C}n5Tb8Vw3YzKp4Qx7RmKp",
        "anyscale_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7RmKp",
    );
}

#[test]
fn adv65_anyscale_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "anyscale-api-key",
        "anyscale_Kp4Qx7Rm2S\u{200E}n5Tb8Vw3YzKp4Qx7RmKp",
        "anyscale_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7RmKp",
    );
}

// =========================================================================
// 8. APIFY API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv65_apify_api_token_normal_must_fire() {
    assert_detector_fires(
        "apify-api-token",
        "apify_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7",
        "apify_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7",
    );
}

#[test]
fn adv65_apify_api_token_wrong_prefix_must_silent() {
    assert_detector_silent("apify-api-token", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv65_apify_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "apify-api-token",
        "apify_api_Kp4Qx7Rm\u{200B}2Sn5Tb8Vw3YzKp4Qx7",
        "apify_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7",
    );
}

#[test]
fn adv65_apify_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "apify-api-token",
        "apify_api_Kp4Qx7Rm\u{00AD}2Sn5Tb8Vw3YzKp4Qx7",
        "apify_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7",
    );
}

#[test]
fn adv65_apify_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "apify-api-token",
        "apify_api_Kp4Qx7Rm\u{200C}2Sn5Tb8Vw3YzKp4Qx7",
        "apify_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7",
    );
}

#[test]
fn adv65_apify_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "apify-api-token",
        "apify_api_Kp4Qx7Rm\u{200D}2Sn5Tb8Vw3YzKp4Qx7",
        "apify_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7",
    );
}

#[test]
fn adv65_apify_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "apify-api-token",
        "apify_api_Kp4Qx7Rm\u{FEFF}2Sn5Tb8Vw3YzKp4Qx7",
        "apify_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7",
    );
}

#[test]
fn adv65_apify_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "apify-api-token",
        "apify_api_Kp4Qx7Rm\u{2060}2Sn5Tb8Vw3YzKp4Qx7",
        "apify_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7",
    );
}

#[test]
fn adv65_apify_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "apify-api-token",
        "apify_api_Kp4Qx7Rm\u{180E}2Sn5Tb8Vw3YzKp4Qx7",
        "apify_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7",
    );
}

#[test]
fn adv65_apify_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "apify-api-token",
        "apify_api_Kp4Qx7Rm\u{202E}2Sn5Tb8Vw3YzKp4Qx7",
        "apify_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7",
    );
}

#[test]
fn adv65_apify_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "apify-api-token",
        "apify_api_Kp4Qx7Rm\u{202C}2Sn5Tb8Vw3YzKp4Qx7",
        "apify_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7",
    );
}

#[test]
fn adv65_apify_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "apify-api-token",
        "apify_api_Kp4Qx7Rm\u{200E}2Sn5Tb8Vw3YzKp4Qx7",
        "apify_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7",
    );
}

// =========================================================================
// 9. APPDYNAMICS API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv65_appdynamics_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "appdynamics-api-credentials",
        "X-AppD-API-Key=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_appdynamics_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "appdynamics-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv65_appdynamics_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "appdynamics-api-credentials",
        "X-AppD-API-Key=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_appdynamics_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "appdynamics-api-credentials",
        "X-AppD-API-Key=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_appdynamics_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "appdynamics-api-credentials",
        "X-AppD-API-Key=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_appdynamics_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "appdynamics-api-credentials",
        "X-AppD-API-Key=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_appdynamics_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "appdynamics-api-credentials",
        "X-AppD-API-Key=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_appdynamics_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "appdynamics-api-credentials",
        "X-AppD-API-Key=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_appdynamics_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "appdynamics-api-credentials",
        "X-AppD-API-Key=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_appdynamics_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "appdynamics-api-credentials",
        "X-AppD-API-Key=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_appdynamics_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "appdynamics-api-credentials",
        "X-AppD-API-Key=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_appdynamics_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "appdynamics-api-credentials",
        "X-AppD-API-Key=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 10. APPIUM CLOUD CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv65_appium_cloud_credentials_normal_must_fire() {
    assert_detector_fires(
        "appium-cloud-credentials",
        "LT_ACCESS_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_appium_cloud_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "appium-cloud-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv65_appium_cloud_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "appium-cloud-credentials",
        "LT_ACCESS_KEY=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_appium_cloud_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "appium-cloud-credentials",
        "LT_ACCESS_KEY=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_appium_cloud_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "appium-cloud-credentials",
        "LT_ACCESS_KEY=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_appium_cloud_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "appium-cloud-credentials",
        "LT_ACCESS_KEY=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_appium_cloud_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "appium-cloud-credentials",
        "LT_ACCESS_KEY=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_appium_cloud_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "appium-cloud-credentials",
        "LT_ACCESS_KEY=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_appium_cloud_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "appium-cloud-credentials",
        "LT_ACCESS_KEY=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_appium_cloud_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "appium-cloud-credentials",
        "LT_ACCESS_KEY=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_appium_cloud_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "appium-cloud-credentials",
        "LT_ACCESS_KEY=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv65_appium_cloud_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "appium-cloud-credentials",
        "LT_ACCESS_KEY=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}
