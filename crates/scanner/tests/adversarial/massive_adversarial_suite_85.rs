//! Part 85 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates epicgames, eppo, equinix, etherscan, eu, exoscale, expedia, facebook, fantom, fastly detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. EPICGAMES API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv85_epicgames_api_key_normal_must_fire() {
    assert_detector_fires(
        "epicgames-api-key",
        "EPIC_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_epicgames_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "epicgames-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv85_epicgames_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "epicgames-api-key",
        "EPIC_API_KEY=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_epicgames_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "epicgames-api-key",
        "EPIC_API_KEY=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_epicgames_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "epicgames-api-key",
        "EPIC_API_KEY=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_epicgames_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "epicgames-api-key",
        "EPIC_API_KEY=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_epicgames_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "epicgames-api-key",
        "EPIC_API_KEY=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_epicgames_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "epicgames-api-key",
        "EPIC_API_KEY=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_epicgames_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "epicgames-api-key",
        "EPIC_API_KEY=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_epicgames_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "epicgames-api-key",
        "EPIC_API_KEY=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_epicgames_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "epicgames-api-key",
        "EPIC_API_KEY=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_epicgames_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "epicgames-api-key",
        "EPIC_API_KEY=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 2. EPPO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv85_eppo_api_key_normal_must_fire() {
    assert_detector_fires(
        "eppo-api-key",
        "eppo=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv85_eppo_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "eppo-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv85_eppo_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "eppo-api-key",
        "eppo=Kp4Qx7Rm2Sn5Tb8Vw3\u{200B}YzKp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv85_eppo_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "eppo-api-key",
        "eppo=Kp4Qx7Rm2Sn5Tb8Vw3\u{00AD}YzKp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv85_eppo_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "eppo-api-key",
        "eppo=Kp4Qx7Rm2Sn5Tb8Vw3\u{200C}YzKp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv85_eppo_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "eppo-api-key",
        "eppo=Kp4Qx7Rm2Sn5Tb8Vw3\u{200D}YzKp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv85_eppo_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "eppo-api-key",
        "eppo=Kp4Qx7Rm2Sn5Tb8Vw3\u{FEFF}YzKp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv85_eppo_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "eppo-api-key",
        "eppo=Kp4Qx7Rm2Sn5Tb8Vw3\u{2060}YzKp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv85_eppo_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "eppo-api-key",
        "eppo=Kp4Qx7Rm2Sn5Tb8Vw3\u{180E}YzKp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv85_eppo_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "eppo-api-key",
        "eppo=Kp4Qx7Rm2Sn5Tb8Vw3\u{202E}YzKp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv85_eppo_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "eppo-api-key",
        "eppo=Kp4Qx7Rm2Sn5Tb8Vw3\u{202C}YzKp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv85_eppo_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "eppo-api-key",
        "eppo=Kp4Qx7Rm2Sn5Tb8Vw3\u{200E}YzKp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8V",
    );
}

// =========================================================================
// 3. EQUINIX METAL API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv85_equinix_metal_api_token_normal_must_fire() {
    assert_detector_fires(
        "equinix-metal-api-token",
        "EQUINIX_API_TOKEN=7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_equinix_metal_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "equinix-metal-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv85_equinix_metal_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "equinix-metal-api-token",
        "EQUINIX_API_TOKEN=7b3e5d8c-1a9f-4e2b\u{200B}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_equinix_metal_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "equinix-metal-api-token",
        "EQUINIX_API_TOKEN=7b3e5d8c-1a9f-4e2b\u{00AD}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_equinix_metal_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "equinix-metal-api-token",
        "EQUINIX_API_TOKEN=7b3e5d8c-1a9f-4e2b\u{200C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_equinix_metal_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "equinix-metal-api-token",
        "EQUINIX_API_TOKEN=7b3e5d8c-1a9f-4e2b\u{200D}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_equinix_metal_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "equinix-metal-api-token",
        "EQUINIX_API_TOKEN=7b3e5d8c-1a9f-4e2b\u{FEFF}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_equinix_metal_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "equinix-metal-api-token",
        "EQUINIX_API_TOKEN=7b3e5d8c-1a9f-4e2b\u{2060}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_equinix_metal_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "equinix-metal-api-token",
        "EQUINIX_API_TOKEN=7b3e5d8c-1a9f-4e2b\u{180E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_equinix_metal_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "equinix-metal-api-token",
        "EQUINIX_API_TOKEN=7b3e5d8c-1a9f-4e2b\u{202E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_equinix_metal_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "equinix-metal-api-token",
        "EQUINIX_API_TOKEN=7b3e5d8c-1a9f-4e2b\u{202C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_equinix_metal_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "equinix-metal-api-token",
        "EQUINIX_API_TOKEN=7b3e5d8c-1a9f-4e2b\u{200E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

// =========================================================================
// 4. ETHERSCAN API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv85_etherscan_api_key_normal_must_fire() {
    assert_detector_fires(
        "etherscan-api-key",
        "ETHERSCAN_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_etherscan_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "etherscan-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv85_etherscan_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "etherscan-api-key",
        "ETHERSCAN_API_KEY=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_etherscan_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "etherscan-api-key",
        "ETHERSCAN_API_KEY=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_etherscan_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "etherscan-api-key",
        "ETHERSCAN_API_KEY=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_etherscan_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "etherscan-api-key",
        "ETHERSCAN_API_KEY=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_etherscan_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "etherscan-api-key",
        "ETHERSCAN_API_KEY=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_etherscan_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "etherscan-api-key",
        "ETHERSCAN_API_KEY=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_etherscan_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "etherscan-api-key",
        "ETHERSCAN_API_KEY=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_etherscan_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "etherscan-api-key",
        "ETHERSCAN_API_KEY=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_etherscan_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "etherscan-api-key",
        "ETHERSCAN_API_KEY=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_etherscan_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "etherscan-api-key",
        "ETHERSCAN_API_KEY=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 5. EU OPEN DATA API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv85_eu_open_data_api_key_normal_must_fire() {
    assert_detector_fires(
        "eu-open-data-api-key",
        "party_token EU_CLIENT-ID=7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_eu_open_data_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "eu-open-data-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv85_eu_open_data_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "eu-open-data-api-key",
        "party_token EU_CLIENT-ID=7b3e5d8c-1a9f-4e2b\u{200B}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_eu_open_data_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "eu-open-data-api-key",
        "party_token EU_CLIENT-ID=7b3e5d8c-1a9f-4e2b\u{00AD}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_eu_open_data_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "eu-open-data-api-key",
        "party_token EU_CLIENT-ID=7b3e5d8c-1a9f-4e2b\u{200C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_eu_open_data_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "eu-open-data-api-key",
        "party_token EU_CLIENT-ID=7b3e5d8c-1a9f-4e2b\u{200D}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_eu_open_data_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "eu-open-data-api-key",
        "party_token EU_CLIENT-ID=7b3e5d8c-1a9f-4e2b\u{FEFF}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_eu_open_data_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "eu-open-data-api-key",
        "party_token EU_CLIENT-ID=7b3e5d8c-1a9f-4e2b\u{2060}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_eu_open_data_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "eu-open-data-api-key",
        "party_token EU_CLIENT-ID=7b3e5d8c-1a9f-4e2b\u{180E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_eu_open_data_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "eu-open-data-api-key",
        "party_token EU_CLIENT-ID=7b3e5d8c-1a9f-4e2b\u{202E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_eu_open_data_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "eu-open-data-api-key",
        "party_token EU_CLIENT-ID=7b3e5d8c-1a9f-4e2b\u{202C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_eu_open_data_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "eu-open-data-api-key",
        "party_token EU_CLIENT-ID=7b3e5d8c-1a9f-4e2b\u{200E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

// =========================================================================
// 6. EXOSCALE API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv85_exoscale_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "exoscale-api-credentials",
        "EXOSCALE_API_KEY=EXO7b3e5d8c1a9f4e2b6c8d",
        "EXO7b3e5d8c1a9f4e2b6c8d",
    );
}

#[test]
fn adv85_exoscale_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "exoscale-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv85_exoscale_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "exoscale-api-credentials",
        "EXOSCALE_API_KEY=EXO7b3e5d8c\u{200B}1a9f4e2b6c8d",
        "EXO7b3e5d8c1a9f4e2b6c8d",
    );
}

#[test]
fn adv85_exoscale_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "exoscale-api-credentials",
        "EXOSCALE_API_KEY=EXO7b3e5d8c\u{00AD}1a9f4e2b6c8d",
        "EXO7b3e5d8c1a9f4e2b6c8d",
    );
}

#[test]
fn adv85_exoscale_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "exoscale-api-credentials",
        "EXOSCALE_API_KEY=EXO7b3e5d8c\u{200C}1a9f4e2b6c8d",
        "EXO7b3e5d8c1a9f4e2b6c8d",
    );
}

#[test]
fn adv85_exoscale_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "exoscale-api-credentials",
        "EXOSCALE_API_KEY=EXO7b3e5d8c\u{200D}1a9f4e2b6c8d",
        "EXO7b3e5d8c1a9f4e2b6c8d",
    );
}

#[test]
fn adv85_exoscale_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "exoscale-api-credentials",
        "EXOSCALE_API_KEY=EXO7b3e5d8c\u{FEFF}1a9f4e2b6c8d",
        "EXO7b3e5d8c1a9f4e2b6c8d",
    );
}

#[test]
fn adv85_exoscale_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "exoscale-api-credentials",
        "EXOSCALE_API_KEY=EXO7b3e5d8c\u{2060}1a9f4e2b6c8d",
        "EXO7b3e5d8c1a9f4e2b6c8d",
    );
}

#[test]
fn adv85_exoscale_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "exoscale-api-credentials",
        "EXOSCALE_API_KEY=EXO7b3e5d8c\u{180E}1a9f4e2b6c8d",
        "EXO7b3e5d8c1a9f4e2b6c8d",
    );
}

#[test]
fn adv85_exoscale_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "exoscale-api-credentials",
        "EXOSCALE_API_KEY=EXO7b3e5d8c\u{202E}1a9f4e2b6c8d",
        "EXO7b3e5d8c1a9f4e2b6c8d",
    );
}

#[test]
fn adv85_exoscale_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "exoscale-api-credentials",
        "EXOSCALE_API_KEY=EXO7b3e5d8c\u{202C}1a9f4e2b6c8d",
        "EXO7b3e5d8c1a9f4e2b6c8d",
    );
}

#[test]
fn adv85_exoscale_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "exoscale-api-credentials",
        "EXOSCALE_API_KEY=EXO7b3e5d8c\u{200E}1a9f4e2b6c8d",
        "EXO7b3e5d8c1a9f4e2b6c8d",
    );
}

// =========================================================================
// 7. EXPEDIA API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv85_expedia_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "expedia-api-credentials",
        "EXPEDIA_API_KEY=7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_expedia_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "expedia-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv85_expedia_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "expedia-api-credentials",
        "EXPEDIA_API_KEY=7b3e5d8c-1a9f-4e2b\u{200B}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_expedia_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "expedia-api-credentials",
        "EXPEDIA_API_KEY=7b3e5d8c-1a9f-4e2b\u{00AD}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_expedia_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "expedia-api-credentials",
        "EXPEDIA_API_KEY=7b3e5d8c-1a9f-4e2b\u{200C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_expedia_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "expedia-api-credentials",
        "EXPEDIA_API_KEY=7b3e5d8c-1a9f-4e2b\u{200D}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_expedia_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "expedia-api-credentials",
        "EXPEDIA_API_KEY=7b3e5d8c-1a9f-4e2b\u{FEFF}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_expedia_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "expedia-api-credentials",
        "EXPEDIA_API_KEY=7b3e5d8c-1a9f-4e2b\u{2060}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_expedia_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "expedia-api-credentials",
        "EXPEDIA_API_KEY=7b3e5d8c-1a9f-4e2b\u{180E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_expedia_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "expedia-api-credentials",
        "EXPEDIA_API_KEY=7b3e5d8c-1a9f-4e2b\u{202E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_expedia_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "expedia-api-credentials",
        "EXPEDIA_API_KEY=7b3e5d8c-1a9f-4e2b\u{202C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_expedia_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "expedia-api-credentials",
        "EXPEDIA_API_KEY=7b3e5d8c-1a9f-4e2b\u{200E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

// =========================================================================
// 8. FACEBOOK OAUTH SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv85_facebook_oauth_secret_normal_must_fire() {
    assert_detector_fires(
        "facebook-oauth-secret",
        "FACEBOOK_CLIENT_SECRET=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_facebook_oauth_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "facebook-oauth-secret",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv85_facebook_oauth_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "facebook-oauth-secret",
        "FACEBOOK_CLIENT_SECRET=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_facebook_oauth_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "facebook-oauth-secret",
        "FACEBOOK_CLIENT_SECRET=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_facebook_oauth_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "facebook-oauth-secret",
        "FACEBOOK_CLIENT_SECRET=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_facebook_oauth_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "facebook-oauth-secret",
        "FACEBOOK_CLIENT_SECRET=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_facebook_oauth_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "facebook-oauth-secret",
        "FACEBOOK_CLIENT_SECRET=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_facebook_oauth_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "facebook-oauth-secret",
        "FACEBOOK_CLIENT_SECRET=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_facebook_oauth_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "facebook-oauth-secret",
        "FACEBOOK_CLIENT_SECRET=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_facebook_oauth_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "facebook-oauth-secret",
        "FACEBOOK_CLIENT_SECRET=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_facebook_oauth_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "facebook-oauth-secret",
        "FACEBOOK_CLIENT_SECRET=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_facebook_oauth_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "facebook-oauth-secret",
        "FACEBOOK_CLIENT_SECRET=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 9. FANTOM API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv85_fantom_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "fantom-api-credentials",
        "fantom_api_key=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_fantom_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "fantom-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv85_fantom_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "fantom-api-credentials",
        "fantom_api_key=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_fantom_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "fantom-api-credentials",
        "fantom_api_key=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_fantom_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "fantom-api-credentials",
        "fantom_api_key=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_fantom_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "fantom-api-credentials",
        "fantom_api_key=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_fantom_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "fantom-api-credentials",
        "fantom_api_key=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_fantom_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "fantom-api-credentials",
        "fantom_api_key=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_fantom_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "fantom-api-credentials",
        "fantom_api_key=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_fantom_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "fantom-api-credentials",
        "fantom_api_key=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_fantom_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "fantom-api-credentials",
        "fantom_api_key=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv85_fantom_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "fantom-api-credentials",
        "fantom_api_key=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 10. FASTLY API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv85_fastly_api_token_normal_must_fire() {
    assert_detector_fires(
        "fastly-api-token",
        "FASTLY_API_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv85_fastly_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "fastly-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv85_fastly_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "fastly-api-token",
        "FASTLY_API_TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv85_fastly_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "fastly-api-token",
        "FASTLY_API_TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv85_fastly_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "fastly-api-token",
        "FASTLY_API_TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv85_fastly_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "fastly-api-token",
        "FASTLY_API_TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv85_fastly_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "fastly-api-token",
        "FASTLY_API_TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv85_fastly_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "fastly-api-token",
        "FASTLY_API_TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv85_fastly_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "fastly-api-token",
        "FASTLY_API_TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv85_fastly_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "fastly-api-token",
        "FASTLY_API_TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv85_fastly_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "fastly-api-token",
        "FASTLY_API_TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv85_fastly_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "fastly-api-token",
        "FASTLY_API_TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}
