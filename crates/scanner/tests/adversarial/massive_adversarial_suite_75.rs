//! Part 75 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates checkly, checkmarx, checkout, chef, cherryservers, chippercash, chromadb, circleci, classlink, clerk detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. CHECKLY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv75_checkly_api_key_normal_must_fire() {
    assert_detector_fires(
        "checkly-api-key",
        "CHECKLY_API_KEY=cu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
        "cu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv75_checkly_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "checkly-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv75_checkly_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "checkly-api-key",
        "CHECKLY_API_KEY=cu_Kp4Qx7Rm2S\u{200B}n5Tb8Vw3YzKp4Q",
        "cu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv75_checkly_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "checkly-api-key",
        "CHECKLY_API_KEY=cu_Kp4Qx7Rm2S\u{00AD}n5Tb8Vw3YzKp4Q",
        "cu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv75_checkly_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "checkly-api-key",
        "CHECKLY_API_KEY=cu_Kp4Qx7Rm2S\u{200C}n5Tb8Vw3YzKp4Q",
        "cu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv75_checkly_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "checkly-api-key",
        "CHECKLY_API_KEY=cu_Kp4Qx7Rm2S\u{200D}n5Tb8Vw3YzKp4Q",
        "cu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv75_checkly_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "checkly-api-key",
        "CHECKLY_API_KEY=cu_Kp4Qx7Rm2S\u{FEFF}n5Tb8Vw3YzKp4Q",
        "cu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv75_checkly_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "checkly-api-key",
        "CHECKLY_API_KEY=cu_Kp4Qx7Rm2S\u{2060}n5Tb8Vw3YzKp4Q",
        "cu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv75_checkly_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "checkly-api-key",
        "CHECKLY_API_KEY=cu_Kp4Qx7Rm2S\u{180E}n5Tb8Vw3YzKp4Q",
        "cu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv75_checkly_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "checkly-api-key",
        "CHECKLY_API_KEY=cu_Kp4Qx7Rm2S\u{202E}n5Tb8Vw3YzKp4Q",
        "cu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv75_checkly_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "checkly-api-key",
        "CHECKLY_API_KEY=cu_Kp4Qx7Rm2S\u{202C}n5Tb8Vw3YzKp4Q",
        "cu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv75_checkly_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "checkly-api-key",
        "CHECKLY_API_KEY=cu_Kp4Qx7Rm2S\u{200E}n5Tb8Vw3YzKp4Q",
        "cu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

// =========================================================================
// 2. CHECKMARX API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv75_checkmarx_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "checkmarx-api-credentials",
        "CHECKMARX_CLIENT_ID=7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv75_checkmarx_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "checkmarx-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv75_checkmarx_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "checkmarx-api-credentials",
        "CHECKMARX_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{200B}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv75_checkmarx_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "checkmarx-api-credentials",
        "CHECKMARX_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{00AD}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv75_checkmarx_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "checkmarx-api-credentials",
        "CHECKMARX_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{200C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv75_checkmarx_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "checkmarx-api-credentials",
        "CHECKMARX_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{200D}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv75_checkmarx_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "checkmarx-api-credentials",
        "CHECKMARX_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{FEFF}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv75_checkmarx_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "checkmarx-api-credentials",
        "CHECKMARX_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{2060}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv75_checkmarx_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "checkmarx-api-credentials",
        "CHECKMARX_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{180E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv75_checkmarx_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "checkmarx-api-credentials",
        "CHECKMARX_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{202E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv75_checkmarx_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "checkmarx-api-credentials",
        "CHECKMARX_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{202C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv75_checkmarx_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "checkmarx-api-credentials",
        "CHECKMARX_CLIENT_ID=7b3e5d8c-1a9f-4e2b\u{200E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

// =========================================================================
// 3. CHECKOUT COM API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv75_checkout_com_api_key_normal_must_fire() {
    assert_detector_fires(
        "checkout-com-api-key",
        "sk_sbox_kp4qx7rm2sn5tb8vw3yzkp4qx",
        "sk_sbox_kp4qx7rm2sn5tb8vw3yzkp4qx",
    );
}

#[test]
fn adv75_checkout_com_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("checkout-com-api-key", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv75_checkout_com_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "checkout-com-api-key",
        "sk_sbox_kp4qx7rm\u{200B}2sn5tb8vw3yzkp4qx",
        "sk_sbox_kp4qx7rm2sn5tb8vw3yzkp4qx",
    );
}

#[test]
fn adv75_checkout_com_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "checkout-com-api-key",
        "sk_sbox_kp4qx7rm\u{00AD}2sn5tb8vw3yzkp4qx",
        "sk_sbox_kp4qx7rm2sn5tb8vw3yzkp4qx",
    );
}

#[test]
fn adv75_checkout_com_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "checkout-com-api-key",
        "sk_sbox_kp4qx7rm\u{200C}2sn5tb8vw3yzkp4qx",
        "sk_sbox_kp4qx7rm2sn5tb8vw3yzkp4qx",
    );
}

#[test]
fn adv75_checkout_com_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "checkout-com-api-key",
        "sk_sbox_kp4qx7rm\u{200D}2sn5tb8vw3yzkp4qx",
        "sk_sbox_kp4qx7rm2sn5tb8vw3yzkp4qx",
    );
}

#[test]
fn adv75_checkout_com_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "checkout-com-api-key",
        "sk_sbox_kp4qx7rm\u{FEFF}2sn5tb8vw3yzkp4qx",
        "sk_sbox_kp4qx7rm2sn5tb8vw3yzkp4qx",
    );
}

#[test]
fn adv75_checkout_com_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "checkout-com-api-key",
        "sk_sbox_kp4qx7rm\u{2060}2sn5tb8vw3yzkp4qx",
        "sk_sbox_kp4qx7rm2sn5tb8vw3yzkp4qx",
    );
}

#[test]
fn adv75_checkout_com_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "checkout-com-api-key",
        "sk_sbox_kp4qx7rm\u{180E}2sn5tb8vw3yzkp4qx",
        "sk_sbox_kp4qx7rm2sn5tb8vw3yzkp4qx",
    );
}

#[test]
fn adv75_checkout_com_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "checkout-com-api-key",
        "sk_sbox_kp4qx7rm\u{202E}2sn5tb8vw3yzkp4qx",
        "sk_sbox_kp4qx7rm2sn5tb8vw3yzkp4qx",
    );
}

#[test]
fn adv75_checkout_com_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "checkout-com-api-key",
        "sk_sbox_kp4qx7rm\u{202C}2sn5tb8vw3yzkp4qx",
        "sk_sbox_kp4qx7rm2sn5tb8vw3yzkp4qx",
    );
}

#[test]
fn adv75_checkout_com_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "checkout-com-api-key",
        "sk_sbox_kp4qx7rm\u{200E}2sn5tb8vw3yzkp4qx",
        "sk_sbox_kp4qx7rm2sn5tb8vw3yzkp4qx",
    );
}

// =========================================================================
// 4. CHEF AUTOMATE TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv75_chef_automate_token_normal_must_fire() {
    assert_detector_fires(
        "chef-automate-token",
        "CHEF_AUTOMATE_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzK",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzK",
    );
}

#[test]
fn adv75_chef_automate_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "chef-automate-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv75_chef_automate_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "chef-automate-token",
        "CHEF_AUTOMATE_TOKEN=Kp4Qx7Rm2S\u{200B}n5Tb8Vw3YzK",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzK",
    );
}

#[test]
fn adv75_chef_automate_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "chef-automate-token",
        "CHEF_AUTOMATE_TOKEN=Kp4Qx7Rm2S\u{00AD}n5Tb8Vw3YzK",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzK",
    );
}

#[test]
fn adv75_chef_automate_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "chef-automate-token",
        "CHEF_AUTOMATE_TOKEN=Kp4Qx7Rm2S\u{200C}n5Tb8Vw3YzK",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzK",
    );
}

#[test]
fn adv75_chef_automate_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "chef-automate-token",
        "CHEF_AUTOMATE_TOKEN=Kp4Qx7Rm2S\u{200D}n5Tb8Vw3YzK",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzK",
    );
}

#[test]
fn adv75_chef_automate_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "chef-automate-token",
        "CHEF_AUTOMATE_TOKEN=Kp4Qx7Rm2S\u{FEFF}n5Tb8Vw3YzK",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzK",
    );
}

#[test]
fn adv75_chef_automate_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "chef-automate-token",
        "CHEF_AUTOMATE_TOKEN=Kp4Qx7Rm2S\u{2060}n5Tb8Vw3YzK",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzK",
    );
}

#[test]
fn adv75_chef_automate_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "chef-automate-token",
        "CHEF_AUTOMATE_TOKEN=Kp4Qx7Rm2S\u{180E}n5Tb8Vw3YzK",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzK",
    );
}

#[test]
fn adv75_chef_automate_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "chef-automate-token",
        "CHEF_AUTOMATE_TOKEN=Kp4Qx7Rm2S\u{202E}n5Tb8Vw3YzK",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzK",
    );
}

#[test]
fn adv75_chef_automate_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "chef-automate-token",
        "CHEF_AUTOMATE_TOKEN=Kp4Qx7Rm2S\u{202C}n5Tb8Vw3YzK",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzK",
    );
}

#[test]
fn adv75_chef_automate_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "chef-automate-token",
        "CHEF_AUTOMATE_TOKEN=Kp4Qx7Rm2S\u{200E}n5Tb8Vw3YzK",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzK",
    );
}

// =========================================================================
// 5. CHERRYSERVERS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv75_cherryservers_api_key_normal_must_fire() {
    assert_detector_fires(
        "cherryservers-api-key",
        "CHERRY_AUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_cherryservers_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cherryservers-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv75_cherryservers_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cherryservers-api-key",
        "CHERRY_AUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_cherryservers_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cherryservers-api-key",
        "CHERRY_AUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_cherryservers_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "cherryservers-api-key",
        "CHERRY_AUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_cherryservers_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "cherryservers-api-key",
        "CHERRY_AUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_cherryservers_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "cherryservers-api-key",
        "CHERRY_AUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_cherryservers_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "cherryservers-api-key",
        "CHERRY_AUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_cherryservers_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "cherryservers-api-key",
        "CHERRY_AUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_cherryservers_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "cherryservers-api-key",
        "CHERRY_AUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_cherryservers_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "cherryservers-api-key",
        "CHERRY_AUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_cherryservers_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "cherryservers-api-key",
        "CHERRY_AUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 6. CHIPPERCASH API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv75_chippercash_api_key_normal_must_fire() {
    assert_detector_fires(
        "chippercash-api-key",
        "CHIPPER_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_chippercash_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "chippercash-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv75_chippercash_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "chippercash-api-key",
        "CHIPPER_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_chippercash_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "chippercash-api-key",
        "CHIPPER_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_chippercash_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "chippercash-api-key",
        "CHIPPER_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_chippercash_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "chippercash-api-key",
        "CHIPPER_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_chippercash_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "chippercash-api-key",
        "CHIPPER_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_chippercash_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "chippercash-api-key",
        "CHIPPER_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_chippercash_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "chippercash-api-key",
        "CHIPPER_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_chippercash_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "chippercash-api-key",
        "CHIPPER_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_chippercash_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "chippercash-api-key",
        "CHIPPER_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_chippercash_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "chippercash-api-key",
        "CHIPPER_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 7. CHROMADB API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv75_chromadb_api_key_normal_must_fire() {
    assert_detector_fires(
        "chromadb-api-key",
        "CHROMA_AUTH_TOKEN=Kp4Qx7Rm2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv75_chromadb_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("chromadb-api-key", "dummy_prefix_0 =xxxxxxxxxxxxxxxx");
}

#[test]
fn adv75_chromadb_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "chromadb-api-key",
        "CHROMA_AUTH_TOKEN=Kp4Qx7Rm\u{200B}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv75_chromadb_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "chromadb-api-key",
        "CHROMA_AUTH_TOKEN=Kp4Qx7Rm\u{00AD}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv75_chromadb_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "chromadb-api-key",
        "CHROMA_AUTH_TOKEN=Kp4Qx7Rm\u{200C}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv75_chromadb_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "chromadb-api-key",
        "CHROMA_AUTH_TOKEN=Kp4Qx7Rm\u{200D}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv75_chromadb_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "chromadb-api-key",
        "CHROMA_AUTH_TOKEN=Kp4Qx7Rm\u{FEFF}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv75_chromadb_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "chromadb-api-key",
        "CHROMA_AUTH_TOKEN=Kp4Qx7Rm\u{2060}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv75_chromadb_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "chromadb-api-key",
        "CHROMA_AUTH_TOKEN=Kp4Qx7Rm\u{180E}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv75_chromadb_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "chromadb-api-key",
        "CHROMA_AUTH_TOKEN=Kp4Qx7Rm\u{202E}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv75_chromadb_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "chromadb-api-key",
        "CHROMA_AUTH_TOKEN=Kp4Qx7Rm\u{202C}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

#[test]
fn adv75_chromadb_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "chromadb-api-key",
        "CHROMA_AUTH_TOKEN=Kp4Qx7Rm\u{200E}2Sn5Tb8V",
        "Kp4Qx7Rm2Sn5Tb8V",
    );
}

// =========================================================================
// 8. CIRCLECI API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv75_circleci_api_token_normal_must_fire() {
    assert_detector_fires(
        "circleci-api-token",
        "CIRCLE_TOKEN=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv75_circleci_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "circleci-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv75_circleci_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "circleci-api-token",
        "CIRCLE_TOKEN=7b3e5d8c1a9f4e2b6c8d\u{200B}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv75_circleci_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "circleci-api-token",
        "CIRCLE_TOKEN=7b3e5d8c1a9f4e2b6c8d\u{00AD}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv75_circleci_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "circleci-api-token",
        "CIRCLE_TOKEN=7b3e5d8c1a9f4e2b6c8d\u{200C}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv75_circleci_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "circleci-api-token",
        "CIRCLE_TOKEN=7b3e5d8c1a9f4e2b6c8d\u{200D}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv75_circleci_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "circleci-api-token",
        "CIRCLE_TOKEN=7b3e5d8c1a9f4e2b6c8d\u{FEFF}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv75_circleci_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "circleci-api-token",
        "CIRCLE_TOKEN=7b3e5d8c1a9f4e2b6c8d\u{2060}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv75_circleci_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "circleci-api-token",
        "CIRCLE_TOKEN=7b3e5d8c1a9f4e2b6c8d\u{180E}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv75_circleci_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "circleci-api-token",
        "CIRCLE_TOKEN=7b3e5d8c1a9f4e2b6c8d\u{202E}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv75_circleci_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "circleci-api-token",
        "CIRCLE_TOKEN=7b3e5d8c1a9f4e2b6c8d\u{202C}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

#[test]
fn adv75_circleci_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "circleci-api-token",
        "CIRCLE_TOKEN=7b3e5d8c1a9f4e2b6c8d\u{200E}3a5e9f1b7c4d8e6a2b9f",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f",
    );
}

// =========================================================================
// 9. CLASSLINK API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv75_classlink_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "classlink-api-credentials",
        "classlink_api_key=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv75_classlink_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "classlink-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv75_classlink_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "classlink-api-credentials",
        "classlink_api_key=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx\u{200B}7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv75_classlink_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "classlink-api-credentials",
        "classlink_api_key=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx\u{00AD}7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv75_classlink_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "classlink-api-credentials",
        "classlink_api_key=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx\u{200C}7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv75_classlink_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "classlink-api-credentials",
        "classlink_api_key=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx\u{200D}7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv75_classlink_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "classlink-api-credentials",
        "classlink_api_key=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx\u{FEFF}7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv75_classlink_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "classlink-api-credentials",
        "classlink_api_key=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx\u{2060}7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv75_classlink_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "classlink-api-credentials",
        "classlink_api_key=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx\u{180E}7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv75_classlink_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "classlink-api-credentials",
        "classlink_api_key=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx\u{202E}7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv75_classlink_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "classlink-api-credentials",
        "classlink_api_key=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx\u{202C}7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv75_classlink_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "classlink-api-credentials",
        "classlink_api_key=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx\u{200E}7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

// =========================================================================
// 10. CLERK API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv75_clerk_api_key_normal_must_fire() {
    assert_detector_fires(
        "clerk-api-key",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_clerk_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("clerk-api-key", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv75_clerk_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "clerk-api-key",
        "pk_live_Kp4Qx7Rm2Sn5\u{200B}Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_clerk_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "clerk-api-key",
        "pk_live_Kp4Qx7Rm2Sn5\u{00AD}Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_clerk_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "clerk-api-key",
        "pk_live_Kp4Qx7Rm2Sn5\u{200C}Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_clerk_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "clerk-api-key",
        "pk_live_Kp4Qx7Rm2Sn5\u{200D}Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_clerk_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "clerk-api-key",
        "pk_live_Kp4Qx7Rm2Sn5\u{FEFF}Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_clerk_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "clerk-api-key",
        "pk_live_Kp4Qx7Rm2Sn5\u{2060}Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_clerk_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "clerk-api-key",
        "pk_live_Kp4Qx7Rm2Sn5\u{180E}Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_clerk_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "clerk-api-key",
        "pk_live_Kp4Qx7Rm2Sn5\u{202E}Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_clerk_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "clerk-api-key",
        "pk_live_Kp4Qx7Rm2Sn5\u{202C}Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv75_clerk_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "clerk-api-key",
        "pk_live_Kp4Qx7Rm2Sn5\u{200E}Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pk_live_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}
