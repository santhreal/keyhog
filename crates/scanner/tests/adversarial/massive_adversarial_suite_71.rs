//! Part 71 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates bitbucket, bitquery, blackboard, blockcypher, bluejeans, bluesky, bluesnap, blynk, booking, box detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. BITBUCKET PIPELINE VARIABLE ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv71_bitbucket_pipeline_variable_normal_must_fire() {
    assert_detector_fires(
        "bitbucket-pipeline-variable",
        "BITBUCKET_DEPLOY_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bitbucket_pipeline_variable_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bitbucket-pipeline-variable",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv71_bitbucket_pipeline_variable_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bitbucket-pipeline-variable",
        "BITBUCKET_DEPLOY_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bitbucket_pipeline_variable_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bitbucket-pipeline-variable",
        "BITBUCKET_DEPLOY_KEY=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bitbucket_pipeline_variable_evade_zwnj_must_fire() {
    assert_detector_fires(
        "bitbucket-pipeline-variable",
        "BITBUCKET_DEPLOY_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bitbucket_pipeline_variable_evade_zwj_must_fire() {
    assert_detector_fires(
        "bitbucket-pipeline-variable",
        "BITBUCKET_DEPLOY_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bitbucket_pipeline_variable_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "bitbucket-pipeline-variable",
        "BITBUCKET_DEPLOY_KEY=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bitbucket_pipeline_variable_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "bitbucket-pipeline-variable",
        "BITBUCKET_DEPLOY_KEY=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bitbucket_pipeline_variable_evade_mongolian_must_fire() {
    assert_detector_fires(
        "bitbucket-pipeline-variable",
        "BITBUCKET_DEPLOY_KEY=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bitbucket_pipeline_variable_evade_rtl_must_fire() {
    assert_detector_fires(
        "bitbucket-pipeline-variable",
        "BITBUCKET_DEPLOY_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bitbucket_pipeline_variable_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "bitbucket-pipeline-variable",
        "BITBUCKET_DEPLOY_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bitbucket_pipeline_variable_evade_lrm_must_fire() {
    assert_detector_fires(
        "bitbucket-pipeline-variable",
        "BITBUCKET_DEPLOY_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 2. BITQUERY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv71_bitquery_api_key_normal_must_fire() {
    assert_detector_fires(
        "bitquery-api-key",
        "BITQUERY_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_bitquery_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bitquery-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv71_bitquery_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bitquery-api-key",
        "BITQUERY_API_KEY=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_bitquery_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bitquery-api-key",
        "BITQUERY_API_KEY=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_bitquery_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "bitquery-api-key",
        "BITQUERY_API_KEY=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_bitquery_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "bitquery-api-key",
        "BITQUERY_API_KEY=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_bitquery_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "bitquery-api-key",
        "BITQUERY_API_KEY=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_bitquery_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "bitquery-api-key",
        "BITQUERY_API_KEY=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_bitquery_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "bitquery-api-key",
        "BITQUERY_API_KEY=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_bitquery_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "bitquery-api-key",
        "BITQUERY_API_KEY=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_bitquery_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "bitquery-api-key",
        "BITQUERY_API_KEY=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_bitquery_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "bitquery-api-key",
        "BITQUERY_API_KEY=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 3. BLACKBOARD API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv71_blackboard_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "blackboard-api-credentials",
        "blackboard_api_key=7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_blackboard_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "blackboard-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv71_blackboard_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "blackboard-api-credentials",
        "blackboard_api_key=7b3e5d8c-1a9f-4e2b\u{200B}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_blackboard_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "blackboard-api-credentials",
        "blackboard_api_key=7b3e5d8c-1a9f-4e2b\u{00AD}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_blackboard_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "blackboard-api-credentials",
        "blackboard_api_key=7b3e5d8c-1a9f-4e2b\u{200C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_blackboard_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "blackboard-api-credentials",
        "blackboard_api_key=7b3e5d8c-1a9f-4e2b\u{200D}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_blackboard_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "blackboard-api-credentials",
        "blackboard_api_key=7b3e5d8c-1a9f-4e2b\u{FEFF}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_blackboard_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "blackboard-api-credentials",
        "blackboard_api_key=7b3e5d8c-1a9f-4e2b\u{2060}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_blackboard_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "blackboard-api-credentials",
        "blackboard_api_key=7b3e5d8c-1a9f-4e2b\u{180E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_blackboard_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "blackboard-api-credentials",
        "blackboard_api_key=7b3e5d8c-1a9f-4e2b\u{202E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_blackboard_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "blackboard-api-credentials",
        "blackboard_api_key=7b3e5d8c-1a9f-4e2b\u{202C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_blackboard_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "blackboard-api-credentials",
        "blackboard_api_key=7b3e5d8c-1a9f-4e2b\u{200E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

// =========================================================================
// 4. BLOCKCYPHER API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv71_blockcypher_api_token_normal_must_fire() {
    assert_detector_fires(
        "blockcypher-api-token",
        "BLOCKCYPHER_TOKEN=7b3e5d8c1a9f4e2b6c8d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b",
    );
}

#[test]
fn adv71_blockcypher_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "blockcypher-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv71_blockcypher_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "blockcypher-api-token",
        "BLOCKCYPHER_TOKEN=7b3e5d8c1a9f4e\u{200B}2b6c8d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b",
    );
}

#[test]
fn adv71_blockcypher_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "blockcypher-api-token",
        "BLOCKCYPHER_TOKEN=7b3e5d8c1a9f4e\u{00AD}2b6c8d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b",
    );
}

#[test]
fn adv71_blockcypher_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "blockcypher-api-token",
        "BLOCKCYPHER_TOKEN=7b3e5d8c1a9f4e\u{200C}2b6c8d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b",
    );
}

#[test]
fn adv71_blockcypher_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "blockcypher-api-token",
        "BLOCKCYPHER_TOKEN=7b3e5d8c1a9f4e\u{200D}2b6c8d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b",
    );
}

#[test]
fn adv71_blockcypher_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "blockcypher-api-token",
        "BLOCKCYPHER_TOKEN=7b3e5d8c1a9f4e\u{FEFF}2b6c8d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b",
    );
}

#[test]
fn adv71_blockcypher_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "blockcypher-api-token",
        "BLOCKCYPHER_TOKEN=7b3e5d8c1a9f4e\u{2060}2b6c8d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b",
    );
}

#[test]
fn adv71_blockcypher_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "blockcypher-api-token",
        "BLOCKCYPHER_TOKEN=7b3e5d8c1a9f4e\u{180E}2b6c8d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b",
    );
}

#[test]
fn adv71_blockcypher_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "blockcypher-api-token",
        "BLOCKCYPHER_TOKEN=7b3e5d8c1a9f4e\u{202E}2b6c8d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b",
    );
}

#[test]
fn adv71_blockcypher_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "blockcypher-api-token",
        "BLOCKCYPHER_TOKEN=7b3e5d8c1a9f4e\u{202C}2b6c8d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b",
    );
}

#[test]
fn adv71_blockcypher_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "blockcypher-api-token",
        "BLOCKCYPHER_TOKEN=7b3e5d8c1a9f4e\u{200E}2b6c8d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b",
    );
}

// =========================================================================
// 5. BLUEJEANS API ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv71_bluejeans_api_normal_must_fire() {
    assert_detector_fires(
        "bluejeans-api",
        "bluejeans_api_key=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bluejeans_api_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bluejeans-api",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv71_bluejeans_api_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bluejeans-api",
        "bluejeans_api_key=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bluejeans_api_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bluejeans-api",
        "bluejeans_api_key=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bluejeans_api_evade_zwnj_must_fire() {
    assert_detector_fires(
        "bluejeans-api",
        "bluejeans_api_key=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bluejeans_api_evade_zwj_must_fire() {
    assert_detector_fires(
        "bluejeans-api",
        "bluejeans_api_key=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bluejeans_api_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "bluejeans-api",
        "bluejeans_api_key=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bluejeans_api_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "bluejeans-api",
        "bluejeans_api_key=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bluejeans_api_evade_mongolian_must_fire() {
    assert_detector_fires(
        "bluejeans-api",
        "bluejeans_api_key=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bluejeans_api_evade_rtl_must_fire() {
    assert_detector_fires(
        "bluejeans-api",
        "bluejeans_api_key=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bluejeans_api_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "bluejeans-api",
        "bluejeans_api_key=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bluejeans_api_evade_lrm_must_fire() {
    assert_detector_fires(
        "bluejeans-api",
        "bluejeans_api_key=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 6. BLUESKY APP PASSWORD ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv71_bluesky_app_password_normal_must_fire() {
    assert_detector_fires(
        "bluesky-app-password",
        "bluesky=kp4q-x7rm-2sn5-tb8v",
        "kp4q-x7rm-2sn5-tb8v",
    );
}

#[test]
fn adv71_bluesky_app_password_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bluesky-app-password",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv71_bluesky_app_password_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bluesky-app-password",
        "bluesky=kp4q-x7rm\u{200B}-2sn5-tb8v",
        "kp4q-x7rm-2sn5-tb8v",
    );
}

#[test]
fn adv71_bluesky_app_password_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bluesky-app-password",
        "bluesky=kp4q-x7rm\u{00AD}-2sn5-tb8v",
        "kp4q-x7rm-2sn5-tb8v",
    );
}

#[test]
fn adv71_bluesky_app_password_evade_zwnj_must_fire() {
    assert_detector_fires(
        "bluesky-app-password",
        "bluesky=kp4q-x7rm\u{200C}-2sn5-tb8v",
        "kp4q-x7rm-2sn5-tb8v",
    );
}

#[test]
fn adv71_bluesky_app_password_evade_zwj_must_fire() {
    assert_detector_fires(
        "bluesky-app-password",
        "bluesky=kp4q-x7rm\u{200D}-2sn5-tb8v",
        "kp4q-x7rm-2sn5-tb8v",
    );
}

#[test]
fn adv71_bluesky_app_password_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "bluesky-app-password",
        "bluesky=kp4q-x7rm\u{FEFF}-2sn5-tb8v",
        "kp4q-x7rm-2sn5-tb8v",
    );
}

#[test]
fn adv71_bluesky_app_password_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "bluesky-app-password",
        "bluesky=kp4q-x7rm\u{2060}-2sn5-tb8v",
        "kp4q-x7rm-2sn5-tb8v",
    );
}

#[test]
fn adv71_bluesky_app_password_evade_mongolian_must_fire() {
    assert_detector_fires(
        "bluesky-app-password",
        "bluesky=kp4q-x7rm\u{180E}-2sn5-tb8v",
        "kp4q-x7rm-2sn5-tb8v",
    );
}

#[test]
fn adv71_bluesky_app_password_evade_rtl_must_fire() {
    assert_detector_fires(
        "bluesky-app-password",
        "bluesky=kp4q-x7rm\u{202E}-2sn5-tb8v",
        "kp4q-x7rm-2sn5-tb8v",
    );
}

#[test]
fn adv71_bluesky_app_password_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "bluesky-app-password",
        "bluesky=kp4q-x7rm\u{202C}-2sn5-tb8v",
        "kp4q-x7rm-2sn5-tb8v",
    );
}

#[test]
fn adv71_bluesky_app_password_evade_lrm_must_fire() {
    assert_detector_fires(
        "bluesky-app-password",
        "bluesky=kp4q-x7rm\u{200E}-2sn5-tb8v",
        "kp4q-x7rm-2sn5-tb8v",
    );
}

// =========================================================================
// 7. BLUESNAP API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv71_bluesnap_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "bluesnap-api-credentials",
        "BLUESNAP_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bluesnap_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "bluesnap-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv71_bluesnap_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "bluesnap-api-credentials",
        "BLUESNAP_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bluesnap_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "bluesnap-api-credentials",
        "BLUESNAP_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bluesnap_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "bluesnap-api-credentials",
        "BLUESNAP_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bluesnap_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "bluesnap-api-credentials",
        "BLUESNAP_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bluesnap_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "bluesnap-api-credentials",
        "BLUESNAP_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bluesnap_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "bluesnap-api-credentials",
        "BLUESNAP_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bluesnap_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "bluesnap-api-credentials",
        "BLUESNAP_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bluesnap_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "bluesnap-api-credentials",
        "BLUESNAP_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bluesnap_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "bluesnap-api-credentials",
        "BLUESNAP_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv71_bluesnap_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "bluesnap-api-credentials",
        "BLUESNAP_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 8. BLYNK API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv71_blynk_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "blynk-api-credentials",
        "BLYNK_AUTH_TOKEN=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_blynk_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "blynk-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv71_blynk_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "blynk-api-credentials",
        "BLYNK_AUTH_TOKEN=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_blynk_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "blynk-api-credentials",
        "BLYNK_AUTH_TOKEN=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_blynk_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "blynk-api-credentials",
        "BLYNK_AUTH_TOKEN=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_blynk_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "blynk-api-credentials",
        "BLYNK_AUTH_TOKEN=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_blynk_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "blynk-api-credentials",
        "BLYNK_AUTH_TOKEN=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_blynk_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "blynk-api-credentials",
        "BLYNK_AUTH_TOKEN=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_blynk_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "blynk-api-credentials",
        "BLYNK_AUTH_TOKEN=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_blynk_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "blynk-api-credentials",
        "BLYNK_AUTH_TOKEN=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_blynk_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "blynk-api-credentials",
        "BLYNK_AUTH_TOKEN=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv71_blynk_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "blynk-api-credentials",
        "BLYNK_AUTH_TOKEN=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 9. BOOKING COM API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv71_booking_com_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "booking-com-api-credentials",
        "BOOKING_COM_USERNAME=Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv71_booking_com_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "booking-com-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv71_booking_com_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "booking-com-api-credentials",
        "BOOKING_COM_USERNAME=Kp4Qx7Rm2S\u{200B}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv71_booking_com_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "booking-com-api-credentials",
        "BOOKING_COM_USERNAME=Kp4Qx7Rm2S\u{00AD}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv71_booking_com_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "booking-com-api-credentials",
        "BOOKING_COM_USERNAME=Kp4Qx7Rm2S\u{200C}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv71_booking_com_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "booking-com-api-credentials",
        "BOOKING_COM_USERNAME=Kp4Qx7Rm2S\u{200D}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv71_booking_com_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "booking-com-api-credentials",
        "BOOKING_COM_USERNAME=Kp4Qx7Rm2S\u{FEFF}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv71_booking_com_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "booking-com-api-credentials",
        "BOOKING_COM_USERNAME=Kp4Qx7Rm2S\u{2060}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv71_booking_com_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "booking-com-api-credentials",
        "BOOKING_COM_USERNAME=Kp4Qx7Rm2S\u{180E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv71_booking_com_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "booking-com-api-credentials",
        "BOOKING_COM_USERNAME=Kp4Qx7Rm2S\u{202E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv71_booking_com_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "booking-com-api-credentials",
        "BOOKING_COM_USERNAME=Kp4Qx7Rm2S\u{202C}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv71_booking_com_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "booking-com-api-credentials",
        "BOOKING_COM_USERNAME=Kp4Qx7Rm2S\u{200E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 10. BOX DEVELOPER TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv71_box_developer_token_normal_must_fire() {
    assert_detector_fires(
        "box-developer-token",
        "BOX_DEVELOPER_TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv71_box_developer_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "box-developer-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv71_box_developer_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "box-developer-token",
        "BOX_DEVELOPER_TOKEN=Kp4Qx7Rm2Sn5Tb\u{200B}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv71_box_developer_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "box-developer-token",
        "BOX_DEVELOPER_TOKEN=Kp4Qx7Rm2Sn5Tb\u{00AD}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv71_box_developer_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "box-developer-token",
        "BOX_DEVELOPER_TOKEN=Kp4Qx7Rm2Sn5Tb\u{200C}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv71_box_developer_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "box-developer-token",
        "BOX_DEVELOPER_TOKEN=Kp4Qx7Rm2Sn5Tb\u{200D}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv71_box_developer_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "box-developer-token",
        "BOX_DEVELOPER_TOKEN=Kp4Qx7Rm2Sn5Tb\u{FEFF}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv71_box_developer_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "box-developer-token",
        "BOX_DEVELOPER_TOKEN=Kp4Qx7Rm2Sn5Tb\u{2060}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv71_box_developer_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "box-developer-token",
        "BOX_DEVELOPER_TOKEN=Kp4Qx7Rm2Sn5Tb\u{180E}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv71_box_developer_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "box-developer-token",
        "BOX_DEVELOPER_TOKEN=Kp4Qx7Rm2Sn5Tb\u{202E}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv71_box_developer_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "box-developer-token",
        "BOX_DEVELOPER_TOKEN=Kp4Qx7Rm2Sn5Tb\u{202C}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv71_box_developer_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "box-developer-token",
        "BOX_DEVELOPER_TOKEN=Kp4Qx7Rm2Sn5Tb\u{200E}8Vw3YzKp4Qx7Rm",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}
