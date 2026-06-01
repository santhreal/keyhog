//! Part 91 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates gitlab, gitlab, gitlab, gitpod, glitch, goatcounter, gocardless, goldsky, google, google detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. GITLAB PERSONAL ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv91_gitlab_personal_access_token_normal_must_fire() {
    assert_detector_fires(
        "gitlab-personal-access-token",
        "glpat-aB3kQp7VbT2hYRzNcMfW",
        "glpat-aB3kQp7VbT2hYRzNcMfW",
    );
}

#[test]
fn adv91_gitlab_personal_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "gitlab-personal-access-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv91_gitlab_personal_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "gitlab-personal-access-token",
        "glpat-aB3kQp7\u{200B}VbT2hYRzNcMfW",
        "glpat-aB3kQp7VbT2hYRzNcMfW",
    );
}

#[test]
fn adv91_gitlab_personal_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "gitlab-personal-access-token",
        "glpat-aB3kQp7\u{00AD}VbT2hYRzNcMfW",
        "glpat-aB3kQp7VbT2hYRzNcMfW",
    );
}

#[test]
fn adv91_gitlab_personal_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "gitlab-personal-access-token",
        "glpat-aB3kQp7\u{200C}VbT2hYRzNcMfW",
        "glpat-aB3kQp7VbT2hYRzNcMfW",
    );
}

#[test]
fn adv91_gitlab_personal_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "gitlab-personal-access-token",
        "glpat-aB3kQp7\u{200D}VbT2hYRzNcMfW",
        "glpat-aB3kQp7VbT2hYRzNcMfW",
    );
}

#[test]
fn adv91_gitlab_personal_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "gitlab-personal-access-token",
        "glpat-aB3kQp7\u{FEFF}VbT2hYRzNcMfW",
        "glpat-aB3kQp7VbT2hYRzNcMfW",
    );
}

#[test]
fn adv91_gitlab_personal_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "gitlab-personal-access-token",
        "glpat-aB3kQp7\u{2060}VbT2hYRzNcMfW",
        "glpat-aB3kQp7VbT2hYRzNcMfW",
    );
}

#[test]
fn adv91_gitlab_personal_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "gitlab-personal-access-token",
        "glpat-aB3kQp7\u{180E}VbT2hYRzNcMfW",
        "glpat-aB3kQp7VbT2hYRzNcMfW",
    );
}

#[test]
fn adv91_gitlab_personal_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "gitlab-personal-access-token",
        "glpat-aB3kQp7\u{202E}VbT2hYRzNcMfW",
        "glpat-aB3kQp7VbT2hYRzNcMfW",
    );
}

#[test]
fn adv91_gitlab_personal_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "gitlab-personal-access-token",
        "glpat-aB3kQp7\u{202C}VbT2hYRzNcMfW",
        "glpat-aB3kQp7VbT2hYRzNcMfW",
    );
}

#[test]
fn adv91_gitlab_personal_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "gitlab-personal-access-token",
        "glpat-aB3kQp7\u{200E}VbT2hYRzNcMfW",
        "glpat-aB3kQp7VbT2hYRzNcMfW",
    );
}

// =========================================================================
// 2. GITLAB PIPELINE TRIGGER TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv91_gitlab_pipeline_trigger_token_normal_must_fire() {
    assert_detector_fires(
        "gitlab-pipeline-trigger-token",
        "glptt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "glptt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv91_gitlab_pipeline_trigger_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "gitlab-pipeline-trigger-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv91_gitlab_pipeline_trigger_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "gitlab-pipeline-trigger-token",
        "glptt-Kp4Qx7R\u{200B}m2Sn5Tb8Vw3Yz",
        "glptt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv91_gitlab_pipeline_trigger_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "gitlab-pipeline-trigger-token",
        "glptt-Kp4Qx7R\u{00AD}m2Sn5Tb8Vw3Yz",
        "glptt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv91_gitlab_pipeline_trigger_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "gitlab-pipeline-trigger-token",
        "glptt-Kp4Qx7R\u{200C}m2Sn5Tb8Vw3Yz",
        "glptt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv91_gitlab_pipeline_trigger_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "gitlab-pipeline-trigger-token",
        "glptt-Kp4Qx7R\u{200D}m2Sn5Tb8Vw3Yz",
        "glptt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv91_gitlab_pipeline_trigger_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "gitlab-pipeline-trigger-token",
        "glptt-Kp4Qx7R\u{FEFF}m2Sn5Tb8Vw3Yz",
        "glptt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv91_gitlab_pipeline_trigger_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "gitlab-pipeline-trigger-token",
        "glptt-Kp4Qx7R\u{2060}m2Sn5Tb8Vw3Yz",
        "glptt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv91_gitlab_pipeline_trigger_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "gitlab-pipeline-trigger-token",
        "glptt-Kp4Qx7R\u{180E}m2Sn5Tb8Vw3Yz",
        "glptt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv91_gitlab_pipeline_trigger_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "gitlab-pipeline-trigger-token",
        "glptt-Kp4Qx7R\u{202E}m2Sn5Tb8Vw3Yz",
        "glptt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv91_gitlab_pipeline_trigger_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "gitlab-pipeline-trigger-token",
        "glptt-Kp4Qx7R\u{202C}m2Sn5Tb8Vw3Yz",
        "glptt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv91_gitlab_pipeline_trigger_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "gitlab-pipeline-trigger-token",
        "glptt-Kp4Qx7R\u{200E}m2Sn5Tb8Vw3Yz",
        "glptt-Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 3. GITLAB WEBHOOK SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv91_gitlab_webhook_secret_normal_must_fire() {
    assert_detector_fires(
        "gitlab-webhook-secret",
        "GITLAB_WEBHOOK_SECRET=KOR2YryGc3DbBXYMZSKPwmIS",
        "KOR2YryGc3DbBXYMZSKPwmIS",
    );
}

#[test]
fn adv91_gitlab_webhook_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "gitlab-webhook-secret",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv91_gitlab_webhook_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "gitlab-webhook-secret",
        "GITLAB_WEBHOOK_SECRET=KOR2YryGc3Db\u{200B}BXYMZSKPwmIS",
        "KOR2YryGc3DbBXYMZSKPwmIS",
    );
}

#[test]
fn adv91_gitlab_webhook_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "gitlab-webhook-secret",
        "GITLAB_WEBHOOK_SECRET=KOR2YryGc3Db\u{00AD}BXYMZSKPwmIS",
        "KOR2YryGc3DbBXYMZSKPwmIS",
    );
}

#[test]
fn adv91_gitlab_webhook_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "gitlab-webhook-secret",
        "GITLAB_WEBHOOK_SECRET=KOR2YryGc3Db\u{200C}BXYMZSKPwmIS",
        "KOR2YryGc3DbBXYMZSKPwmIS",
    );
}

#[test]
fn adv91_gitlab_webhook_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "gitlab-webhook-secret",
        "GITLAB_WEBHOOK_SECRET=KOR2YryGc3Db\u{200D}BXYMZSKPwmIS",
        "KOR2YryGc3DbBXYMZSKPwmIS",
    );
}

#[test]
fn adv91_gitlab_webhook_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "gitlab-webhook-secret",
        "GITLAB_WEBHOOK_SECRET=KOR2YryGc3Db\u{FEFF}BXYMZSKPwmIS",
        "KOR2YryGc3DbBXYMZSKPwmIS",
    );
}

#[test]
fn adv91_gitlab_webhook_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "gitlab-webhook-secret",
        "GITLAB_WEBHOOK_SECRET=KOR2YryGc3Db\u{2060}BXYMZSKPwmIS",
        "KOR2YryGc3DbBXYMZSKPwmIS",
    );
}

#[test]
fn adv91_gitlab_webhook_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "gitlab-webhook-secret",
        "GITLAB_WEBHOOK_SECRET=KOR2YryGc3Db\u{180E}BXYMZSKPwmIS",
        "KOR2YryGc3DbBXYMZSKPwmIS",
    );
}

#[test]
fn adv91_gitlab_webhook_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "gitlab-webhook-secret",
        "GITLAB_WEBHOOK_SECRET=KOR2YryGc3Db\u{202E}BXYMZSKPwmIS",
        "KOR2YryGc3DbBXYMZSKPwmIS",
    );
}

#[test]
fn adv91_gitlab_webhook_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "gitlab-webhook-secret",
        "GITLAB_WEBHOOK_SECRET=KOR2YryGc3Db\u{202C}BXYMZSKPwmIS",
        "KOR2YryGc3DbBXYMZSKPwmIS",
    );
}

#[test]
fn adv91_gitlab_webhook_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "gitlab-webhook-secret",
        "GITLAB_WEBHOOK_SECRET=KOR2YryGc3Db\u{200E}BXYMZSKPwmIS",
        "KOR2YryGc3DbBXYMZSKPwmIS",
    );
}

// =========================================================================
// 4. GITPOD API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv91_gitpod_api_token_normal_must_fire() {
    assert_detector_fires(
        "gitpod-api-token",
        "GITPOD_TOKEN=6075ce188a4ce087f9a60f3f9c0fd5b6dae4c36a",
        "6075ce188a4ce087f9a60f3f9c0fd5b6dae4c36a",
    );
}

#[test]
fn adv91_gitpod_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "gitpod-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv91_gitpod_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "gitpod-api-token",
        "GITPOD_TOKEN=6075ce188a4ce087f9a6\u{200B}0f3f9c0fd5b6dae4c36a",
        "6075ce188a4ce087f9a60f3f9c0fd5b6dae4c36a",
    );
}

#[test]
fn adv91_gitpod_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "gitpod-api-token",
        "GITPOD_TOKEN=6075ce188a4ce087f9a6\u{00AD}0f3f9c0fd5b6dae4c36a",
        "6075ce188a4ce087f9a60f3f9c0fd5b6dae4c36a",
    );
}

#[test]
fn adv91_gitpod_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "gitpod-api-token",
        "GITPOD_TOKEN=6075ce188a4ce087f9a6\u{200C}0f3f9c0fd5b6dae4c36a",
        "6075ce188a4ce087f9a60f3f9c0fd5b6dae4c36a",
    );
}

#[test]
fn adv91_gitpod_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "gitpod-api-token",
        "GITPOD_TOKEN=6075ce188a4ce087f9a6\u{200D}0f3f9c0fd5b6dae4c36a",
        "6075ce188a4ce087f9a60f3f9c0fd5b6dae4c36a",
    );
}

#[test]
fn adv91_gitpod_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "gitpod-api-token",
        "GITPOD_TOKEN=6075ce188a4ce087f9a6\u{FEFF}0f3f9c0fd5b6dae4c36a",
        "6075ce188a4ce087f9a60f3f9c0fd5b6dae4c36a",
    );
}

#[test]
fn adv91_gitpod_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "gitpod-api-token",
        "GITPOD_TOKEN=6075ce188a4ce087f9a6\u{2060}0f3f9c0fd5b6dae4c36a",
        "6075ce188a4ce087f9a60f3f9c0fd5b6dae4c36a",
    );
}

#[test]
fn adv91_gitpod_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "gitpod-api-token",
        "GITPOD_TOKEN=6075ce188a4ce087f9a6\u{180E}0f3f9c0fd5b6dae4c36a",
        "6075ce188a4ce087f9a60f3f9c0fd5b6dae4c36a",
    );
}

#[test]
fn adv91_gitpod_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "gitpod-api-token",
        "GITPOD_TOKEN=6075ce188a4ce087f9a6\u{202E}0f3f9c0fd5b6dae4c36a",
        "6075ce188a4ce087f9a60f3f9c0fd5b6dae4c36a",
    );
}

#[test]
fn adv91_gitpod_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "gitpod-api-token",
        "GITPOD_TOKEN=6075ce188a4ce087f9a6\u{202C}0f3f9c0fd5b6dae4c36a",
        "6075ce188a4ce087f9a60f3f9c0fd5b6dae4c36a",
    );
}

#[test]
fn adv91_gitpod_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "gitpod-api-token",
        "GITPOD_TOKEN=6075ce188a4ce087f9a6\u{200E}0f3f9c0fd5b6dae4c36a",
        "6075ce188a4ce087f9a60f3f9c0fd5b6dae4c36a",
    );
}

// =========================================================================
// 5. GLITCH API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv91_glitch_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "glitch-api-credentials",
        "glitch-408bfcb0-e673-98bb-2ad8-83dbfdc12d2c",
        "glitch-408bfcb0-e673-98bb-2ad8-83dbfdc12d2c",
    );
}

#[test]
fn adv91_glitch_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "glitch-api-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv91_glitch_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "glitch-api-credentials",
        "glitch-408bfcb0-e673-\u{200B}98bb-2ad8-83dbfdc12d2c",
        "glitch-408bfcb0-e673-98bb-2ad8-83dbfdc12d2c",
    );
}

#[test]
fn adv91_glitch_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "glitch-api-credentials",
        "glitch-408bfcb0-e673-\u{00AD}98bb-2ad8-83dbfdc12d2c",
        "glitch-408bfcb0-e673-98bb-2ad8-83dbfdc12d2c",
    );
}

#[test]
fn adv91_glitch_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "glitch-api-credentials",
        "glitch-408bfcb0-e673-\u{200C}98bb-2ad8-83dbfdc12d2c",
        "glitch-408bfcb0-e673-98bb-2ad8-83dbfdc12d2c",
    );
}

#[test]
fn adv91_glitch_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "glitch-api-credentials",
        "glitch-408bfcb0-e673-\u{200D}98bb-2ad8-83dbfdc12d2c",
        "glitch-408bfcb0-e673-98bb-2ad8-83dbfdc12d2c",
    );
}

#[test]
fn adv91_glitch_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "glitch-api-credentials",
        "glitch-408bfcb0-e673-\u{FEFF}98bb-2ad8-83dbfdc12d2c",
        "glitch-408bfcb0-e673-98bb-2ad8-83dbfdc12d2c",
    );
}

#[test]
fn adv91_glitch_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "glitch-api-credentials",
        "glitch-408bfcb0-e673-\u{2060}98bb-2ad8-83dbfdc12d2c",
        "glitch-408bfcb0-e673-98bb-2ad8-83dbfdc12d2c",
    );
}

#[test]
fn adv91_glitch_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "glitch-api-credentials",
        "glitch-408bfcb0-e673-\u{180E}98bb-2ad8-83dbfdc12d2c",
        "glitch-408bfcb0-e673-98bb-2ad8-83dbfdc12d2c",
    );
}

#[test]
fn adv91_glitch_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "glitch-api-credentials",
        "glitch-408bfcb0-e673-\u{202E}98bb-2ad8-83dbfdc12d2c",
        "glitch-408bfcb0-e673-98bb-2ad8-83dbfdc12d2c",
    );
}

#[test]
fn adv91_glitch_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "glitch-api-credentials",
        "glitch-408bfcb0-e673-\u{202C}98bb-2ad8-83dbfdc12d2c",
        "glitch-408bfcb0-e673-98bb-2ad8-83dbfdc12d2c",
    );
}

#[test]
fn adv91_glitch_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "glitch-api-credentials",
        "glitch-408bfcb0-e673-\u{200E}98bb-2ad8-83dbfdc12d2c",
        "glitch-408bfcb0-e673-98bb-2ad8-83dbfdc12d2c",
    );
}

// =========================================================================
// 6. GOATCOUNTER API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv91_goatcounter_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "goatcounter-api-credentials",
        "GOATCOUNTER_API_KEY=51bd6a0a677c98b398762cab326e0689",
        "51bd6a0a677c98b398762cab326e0689",
    );
}

#[test]
fn adv91_goatcounter_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "goatcounter-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv91_goatcounter_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "goatcounter-api-credentials",
        "GOATCOUNTER_API_KEY=51bd6a0a677c98b3\u{200B}98762cab326e0689",
        "51bd6a0a677c98b398762cab326e0689",
    );
}

#[test]
fn adv91_goatcounter_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "goatcounter-api-credentials",
        "GOATCOUNTER_API_KEY=51bd6a0a677c98b3\u{00AD}98762cab326e0689",
        "51bd6a0a677c98b398762cab326e0689",
    );
}

#[test]
fn adv91_goatcounter_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "goatcounter-api-credentials",
        "GOATCOUNTER_API_KEY=51bd6a0a677c98b3\u{200C}98762cab326e0689",
        "51bd6a0a677c98b398762cab326e0689",
    );
}

#[test]
fn adv91_goatcounter_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "goatcounter-api-credentials",
        "GOATCOUNTER_API_KEY=51bd6a0a677c98b3\u{200D}98762cab326e0689",
        "51bd6a0a677c98b398762cab326e0689",
    );
}

#[test]
fn adv91_goatcounter_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "goatcounter-api-credentials",
        "GOATCOUNTER_API_KEY=51bd6a0a677c98b3\u{FEFF}98762cab326e0689",
        "51bd6a0a677c98b398762cab326e0689",
    );
}

#[test]
fn adv91_goatcounter_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "goatcounter-api-credentials",
        "GOATCOUNTER_API_KEY=51bd6a0a677c98b3\u{2060}98762cab326e0689",
        "51bd6a0a677c98b398762cab326e0689",
    );
}

#[test]
fn adv91_goatcounter_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "goatcounter-api-credentials",
        "GOATCOUNTER_API_KEY=51bd6a0a677c98b3\u{180E}98762cab326e0689",
        "51bd6a0a677c98b398762cab326e0689",
    );
}

#[test]
fn adv91_goatcounter_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "goatcounter-api-credentials",
        "GOATCOUNTER_API_KEY=51bd6a0a677c98b3\u{202E}98762cab326e0689",
        "51bd6a0a677c98b398762cab326e0689",
    );
}

#[test]
fn adv91_goatcounter_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "goatcounter-api-credentials",
        "GOATCOUNTER_API_KEY=51bd6a0a677c98b3\u{202C}98762cab326e0689",
        "51bd6a0a677c98b398762cab326e0689",
    );
}

#[test]
fn adv91_goatcounter_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "goatcounter-api-credentials",
        "GOATCOUNTER_API_KEY=51bd6a0a677c98b3\u{200E}98762cab326e0689",
        "51bd6a0a677c98b398762cab326e0689",
    );
}

// =========================================================================
// 7. GOCARDLESS ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv91_gocardless_access_token_normal_must_fire() {
    assert_detector_fires(
        "gocardless-access-token",
        "GOCARDLESS_ACCESS_TOKEN=YBg4mNl8_wKuNd9dve0UagftXjR4RTS4pLin0z",
        "YBg4mNl8_wKuNd9dve0UagftXjR4RTS4pLin0z",
    );
}

#[test]
fn adv91_gocardless_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "gocardless-access-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv91_gocardless_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "gocardless-access-token",
        "GOCARDLESS_ACCESS_TOKEN=YBg4mNl8_wKuNd9dve0\u{200B}UagftXjR4RTS4pLin0z",
        "YBg4mNl8_wKuNd9dve0UagftXjR4RTS4pLin0z",
    );
}

#[test]
fn adv91_gocardless_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "gocardless-access-token",
        "GOCARDLESS_ACCESS_TOKEN=YBg4mNl8_wKuNd9dve0\u{00AD}UagftXjR4RTS4pLin0z",
        "YBg4mNl8_wKuNd9dve0UagftXjR4RTS4pLin0z",
    );
}

#[test]
fn adv91_gocardless_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "gocardless-access-token",
        "GOCARDLESS_ACCESS_TOKEN=YBg4mNl8_wKuNd9dve0\u{200C}UagftXjR4RTS4pLin0z",
        "YBg4mNl8_wKuNd9dve0UagftXjR4RTS4pLin0z",
    );
}

#[test]
fn adv91_gocardless_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "gocardless-access-token",
        "GOCARDLESS_ACCESS_TOKEN=YBg4mNl8_wKuNd9dve0\u{200D}UagftXjR4RTS4pLin0z",
        "YBg4mNl8_wKuNd9dve0UagftXjR4RTS4pLin0z",
    );
}

#[test]
fn adv91_gocardless_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "gocardless-access-token",
        "GOCARDLESS_ACCESS_TOKEN=YBg4mNl8_wKuNd9dve0\u{FEFF}UagftXjR4RTS4pLin0z",
        "YBg4mNl8_wKuNd9dve0UagftXjR4RTS4pLin0z",
    );
}

#[test]
fn adv91_gocardless_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "gocardless-access-token",
        "GOCARDLESS_ACCESS_TOKEN=YBg4mNl8_wKuNd9dve0\u{2060}UagftXjR4RTS4pLin0z",
        "YBg4mNl8_wKuNd9dve0UagftXjR4RTS4pLin0z",
    );
}

#[test]
fn adv91_gocardless_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "gocardless-access-token",
        "GOCARDLESS_ACCESS_TOKEN=YBg4mNl8_wKuNd9dve0\u{180E}UagftXjR4RTS4pLin0z",
        "YBg4mNl8_wKuNd9dve0UagftXjR4RTS4pLin0z",
    );
}

#[test]
fn adv91_gocardless_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "gocardless-access-token",
        "GOCARDLESS_ACCESS_TOKEN=YBg4mNl8_wKuNd9dve0\u{202E}UagftXjR4RTS4pLin0z",
        "YBg4mNl8_wKuNd9dve0UagftXjR4RTS4pLin0z",
    );
}

#[test]
fn adv91_gocardless_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "gocardless-access-token",
        "GOCARDLESS_ACCESS_TOKEN=YBg4mNl8_wKuNd9dve0\u{202C}UagftXjR4RTS4pLin0z",
        "YBg4mNl8_wKuNd9dve0UagftXjR4RTS4pLin0z",
    );
}

#[test]
fn adv91_gocardless_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "gocardless-access-token",
        "GOCARDLESS_ACCESS_TOKEN=YBg4mNl8_wKuNd9dve0\u{200E}UagftXjR4RTS4pLin0z",
        "YBg4mNl8_wKuNd9dve0UagftXjR4RTS4pLin0z",
    );
}

// =========================================================================
// 8. GOLDSKY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv91_goldsky_api_key_normal_must_fire() {
    assert_detector_fires(
        "goldsky-api-key",
        "GOLDSKY=d659b9c912fa62843c5d8226bcb17ea0",
        "d659b9c912fa62843c5d8226bcb17ea0",
    );
}

#[test]
fn adv91_goldsky_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "goldsky-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv91_goldsky_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "goldsky-api-key",
        "GOLDSKY=d659b9c912fa6284\u{200B}3c5d8226bcb17ea0",
        "d659b9c912fa62843c5d8226bcb17ea0",
    );
}

#[test]
fn adv91_goldsky_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "goldsky-api-key",
        "GOLDSKY=d659b9c912fa6284\u{00AD}3c5d8226bcb17ea0",
        "d659b9c912fa62843c5d8226bcb17ea0",
    );
}

#[test]
fn adv91_goldsky_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "goldsky-api-key",
        "GOLDSKY=d659b9c912fa6284\u{200C}3c5d8226bcb17ea0",
        "d659b9c912fa62843c5d8226bcb17ea0",
    );
}

#[test]
fn adv91_goldsky_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "goldsky-api-key",
        "GOLDSKY=d659b9c912fa6284\u{200D}3c5d8226bcb17ea0",
        "d659b9c912fa62843c5d8226bcb17ea0",
    );
}

#[test]
fn adv91_goldsky_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "goldsky-api-key",
        "GOLDSKY=d659b9c912fa6284\u{FEFF}3c5d8226bcb17ea0",
        "d659b9c912fa62843c5d8226bcb17ea0",
    );
}

#[test]
fn adv91_goldsky_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "goldsky-api-key",
        "GOLDSKY=d659b9c912fa6284\u{2060}3c5d8226bcb17ea0",
        "d659b9c912fa62843c5d8226bcb17ea0",
    );
}

#[test]
fn adv91_goldsky_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "goldsky-api-key",
        "GOLDSKY=d659b9c912fa6284\u{180E}3c5d8226bcb17ea0",
        "d659b9c912fa62843c5d8226bcb17ea0",
    );
}

#[test]
fn adv91_goldsky_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "goldsky-api-key",
        "GOLDSKY=d659b9c912fa6284\u{202E}3c5d8226bcb17ea0",
        "d659b9c912fa62843c5d8226bcb17ea0",
    );
}

#[test]
fn adv91_goldsky_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "goldsky-api-key",
        "GOLDSKY=d659b9c912fa6284\u{202C}3c5d8226bcb17ea0",
        "d659b9c912fa62843c5d8226bcb17ea0",
    );
}

#[test]
fn adv91_goldsky_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "goldsky-api-key",
        "GOLDSKY=d659b9c912fa6284\u{200E}3c5d8226bcb17ea0",
        "d659b9c912fa62843c5d8226bcb17ea0",
    );
}

// =========================================================================
// 9. GOOGLE ADS API DEVELOPER TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv91_google_ads_api_developer_token_normal_must_fire() {
    assert_detector_fires(
        "google-ads-api-developer-token",
        "developer_token=je2gdlQ8IG3e0QIQ2y4xsT",
        "je2gdlQ8IG3e0QIQ2y4xsT",
    );
}

#[test]
fn adv91_google_ads_api_developer_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "google-ads-api-developer-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv91_google_ads_api_developer_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "google-ads-api-developer-token",
        "developer_token=je2gdlQ8IG3\u{200B}e0QIQ2y4xsT",
        "je2gdlQ8IG3e0QIQ2y4xsT",
    );
}

#[test]
fn adv91_google_ads_api_developer_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "google-ads-api-developer-token",
        "developer_token=je2gdlQ8IG3\u{00AD}e0QIQ2y4xsT",
        "je2gdlQ8IG3e0QIQ2y4xsT",
    );
}

#[test]
fn adv91_google_ads_api_developer_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "google-ads-api-developer-token",
        "developer_token=je2gdlQ8IG3\u{200C}e0QIQ2y4xsT",
        "je2gdlQ8IG3e0QIQ2y4xsT",
    );
}

#[test]
fn adv91_google_ads_api_developer_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "google-ads-api-developer-token",
        "developer_token=je2gdlQ8IG3\u{200D}e0QIQ2y4xsT",
        "je2gdlQ8IG3e0QIQ2y4xsT",
    );
}

#[test]
fn adv91_google_ads_api_developer_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "google-ads-api-developer-token",
        "developer_token=je2gdlQ8IG3\u{FEFF}e0QIQ2y4xsT",
        "je2gdlQ8IG3e0QIQ2y4xsT",
    );
}

#[test]
fn adv91_google_ads_api_developer_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "google-ads-api-developer-token",
        "developer_token=je2gdlQ8IG3\u{2060}e0QIQ2y4xsT",
        "je2gdlQ8IG3e0QIQ2y4xsT",
    );
}

#[test]
fn adv91_google_ads_api_developer_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "google-ads-api-developer-token",
        "developer_token=je2gdlQ8IG3\u{180E}e0QIQ2y4xsT",
        "je2gdlQ8IG3e0QIQ2y4xsT",
    );
}

#[test]
fn adv91_google_ads_api_developer_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "google-ads-api-developer-token",
        "developer_token=je2gdlQ8IG3\u{202E}e0QIQ2y4xsT",
        "je2gdlQ8IG3e0QIQ2y4xsT",
    );
}

#[test]
fn adv91_google_ads_api_developer_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "google-ads-api-developer-token",
        "developer_token=je2gdlQ8IG3\u{202C}e0QIQ2y4xsT",
        "je2gdlQ8IG3e0QIQ2y4xsT",
    );
}

#[test]
fn adv91_google_ads_api_developer_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "google-ads-api-developer-token",
        "developer_token=je2gdlQ8IG3\u{200E}e0QIQ2y4xsT",
        "je2gdlQ8IG3e0QIQ2y4xsT",
    );
}

// =========================================================================
// 10. GOOGLE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv91_google_api_key_normal_must_fire() {
    assert_detector_fires(
        "google-api-key",
        "AIza9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnV",
        "AIza9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnV",
    );
}

#[test]
fn adv91_google_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("google-api-key", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv91_google_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "google-api-key",
        "AIza9X3kQp7VbT2hYRz\u{200B}NcMfWj4DgEsLuHaIoBnV",
        "AIza9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnV",
    );
}

#[test]
fn adv91_google_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "google-api-key",
        "AIza9X3kQp7VbT2hYRz\u{00AD}NcMfWj4DgEsLuHaIoBnV",
        "AIza9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnV",
    );
}

#[test]
fn adv91_google_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "google-api-key",
        "AIza9X3kQp7VbT2hYRz\u{200C}NcMfWj4DgEsLuHaIoBnV",
        "AIza9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnV",
    );
}

#[test]
fn adv91_google_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "google-api-key",
        "AIza9X3kQp7VbT2hYRz\u{200D}NcMfWj4DgEsLuHaIoBnV",
        "AIza9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnV",
    );
}

#[test]
fn adv91_google_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "google-api-key",
        "AIza9X3kQp7VbT2hYRz\u{FEFF}NcMfWj4DgEsLuHaIoBnV",
        "AIza9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnV",
    );
}

#[test]
fn adv91_google_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "google-api-key",
        "AIza9X3kQp7VbT2hYRz\u{2060}NcMfWj4DgEsLuHaIoBnV",
        "AIza9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnV",
    );
}

#[test]
fn adv91_google_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "google-api-key",
        "AIza9X3kQp7VbT2hYRz\u{180E}NcMfWj4DgEsLuHaIoBnV",
        "AIza9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnV",
    );
}

#[test]
fn adv91_google_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "google-api-key",
        "AIza9X3kQp7VbT2hYRz\u{202E}NcMfWj4DgEsLuHaIoBnV",
        "AIza9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnV",
    );
}

#[test]
fn adv91_google_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "google-api-key",
        "AIza9X3kQp7VbT2hYRz\u{202C}NcMfWj4DgEsLuHaIoBnV",
        "AIza9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnV",
    );
}

#[test]
fn adv91_google_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "google-api-key",
        "AIza9X3kQp7VbT2hYRz\u{200E}NcMfWj4DgEsLuHaIoBnV",
        "AIza9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnV",
    );
}
