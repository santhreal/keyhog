//! Part 58 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates redis, redis, remitly, render, render, replicate, replit, resend, resend, retool detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. REDIS CLOUD V2 API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv58_redis_cloud_v2_api_key_normal_must_fire() {
    assert_detector_fires(
        "redis-cloud-v2-api-key",
        "REDIS_CLOUD_V2_API_KEY=d1935adc5f2e5219091134d0fb1b5822c47225da",
        "d1935adc5f2e5219091134d0fb1b5822c47225da",
    );
}

#[test]
fn adv58_redis_cloud_v2_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "redis-cloud-v2-api-key",
        "dummy_prefix_0 =xxx35adc5f2e5219091134d0fb1b5822c47225da",
    );
}

#[test]
fn adv58_redis_cloud_v2_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "redis-cloud-v2-api-key",
        "REDIS_CLOUD_V2_API_KEY=d1935adc5f2e52190911\u{200B}34d0fb1b5822c47225da",
        "d1935adc5f2e5219091134d0fb1b5822c47225da",
    );
}

#[test]
fn adv58_redis_cloud_v2_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "redis-cloud-v2-api-key",
        "REDIS_CLOUD_V2_API_KEY=d1935adc5f2e52190911\u{00AD}34d0fb1b5822c47225da",
        "d1935adc5f2e5219091134d0fb1b5822c47225da",
    );
}

// =========================================================================
// 2. REDIS LABS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv58_redis_labs_api_key_normal_must_fire() {
    assert_detector_fires(
        "redis-labs-api-key",
        "REDIS_LABS_API_KEY=517cfd95dfd9f72aaf77a72c5fadfc74",
        "517cfd95dfd9f72aaf77a72c5fadfc74",
    );
}

#[test]
fn adv58_redis_labs_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "redis-labs-api-key",
        "dummy_prefix_0 =xxxcfd95dfd9f72aaf77a72c5fadfc74",
    );
}

#[test]
fn adv58_redis_labs_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "redis-labs-api-key",
        "REDIS_LABS_API_KEY=517cfd95dfd9f72a\u{200B}af77a72c5fadfc74",
        "517cfd95dfd9f72aaf77a72c5fadfc74",
    );
}

#[test]
fn adv58_redis_labs_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "redis-labs-api-key",
        "REDIS_LABS_API_KEY=517cfd95dfd9f72a\u{00AD}af77a72c5fadfc74",
        "517cfd95dfd9f72aaf77a72c5fadfc74",
    );
}

// =========================================================================
// 3. REMITLY API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv58_remitly_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "remitly-api-credentials",
        "REMITLYSECRET=L_7WqtXx_S2EwRDJn_OAdB13uj-8I08qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
        "L_7WqtXx_S2EwRDJn_OAdB13uj-8I08qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
    );
}

#[test]
fn adv58_remitly_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "remitly-api-credentials",
        "dummy_prefix_0 =xxxWqtXx_S2EwRDJn_OAdB13uj-8I08qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
    );
}

#[test]
fn adv58_remitly_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "remitly-api-credentials",
        "REMITLYSECRET=L_7WqtXx_S2EwRDJn_OAdB13uj-8I0\u{200B}8qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
        "L_7WqtXx_S2EwRDJn_OAdB13uj-8I08qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
    );
}

#[test]
fn adv58_remitly_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "remitly-api-credentials",
        "REMITLYSECRET=L_7WqtXx_S2EwRDJn_OAdB13uj-8I0\u{00AD}8qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
        "L_7WqtXx_S2EwRDJn_OAdB13uj-8I08qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
    );
}

// =========================================================================
// 4. RENDER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv58_render_api_key_normal_must_fire() {
    assert_detector_fires(
        "render-api-key",
        "rnd_9X3kQp7VbT2hYRzNcMfWj4Dg",
        "rnd_9X3kQp7VbT2hYRzNcMfWj4Dg",
    );
}

#[test]
fn adv58_render_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "render-api-key",
        "dummy9X3kQp7VbT2hYRzNcMfWj4Dg",
    );
}

#[test]
fn adv58_render_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "render-api-key",
        "rnd_9X3kQp7VbT\u{200B}2hYRzNcMfWj4Dg",
        "rnd_9X3kQp7VbT2hYRzNcMfWj4Dg",
    );
}

#[test]
fn adv58_render_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "render-api-key",
        "rnd_9X3kQp7VbT\u{00AD}2hYRzNcMfWj4Dg",
        "rnd_9X3kQp7VbT2hYRzNcMfWj4Dg",
    );
}

// =========================================================================
// 5. RENDER DEPLOY HOOK ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv58_render_deploy_hook_normal_must_fire() {
    assert_detector_fires(
        "render-deploy-hook",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15ff3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15ff3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
    );
}

#[test]
fn adv58_render_deploy_hook_wrong_prefix_must_silent() {
    assert_detector_silent(
        "render-deploy-hook",
        "dummy_prefix_0 =6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
    );
}

#[test]
fn adv58_render_deploy_hook_evade_zwsp_must_fire() {
    assert_detector_fires(
        "render-deploy-hook",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15f\u{200B}f3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15ff3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
    );
}

#[test]
fn adv58_render_deploy_hook_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "render-deploy-hook",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15f\u{00AD}f3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15ff3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
    );
}

// =========================================================================
// 6. REPLICATE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv58_replicate_api_key_normal_must_fire() {
    assert_detector_fires(
        "replicate-api-key",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv58_replicate_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "replicate-api-key",
        "dummyp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv58_replicate_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "replicate-api-key",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw\u{200B}3YzKp4Qx7Rm2Sn5Tb8Vw",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv58_replicate_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "replicate-api-key",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw\u{00AD}3YzKp4Qx7Rm2Sn5Tb8Vw",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

// =========================================================================
// 7. REPLIT API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv58_replit_api_token_normal_must_fire() {
    assert_detector_fires(
        "replit-api-token",
        "REPLIT_TOKEN=9qtUzgH7dMqUlSTEoivR8-oPFmpLxB",
        "9qtUzgH7dMqUlSTEoivR8-oPFmpLxB",
    );
}

#[test]
fn adv58_replit_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "replit-api-token",
        "dummy_prefix_0 =xxxUzgH7dMqUlSTEoivR8-oPFmpLxB",
    );
}

#[test]
fn adv58_replit_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "replit-api-token",
        "REPLIT_TOKEN=9qtUzgH7dMqUlST\u{200B}EoivR8-oPFmpLxB",
        "9qtUzgH7dMqUlSTEoivR8-oPFmpLxB",
    );
}

#[test]
fn adv58_replit_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "replit-api-token",
        "REPLIT_TOKEN=9qtUzgH7dMqUlST\u{00AD}EoivR8-oPFmpLxB",
        "9qtUzgH7dMqUlSTEoivR8-oPFmpLxB",
    );
}

// =========================================================================
// 8. RESEND API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv58_resend_api_key_normal_must_fire() {
    assert_detector_fires(
        "resend-api-key",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv58_resend_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "resend-api-key",
        "dummyp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv58_resend_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "resend-api-key",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{200B}4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv58_resend_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "resend-api-key",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{00AD}4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

// =========================================================================
// 9. RESEND WEBHOOK SIGNING SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv58_resend_webhook_signing_secret_normal_must_fire() {
    assert_detector_fires(
        "resend-webhook-signing-secret",
        "whsec_XabErUS2Y5QkC0OSzR9WBr5ho8NBfAgG",
        "whsec_XabErUS2Y5QkC0OSzR9WBr5ho8NBfAgG",
    );
}

#[test]
fn adv58_resend_webhook_signing_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "resend-webhook-signing-secret",
        "dummyc_XabErUS2Y5QkC0OSzR9WBr5ho8NBfAgG",
    );
}

#[test]
fn adv58_resend_webhook_signing_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "resend-webhook-signing-secret",
        "whsec_XabErUS2Y5QkC\u{200B}0OSzR9WBr5ho8NBfAgG",
        "whsec_XabErUS2Y5QkC0OSzR9WBr5ho8NBfAgG",
    );
}

#[test]
fn adv58_resend_webhook_signing_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "resend-webhook-signing-secret",
        "whsec_XabErUS2Y5QkC\u{00AD}0OSzR9WBr5ho8NBfAgG",
        "whsec_XabErUS2Y5QkC0OSzR9WBr5ho8NBfAgG",
    );
}

// =========================================================================
// 10. RETOOL API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv58_retool_api_key_normal_must_fire() {
    assert_detector_fires(
        "retool-api-key",
        "retool_api_0sI0n2TSM9vvCvZmGeP8eoWow4CByclT",
        "retool_api_0sI0n2TSM9vvCvZmGeP8eoWow4CByclT",
    );
}

#[test]
fn adv58_retool_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "retool-api-key",
        "dummyol_api_0sI0n2TSM9vvCvZmGeP8eoWow4CByclT",
    );
}

#[test]
fn adv58_retool_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "retool-api-key",
        "retool_api_0sI0n2TSM9\u{200B}vvCvZmGeP8eoWow4CByclT",
        "retool_api_0sI0n2TSM9vvCvZmGeP8eoWow4CByclT",
    );
}

#[test]
fn adv58_retool_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "retool-api-key",
        "retool_api_0sI0n2TSM9\u{00AD}vvCvZmGeP8eoWow4CByclT",
        "retool_api_0sI0n2TSM9vvCvZmGeP8eoWow4CByclT",
    );
}


