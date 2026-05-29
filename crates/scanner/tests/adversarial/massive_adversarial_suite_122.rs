//! Part 122 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates render, render, replicate, replit, resend, resend, retool, retool, ringcentral, riotgames detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. RENDER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv122_render_api_key_normal_must_fire() {
    assert_detector_fires(
        "render-api-key",
        "rnd_9X3kQp7VbT2hYRzNcMfWj4Dg",
        "rnd_9X3kQp7VbT2hYRzNcMfWj4Dg",
    );
}

#[test]
fn adv122_render_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "render-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv122_render_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "render-api-key",
        "rnd_9X3kQp7VbT\u{200B}2hYRzNcMfWj4Dg",
        "rnd_9X3kQp7VbT2hYRzNcMfWj4Dg",
    );
}

#[test]
fn adv122_render_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "render-api-key",
        "rnd_9X3kQp7VbT\u{00AD}2hYRzNcMfWj4Dg",
        "rnd_9X3kQp7VbT2hYRzNcMfWj4Dg",
    );
}

#[test]
fn adv122_render_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "render-api-key",
        "rnd_9X3kQp7VbT\u{200C}2hYRzNcMfWj4Dg",
        "rnd_9X3kQp7VbT2hYRzNcMfWj4Dg",
    );
}

#[test]
fn adv122_render_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "render-api-key",
        "rnd_9X3kQp7VbT\u{200D}2hYRzNcMfWj4Dg",
        "rnd_9X3kQp7VbT2hYRzNcMfWj4Dg",
    );
}

#[test]
fn adv122_render_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "render-api-key",
        "rnd_9X3kQp7VbT\u{FEFF}2hYRzNcMfWj4Dg",
        "rnd_9X3kQp7VbT2hYRzNcMfWj4Dg",
    );
}

#[test]
fn adv122_render_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "render-api-key",
        "rnd_9X3kQp7VbT\u{2060}2hYRzNcMfWj4Dg",
        "rnd_9X3kQp7VbT2hYRzNcMfWj4Dg",
    );
}

#[test]
fn adv122_render_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "render-api-key",
        "rnd_9X3kQp7VbT\u{180E}2hYRzNcMfWj4Dg",
        "rnd_9X3kQp7VbT2hYRzNcMfWj4Dg",
    );
}

#[test]
fn adv122_render_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "render-api-key",
        "rnd_9X3kQp7VbT\u{202E}2hYRzNcMfWj4Dg",
        "rnd_9X3kQp7VbT2hYRzNcMfWj4Dg",
    );
}

#[test]
fn adv122_render_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "render-api-key",
        "rnd_9X3kQp7VbT\u{202C}2hYRzNcMfWj4Dg",
        "rnd_9X3kQp7VbT2hYRzNcMfWj4Dg",
    );
}

#[test]
fn adv122_render_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "render-api-key",
        "rnd_9X3kQp7VbT\u{200E}2hYRzNcMfWj4Dg",
        "rnd_9X3kQp7VbT2hYRzNcMfWj4Dg",
    );
}

// =========================================================================
// 2. RENDER DEPLOY HOOK ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv122_render_deploy_hook_normal_must_fire() {
    assert_detector_fires(
        "render-deploy-hook",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15ff3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15ff3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
    );
}

#[test]
fn adv122_render_deploy_hook_wrong_prefix_must_silent() {
    assert_detector_silent(
        "render-deploy-hook",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv122_render_deploy_hook_evade_zwsp_must_fire() {
    assert_detector_fires(
        "render-deploy-hook",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15f\u{200B}f3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15ff3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
    );
}

#[test]
fn adv122_render_deploy_hook_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "render-deploy-hook",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15f\u{00AD}f3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15ff3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
    );
}

#[test]
fn adv122_render_deploy_hook_evade_zwnj_must_fire() {
    assert_detector_fires(
        "render-deploy-hook",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15f\u{200C}f3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15ff3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
    );
}

#[test]
fn adv122_render_deploy_hook_evade_zwj_must_fire() {
    assert_detector_fires(
        "render-deploy-hook",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15f\u{200D}f3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15ff3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
    );
}

#[test]
fn adv122_render_deploy_hook_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "render-deploy-hook",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15f\u{FEFF}f3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15ff3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
    );
}

#[test]
fn adv122_render_deploy_hook_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "render-deploy-hook",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15f\u{2060}f3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15ff3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
    );
}

#[test]
fn adv122_render_deploy_hook_evade_mongolian_must_fire() {
    assert_detector_fires(
        "render-deploy-hook",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15f\u{180E}f3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15ff3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
    );
}

#[test]
fn adv122_render_deploy_hook_evade_rtl_must_fire() {
    assert_detector_fires(
        "render-deploy-hook",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15f\u{202E}f3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15ff3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
    );
}

#[test]
fn adv122_render_deploy_hook_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "render-deploy-hook",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15f\u{202C}f3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15ff3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
    );
}

#[test]
fn adv122_render_deploy_hook_evade_lrm_must_fire() {
    assert_detector_fires(
        "render-deploy-hook",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15f\u{200E}f3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
        "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15ff3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
    );
}

// =========================================================================
// 3. REPLICATE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv122_replicate_api_key_normal_must_fire() {
    assert_detector_fires(
        "replicate-api-key",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv122_replicate_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "replicate-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv122_replicate_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "replicate-api-key",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw\u{200B}3YzKp4Qx7Rm2Sn5Tb8Vw",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv122_replicate_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "replicate-api-key",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw\u{00AD}3YzKp4Qx7Rm2Sn5Tb8Vw",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv122_replicate_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "replicate-api-key",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw\u{200C}3YzKp4Qx7Rm2Sn5Tb8Vw",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv122_replicate_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "replicate-api-key",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw\u{200D}3YzKp4Qx7Rm2Sn5Tb8Vw",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv122_replicate_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "replicate-api-key",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw\u{FEFF}3YzKp4Qx7Rm2Sn5Tb8Vw",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv122_replicate_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "replicate-api-key",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw\u{2060}3YzKp4Qx7Rm2Sn5Tb8Vw",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv122_replicate_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "replicate-api-key",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw\u{180E}3YzKp4Qx7Rm2Sn5Tb8Vw",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv122_replicate_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "replicate-api-key",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw\u{202E}3YzKp4Qx7Rm2Sn5Tb8Vw",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv122_replicate_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "replicate-api-key",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw\u{202C}3YzKp4Qx7Rm2Sn5Tb8Vw",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

#[test]
fn adv122_replicate_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "replicate-api-key",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw\u{200E}3YzKp4Qx7Rm2Sn5Tb8Vw",
        "r8_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw",
    );
}

// =========================================================================
// 4. REPLIT API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv122_replit_api_token_normal_must_fire() {
    assert_detector_fires(
        "replit-api-token",
        "REPLIT_TOKEN=9qtUzgH7dMqUlSTEoivR8-oPFmpLxB",
        "9qtUzgH7dMqUlSTEoivR8-oPFmpLxB",
    );
}

#[test]
fn adv122_replit_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "replit-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv122_replit_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "replit-api-token",
        "REPLIT_TOKEN=9qtUzgH7dMqUlST\u{200B}EoivR8-oPFmpLxB",
        "9qtUzgH7dMqUlSTEoivR8-oPFmpLxB",
    );
}

#[test]
fn adv122_replit_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "replit-api-token",
        "REPLIT_TOKEN=9qtUzgH7dMqUlST\u{00AD}EoivR8-oPFmpLxB",
        "9qtUzgH7dMqUlSTEoivR8-oPFmpLxB",
    );
}

#[test]
fn adv122_replit_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "replit-api-token",
        "REPLIT_TOKEN=9qtUzgH7dMqUlST\u{200C}EoivR8-oPFmpLxB",
        "9qtUzgH7dMqUlSTEoivR8-oPFmpLxB",
    );
}

#[test]
fn adv122_replit_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "replit-api-token",
        "REPLIT_TOKEN=9qtUzgH7dMqUlST\u{200D}EoivR8-oPFmpLxB",
        "9qtUzgH7dMqUlSTEoivR8-oPFmpLxB",
    );
}

#[test]
fn adv122_replit_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "replit-api-token",
        "REPLIT_TOKEN=9qtUzgH7dMqUlST\u{FEFF}EoivR8-oPFmpLxB",
        "9qtUzgH7dMqUlSTEoivR8-oPFmpLxB",
    );
}

#[test]
fn adv122_replit_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "replit-api-token",
        "REPLIT_TOKEN=9qtUzgH7dMqUlST\u{2060}EoivR8-oPFmpLxB",
        "9qtUzgH7dMqUlSTEoivR8-oPFmpLxB",
    );
}

#[test]
fn adv122_replit_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "replit-api-token",
        "REPLIT_TOKEN=9qtUzgH7dMqUlST\u{180E}EoivR8-oPFmpLxB",
        "9qtUzgH7dMqUlSTEoivR8-oPFmpLxB",
    );
}

#[test]
fn adv122_replit_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "replit-api-token",
        "REPLIT_TOKEN=9qtUzgH7dMqUlST\u{202E}EoivR8-oPFmpLxB",
        "9qtUzgH7dMqUlSTEoivR8-oPFmpLxB",
    );
}

#[test]
fn adv122_replit_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "replit-api-token",
        "REPLIT_TOKEN=9qtUzgH7dMqUlST\u{202C}EoivR8-oPFmpLxB",
        "9qtUzgH7dMqUlSTEoivR8-oPFmpLxB",
    );
}

#[test]
fn adv122_replit_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "replit-api-token",
        "REPLIT_TOKEN=9qtUzgH7dMqUlST\u{200E}EoivR8-oPFmpLxB",
        "9qtUzgH7dMqUlSTEoivR8-oPFmpLxB",
    );
}

// =========================================================================
// 5. RESEND API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv122_resend_api_key_normal_must_fire() {
    assert_detector_fires(
        "resend-api-key",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv122_resend_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "resend-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv122_resend_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "resend-api-key",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{200B}4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv122_resend_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "resend-api-key",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{00AD}4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv122_resend_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "resend-api-key",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{200C}4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv122_resend_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "resend-api-key",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{200D}4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv122_resend_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "resend-api-key",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{FEFF}4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv122_resend_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "resend-api-key",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{2060}4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv122_resend_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "resend-api-key",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{180E}4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv122_resend_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "resend-api-key",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{202E}4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv122_resend_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "resend-api-key",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{202C}4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv122_resend_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "resend-api-key",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{200E}4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "re_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

// =========================================================================
// 6. RESEND WEBHOOK SIGNING SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv122_resend_webhook_signing_secret_normal_must_fire() {
    assert_detector_fires(
        "resend-webhook-signing-secret",
        "whsec_XabErUS2Y5QkC0OSzR9WBr5ho8NBfAgG",
        "whsec_XabErUS2Y5QkC0OSzR9WBr5ho8NBfAgG",
    );
}

#[test]
fn adv122_resend_webhook_signing_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "resend-webhook-signing-secret",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv122_resend_webhook_signing_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "resend-webhook-signing-secret",
        "whsec_XabErUS2Y5QkC\u{200B}0OSzR9WBr5ho8NBfAgG",
        "whsec_XabErUS2Y5QkC0OSzR9WBr5ho8NBfAgG",
    );
}

#[test]
fn adv122_resend_webhook_signing_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "resend-webhook-signing-secret",
        "whsec_XabErUS2Y5QkC\u{00AD}0OSzR9WBr5ho8NBfAgG",
        "whsec_XabErUS2Y5QkC0OSzR9WBr5ho8NBfAgG",
    );
}

#[test]
fn adv122_resend_webhook_signing_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "resend-webhook-signing-secret",
        "whsec_XabErUS2Y5QkC\u{200C}0OSzR9WBr5ho8NBfAgG",
        "whsec_XabErUS2Y5QkC0OSzR9WBr5ho8NBfAgG",
    );
}

#[test]
fn adv122_resend_webhook_signing_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "resend-webhook-signing-secret",
        "whsec_XabErUS2Y5QkC\u{200D}0OSzR9WBr5ho8NBfAgG",
        "whsec_XabErUS2Y5QkC0OSzR9WBr5ho8NBfAgG",
    );
}

#[test]
fn adv122_resend_webhook_signing_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "resend-webhook-signing-secret",
        "whsec_XabErUS2Y5QkC\u{FEFF}0OSzR9WBr5ho8NBfAgG",
        "whsec_XabErUS2Y5QkC0OSzR9WBr5ho8NBfAgG",
    );
}

#[test]
fn adv122_resend_webhook_signing_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "resend-webhook-signing-secret",
        "whsec_XabErUS2Y5QkC\u{2060}0OSzR9WBr5ho8NBfAgG",
        "whsec_XabErUS2Y5QkC0OSzR9WBr5ho8NBfAgG",
    );
}

#[test]
fn adv122_resend_webhook_signing_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "resend-webhook-signing-secret",
        "whsec_XabErUS2Y5QkC\u{180E}0OSzR9WBr5ho8NBfAgG",
        "whsec_XabErUS2Y5QkC0OSzR9WBr5ho8NBfAgG",
    );
}

#[test]
fn adv122_resend_webhook_signing_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "resend-webhook-signing-secret",
        "whsec_XabErUS2Y5QkC\u{202E}0OSzR9WBr5ho8NBfAgG",
        "whsec_XabErUS2Y5QkC0OSzR9WBr5ho8NBfAgG",
    );
}

#[test]
fn adv122_resend_webhook_signing_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "resend-webhook-signing-secret",
        "whsec_XabErUS2Y5QkC\u{202C}0OSzR9WBr5ho8NBfAgG",
        "whsec_XabErUS2Y5QkC0OSzR9WBr5ho8NBfAgG",
    );
}

#[test]
fn adv122_resend_webhook_signing_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "resend-webhook-signing-secret",
        "whsec_XabErUS2Y5QkC\u{200E}0OSzR9WBr5ho8NBfAgG",
        "whsec_XabErUS2Y5QkC0OSzR9WBr5ho8NBfAgG",
    );
}

// =========================================================================
// 7. RETOOL API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv122_retool_api_key_normal_must_fire() {
    assert_detector_fires(
        "retool-api-key",
        "retool_api_0sI0n2TSM9vvCvZmGeP8eoWow4CByclT",
        "retool_api_0sI0n2TSM9vvCvZmGeP8eoWow4CByclT",
    );
}

#[test]
fn adv122_retool_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "retool-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv122_retool_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "retool-api-key",
        "retool_api_0sI0n2TSM9\u{200B}vvCvZmGeP8eoWow4CByclT",
        "retool_api_0sI0n2TSM9vvCvZmGeP8eoWow4CByclT",
    );
}

#[test]
fn adv122_retool_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "retool-api-key",
        "retool_api_0sI0n2TSM9\u{00AD}vvCvZmGeP8eoWow4CByclT",
        "retool_api_0sI0n2TSM9vvCvZmGeP8eoWow4CByclT",
    );
}

#[test]
fn adv122_retool_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "retool-api-key",
        "retool_api_0sI0n2TSM9\u{200C}vvCvZmGeP8eoWow4CByclT",
        "retool_api_0sI0n2TSM9vvCvZmGeP8eoWow4CByclT",
    );
}

#[test]
fn adv122_retool_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "retool-api-key",
        "retool_api_0sI0n2TSM9\u{200D}vvCvZmGeP8eoWow4CByclT",
        "retool_api_0sI0n2TSM9vvCvZmGeP8eoWow4CByclT",
    );
}

#[test]
fn adv122_retool_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "retool-api-key",
        "retool_api_0sI0n2TSM9\u{FEFF}vvCvZmGeP8eoWow4CByclT",
        "retool_api_0sI0n2TSM9vvCvZmGeP8eoWow4CByclT",
    );
}

#[test]
fn adv122_retool_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "retool-api-key",
        "retool_api_0sI0n2TSM9\u{2060}vvCvZmGeP8eoWow4CByclT",
        "retool_api_0sI0n2TSM9vvCvZmGeP8eoWow4CByclT",
    );
}

#[test]
fn adv122_retool_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "retool-api-key",
        "retool_api_0sI0n2TSM9\u{180E}vvCvZmGeP8eoWow4CByclT",
        "retool_api_0sI0n2TSM9vvCvZmGeP8eoWow4CByclT",
    );
}

#[test]
fn adv122_retool_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "retool-api-key",
        "retool_api_0sI0n2TSM9\u{202E}vvCvZmGeP8eoWow4CByclT",
        "retool_api_0sI0n2TSM9vvCvZmGeP8eoWow4CByclT",
    );
}

#[test]
fn adv122_retool_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "retool-api-key",
        "retool_api_0sI0n2TSM9\u{202C}vvCvZmGeP8eoWow4CByclT",
        "retool_api_0sI0n2TSM9vvCvZmGeP8eoWow4CByclT",
    );
}

#[test]
fn adv122_retool_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "retool-api-key",
        "retool_api_0sI0n2TSM9\u{200E}vvCvZmGeP8eoWow4CByclT",
        "retool_api_0sI0n2TSM9vvCvZmGeP8eoWow4CByclT",
    );
}

// =========================================================================
// 8. RETOOL DATABASE CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv122_retool_database_credentials_normal_must_fire() {
    assert_detector_fires(
        "retool-database-credentials",
        "RETOOL_DB_PASSWORD=RetoolDbPass123456",
        "RetoolDbPass123456",
    );
}

#[test]
fn adv122_retool_database_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "retool-database-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv122_retool_database_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "retool-database-credentials",
        "RETOOL_DB_PASSWORD=RetoolDbP\u{200B}ass123456",
        "RetoolDbPass123456",
    );
}

#[test]
fn adv122_retool_database_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "retool-database-credentials",
        "RETOOL_DB_PASSWORD=RetoolDbP\u{00AD}ass123456",
        "RetoolDbPass123456",
    );
}

#[test]
fn adv122_retool_database_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "retool-database-credentials",
        "RETOOL_DB_PASSWORD=RetoolDbP\u{200C}ass123456",
        "RetoolDbPass123456",
    );
}

#[test]
fn adv122_retool_database_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "retool-database-credentials",
        "RETOOL_DB_PASSWORD=RetoolDbP\u{200D}ass123456",
        "RetoolDbPass123456",
    );
}

#[test]
fn adv122_retool_database_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "retool-database-credentials",
        "RETOOL_DB_PASSWORD=RetoolDbP\u{FEFF}ass123456",
        "RetoolDbPass123456",
    );
}

#[test]
fn adv122_retool_database_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "retool-database-credentials",
        "RETOOL_DB_PASSWORD=RetoolDbP\u{2060}ass123456",
        "RetoolDbPass123456",
    );
}

#[test]
fn adv122_retool_database_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "retool-database-credentials",
        "RETOOL_DB_PASSWORD=RetoolDbP\u{180E}ass123456",
        "RetoolDbPass123456",
    );
}

#[test]
fn adv122_retool_database_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "retool-database-credentials",
        "RETOOL_DB_PASSWORD=RetoolDbP\u{202E}ass123456",
        "RetoolDbPass123456",
    );
}

#[test]
fn adv122_retool_database_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "retool-database-credentials",
        "RETOOL_DB_PASSWORD=RetoolDbP\u{202C}ass123456",
        "RetoolDbPass123456",
    );
}

#[test]
fn adv122_retool_database_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "retool-database-credentials",
        "RETOOL_DB_PASSWORD=RetoolDbP\u{200E}ass123456",
        "RetoolDbPass123456",
    );
}

// =========================================================================
// 9. RINGCENTRAL API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv122_ringcentral_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "ringcentral-api-credentials",
        "ringcentralclientid=Iqt1Wwep_ED4e1JzZYKZ",
        "Iqt1Wwep_ED4e1JzZYKZ",
    );
}

#[test]
fn adv122_ringcentral_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ringcentral-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv122_ringcentral_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ringcentral-api-credentials",
        "ringcentralclientid=Iqt1Wwep_E\u{200B}D4e1JzZYKZ",
        "Iqt1Wwep_ED4e1JzZYKZ",
    );
}

#[test]
fn adv122_ringcentral_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ringcentral-api-credentials",
        "ringcentralclientid=Iqt1Wwep_E\u{00AD}D4e1JzZYKZ",
        "Iqt1Wwep_ED4e1JzZYKZ",
    );
}

#[test]
fn adv122_ringcentral_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "ringcentral-api-credentials",
        "ringcentralclientid=Iqt1Wwep_E\u{200C}D4e1JzZYKZ",
        "Iqt1Wwep_ED4e1JzZYKZ",
    );
}

#[test]
fn adv122_ringcentral_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "ringcentral-api-credentials",
        "ringcentralclientid=Iqt1Wwep_E\u{200D}D4e1JzZYKZ",
        "Iqt1Wwep_ED4e1JzZYKZ",
    );
}

#[test]
fn adv122_ringcentral_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "ringcentral-api-credentials",
        "ringcentralclientid=Iqt1Wwep_E\u{FEFF}D4e1JzZYKZ",
        "Iqt1Wwep_ED4e1JzZYKZ",
    );
}

#[test]
fn adv122_ringcentral_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "ringcentral-api-credentials",
        "ringcentralclientid=Iqt1Wwep_E\u{2060}D4e1JzZYKZ",
        "Iqt1Wwep_ED4e1JzZYKZ",
    );
}

#[test]
fn adv122_ringcentral_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "ringcentral-api-credentials",
        "ringcentralclientid=Iqt1Wwep_E\u{180E}D4e1JzZYKZ",
        "Iqt1Wwep_ED4e1JzZYKZ",
    );
}

#[test]
fn adv122_ringcentral_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "ringcentral-api-credentials",
        "ringcentralclientid=Iqt1Wwep_E\u{202E}D4e1JzZYKZ",
        "Iqt1Wwep_ED4e1JzZYKZ",
    );
}

#[test]
fn adv122_ringcentral_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "ringcentral-api-credentials",
        "ringcentralclientid=Iqt1Wwep_E\u{202C}D4e1JzZYKZ",
        "Iqt1Wwep_ED4e1JzZYKZ",
    );
}

#[test]
fn adv122_ringcentral_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "ringcentral-api-credentials",
        "ringcentralclientid=Iqt1Wwep_E\u{200E}D4e1JzZYKZ",
        "Iqt1Wwep_ED4e1JzZYKZ",
    );
}

// =========================================================================
// 10. RIOTGAMES API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv122_riotgames_api_key_normal_must_fire() {
    assert_detector_fires(
        "riotgames-api-key",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
    );
}

#[test]
fn adv122_riotgames_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "riotgames-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv122_riotgames_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "riotgames-api-key",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q\u{200B}1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
    );
}

#[test]
fn adv122_riotgames_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "riotgames-api-key",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q\u{00AD}1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
    );
}

#[test]
fn adv122_riotgames_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "riotgames-api-key",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q\u{200C}1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
    );
}

#[test]
fn adv122_riotgames_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "riotgames-api-key",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q\u{200D}1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
    );
}

#[test]
fn adv122_riotgames_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "riotgames-api-key",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q\u{FEFF}1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
    );
}

#[test]
fn adv122_riotgames_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "riotgames-api-key",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q\u{2060}1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
    );
}

#[test]
fn adv122_riotgames_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "riotgames-api-key",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q\u{180E}1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
    );
}

#[test]
fn adv122_riotgames_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "riotgames-api-key",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q\u{202E}1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
    );
}

#[test]
fn adv122_riotgames_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "riotgames-api-key",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q\u{202C}1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
    );
}

#[test]
fn adv122_riotgames_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "riotgames-api-key",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q\u{200E}1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
    );
}


