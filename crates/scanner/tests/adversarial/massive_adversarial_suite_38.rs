//! Part 38 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates gitkraken, gitlab, gitpod, glitch, goatcounter, gocardless,
//! goldsky, and google-ads detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. GITKRAKEN API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv38_gitkraken_normal_must_fire() {
    assert_detector_fires(
        "gitkraken-api-token",
        "gitkraken_token = \"abcde12345abcde12345abcde1234512\"",
        "abcde12345abcde12345abcde1234512",
    );
}

#[test]
fn adv38_gitkraken_wrong_prefix_must_silent() {
    assert_detector_silent(
        "gitkraken-api-token",
        "gietkraken_token = \"abcde12345abcde12345abcde1234512\"",
    );
}

#[test]
fn adv38_gitkraken_evade_zwsp_must_fire() {
    assert_detector_fires(
        "gitkraken-api-token",
        "gitkraken_token = \"abcde12345\u{200B}abcde12345abcde1234512\"",
        "abcde12345abcde12345abcde1234512",
    );
}

#[test]
fn adv38_gitkraken_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "gitkraken-api-token",
        "gitkraken_token = \"abcde12345abcde12345abcde123\u{00AD}4512\"",
        "abcde12345abcde12345abcde1234512",
    );
}

#[test]
fn adv38_gitkraken_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "gitkraken-api-token",
        "g\u{0456}tkrak\u{0435}n_token = \"abcde12345abcde12345abcde1234512\"",
        "abcde12345abcde12345abcde1234512",
    );
}

// =========================================================================
// 2. GITLAB DEPLOY TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv38_gitlab_deploy_normal_must_fire() {
    assert_detector_fires(
        "gitlab-deploy-token",
        "gitlab_deploy = gldt-12345678901234567890",
        "gldt-12345678901234567890",
    );
}

#[test]
fn adv38_gitlab_deploy_wrong_prefix_must_silent() {
    assert_detector_silent(
        "gitlab-deploy-token",
        "gitlab_deploy = hldt-12345678901234567890",
    );
}

#[test]
fn adv38_gitlab_deploy_evade_zwsp_must_fire() {
    assert_detector_fires(
        "gitlab-deploy-token",
        "gitlab_deploy = gldt-\u{200B}12345678901234567890",
        "gldt-12345678901234567890",
    );
}

#[test]
fn adv38_gitlab_deploy_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "gitlab-deploy-token",
        "gitlab_deploy = gldt-1234567890123456\u{00AD}7890",
        "gldt-12345678901234567890",
    );
}

#[test]
fn adv38_gitlab_deploy_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "gitlab-deploy-token",
        "g\u{0456}tlab_deploy = gldt-12345678901234567890",
        "gldt-12345678901234567890",
    );
}

// =========================================================================
// 3. GITLAB PACKAGE REGISTRY TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv38_gitlab_package_normal_must_fire() {
    assert_detector_fires(
        "gitlab-package-registry-token",
        "gitlab_deploy = glcbt-12345678901234567890",
        "glcbt-12345678901234567890",
    );
}

#[test]
fn adv38_gitlab_package_wrong_prefix_must_silent() {
    assert_detector_silent(
        "gitlab-package-registry-token",
        "gitlab_deploy = hlcbt-12345678901234567890",
    );
}

#[test]
fn adv38_gitlab_package_evade_zwsp_must_fire() {
    assert_detector_fires(
        "gitlab-package-registry-token",
        "gitlab_deploy = glcbt-\u{200B}12345678901234567890",
        "glcbt-12345678901234567890",
    );
}

#[test]
fn adv38_gitlab_package_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "gitlab-package-registry-token",
        "gitlab_deploy = glcbt-1234567890123456\u{00AD}7890",
        "glcbt-12345678901234567890",
    );
}

#[test]
fn adv38_gitlab_package_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "gitlab-package-registry-token",
        "g\u{0456}tlab_deploy = glcbt-12345678901234567890",
        "glcbt-12345678901234567890",
    );
}

// =========================================================================
// 4. GITLAB PERSONAL ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv38_gitlab_pat_normal_must_fire() {
    assert_detector_fires(
        "gitlab-personal-access-token",
        "gitlab = glpat-12345678901234567890",
        "glpat-12345678901234567890",
    );
}

#[test]
fn adv38_gitlab_pat_wrong_prefix_must_silent() {
    assert_detector_silent(
        "gitlab-personal-access-token",
        "gitlab = hlpat-12345678901234567890",
    );
}

#[test]
fn adv38_gitlab_pat_evade_zwsp_must_fire() {
    assert_detector_fires(
        "gitlab-personal-access-token",
        "gitlab = glpat-\u{200B}12345678901234567890",
        "glpat-12345678901234567890",
    );
}

#[test]
fn adv38_gitlab_pat_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "gitlab-personal-access-token",
        "gitlab = glpat-1234567890123456\u{00AD}7890",
        "glpat-12345678901234567890",
    );
}

#[test]
fn adv38_gitlab_pat_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "gitlab-personal-access-token",
        "g\u{0456}tlab = glpat-12345678901234567890",
        "glpat-12345678901234567890",
    );
}

// =========================================================================
// 5. GITLAB PIPELINE TRIGGER TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv38_gitlab_trigger_normal_must_fire() {
    assert_detector_fires(
        "gitlab-pipeline-trigger-token",
        "gitlab = glptt-12345678901234567890",
        "glptt-12345678901234567890",
    );
}

#[test]
fn adv38_gitlab_trigger_wrong_prefix_must_silent() {
    assert_detector_silent(
        "gitlab-pipeline-trigger-token",
        "gitlab = hlptt-12345678901234567890",
    );
}

#[test]
fn adv38_gitlab_trigger_evade_zwsp_must_fire() {
    assert_detector_fires(
        "gitlab-pipeline-trigger-token",
        "gitlab = glptt-\u{200B}12345678901234567890",
        "glptt-12345678901234567890",
    );
}

#[test]
fn adv38_gitlab_trigger_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "gitlab-pipeline-trigger-token",
        "gitlab = glptt-1234567890123456\u{00AD}7890",
        "glptt-12345678901234567890",
    );
}

#[test]
fn adv38_gitlab_trigger_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "gitlab-pipeline-trigger-token",
        "g\u{0456}tlab = glptt-12345678901234567890",
        "glptt-12345678901234567890",
    );
}

// =========================================================================
// 6. GITLAB WEBHOOK SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv38_gitlab_webhook_normal_must_fire() {
    assert_detector_fires(
        "gitlab-webhook-secret",
        "gitlab_webhook_secret = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv38_gitlab_webhook_wrong_prefix_must_silent() {
    assert_detector_silent(
        "gitlab-webhook-secret",
        "hitlab_webhook_secret = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv38_gitlab_webhook_evade_zwsp_must_fire() {
    assert_detector_fires(
        "gitlab-webhook-secret",
        "gitlab_webhook_secret = \"abcde12345\u{200B}abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv38_gitlab_webhook_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "gitlab-webhook-secret",
        "gitlab_webhook_secret = \"abcde12345abcd\u{00AD}e12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv38_gitlab_webhook_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "gitlab-webhook-secret",
        "g\u{0456}tlab_w\u{0435}bh\u{043e}\u{043e}k_s\u{0435}cr\u{0435}t = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

// =========================================================================
// 7. GITPOD API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv38_gitpod_normal_must_fire() {
    assert_detector_fires(
        "gitpod-api-token",
        "gitpod_token = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    );
}

#[test]
fn adv38_gitpod_wrong_prefix_must_silent() {
    assert_detector_silent(
        "gitpod-api-token",
        "hitpod_token = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\"",
    );
}

#[test]
fn adv38_gitpod_evade_zwsp_must_fire() {
    assert_detector_fires(
        "gitpod-api-token",
        "gitpod_token = \"a1b2c3d4e5f6a1b2c3\u{200B}d4e5f6a1b2c3d4e5f6a1b2\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    );
}

#[test]
fn adv38_gitpod_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "gitpod-api-token",
        "gitpod_token = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5\u{00AD}f6a1b2\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    );
}

#[test]
fn adv38_gitpod_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "gitpod-api-token",
        "g\u{0456}tp\u{043e}d_t\u{043e}k\u{0435}n = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    );
}

// =========================================================================
// 8. GLITCH API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv38_glitch_normal_must_fire() {
    assert_detector_fires(
        "glitch-api-credentials",
        "glitch_token = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv38_glitch_wrong_prefix_must_silent() {
    assert_detector_silent(
        "glitch-api-credentials",
        "hlitch_token = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"",
    );
}

#[test]
fn adv38_glitch_evade_zwsp_must_fire() {
    assert_detector_fires(
        "glitch-api-credentials",
        "glitch_token = \"a1b2c3d4e5f6a1b2\u{200B}c3d4e5f6a1b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv38_glitch_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "glitch-api-credentials",
        "glitch_token = \"a1b2c3d4e5f6a1b2c3d4e5f6a1\u{00AD}b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv38_glitch_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "glitch-api-credentials",
        "gl\u{0456}tch_t\u{043e}k\u{0435}n = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

// =========================================================================
// 9. GOATCOUNTER API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv38_goatcounter_normal_must_fire() {
    assert_detector_fires(
        "goatcounter-api-credentials",
        "goatcounter_api_key = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv38_goatcounter_wrong_prefix_must_silent() {
    assert_detector_silent(
        "goatcounter-api-credentials",
        "hoatcounter_api_key = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"",
    );
}

#[test]
fn adv38_goatcounter_evade_zwsp_must_fire() {
    assert_detector_fires(
        "goatcounter-api-credentials",
        "goatcounter_api_key = \"a1b2c3d4e5f6a1b2\u{200B}c3d4e5f6a1b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv38_goatcounter_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "goatcounter-api-credentials",
        "goatcounter_api_key = \"a1b2c3d4e5f6a1b2c3d4e5f6a1\u{00AD}b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv38_goatcounter_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "goatcounter-api-credentials",
        "g\u{043e}atcount\u{0435}r_api_key = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

// =========================================================================
// 10. GOCARDLESS ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv38_gocardless_normal_must_fire() {
    assert_detector_fires(
        "gocardless-access-token",
        "gocardless_token = \"abcde12345abcde12345abcde12345\"",
        "abcde12345abcde12345abcde12345",
    );
}

#[test]
fn adv38_gocardless_wrong_prefix_must_silent() {
    assert_detector_silent(
        "gocardless-access-token",
        "hocardless_token = \"abcde12345abcde12345abcde12345\"",
    );
}

#[test]
fn adv38_gocardless_evade_zwsp_must_fire() {
    assert_detector_fires(
        "gocardless-access-token",
        "gocardless_token = \"abcde12345\u{200B}abcde12345abcde12345\"",
        "abcde12345abcde12345abcde12345",
    );
}

#[test]
fn adv38_gocardless_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "gocardless-access-token",
        "gocardless_token = \"abcde12345abcde12345abcde1\u{00AD}2345\"",
        "abcde12345abcde12345abcde12345",
    );
}

#[test]
fn adv38_gocardless_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "gocardless-access-token",
        "g\u{043e}cardl\u{0435}ss_t\u{043e}k\u{0435}n = \"abcde12345abcde12345abcde12345\"",
        "abcde12345abcde12345abcde12345",
    );
}

// =========================================================================
// 11. GOLDSKY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv38_goldsky_normal_must_fire() {
    assert_detector_fires(
        "goldsky-api-key",
        "goldsky_key = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv38_goldsky_wrong_prefix_must_silent() {
    assert_detector_silent(
        "goldsky-api-key",
        "holdsky_key = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"",
    );
}

#[test]
fn adv38_goldsky_evade_zwsp_must_fire() {
    assert_detector_fires(
        "goldsky-api-key",
        "goldsky_key = \"a1b2c3d4e5f6a1b2\u{200B}c3d4e5f6a1b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv38_goldsky_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "goldsky-api-key",
        "goldsky_key = \"a1b2c3d4e5f6a1b2c3d4e5f6a1\u{00AD}b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv38_goldsky_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "goldsky-api-key",
        "g\u{043e}ldsky_key = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

// =========================================================================
// 12. GOOGLE ADS API DEVELOPER TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv38_googleads_normal_must_fire() {
    assert_detector_fires(
        "google-ads-api-developer-token",
        "developer_token = \"abcde12345abcde1234512\"",
        "abcde12345abcde1234512",
    );
}

#[test]
fn adv38_googleads_wrong_prefix_must_silent() {
    assert_detector_silent(
        "google-ads-api-developer-token",
        "oeveloper_token = \"abcde12345abcde1234512\"",
    );
}

#[test]
fn adv38_googleads_evade_zwsp_must_fire() {
    assert_detector_fires(
        "google-ads-api-developer-token",
        "developer_token = \"abcde12345\u{200B}abcde1234512\"",
        "abcde12345abcde1234512",
    );
}

#[test]
fn adv38_googleads_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "google-ads-api-developer-token",
        "developer_token = \"abcde12345abcde123\u{00AD}4512\"",
        "abcde12345abcde1234512",
    );
}

#[test]
fn adv38_googleads_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "google-ads-api-developer-token",
        "d\u{0435}v\u{0435}l\u{043e}p\u{0435}r_t\u{043e}k\u{0435}n = \"abcde12345abcde1234512\"",
        "abcde12345abcde1234512",
    );
}
