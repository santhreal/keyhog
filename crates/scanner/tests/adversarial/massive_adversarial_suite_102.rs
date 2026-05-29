//! Part 102 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates libsql, lightstep, linear, linear, linode, litellm, livechat, livekit, lob, locationiq detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. LIBSQL CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv102_libsql_credentials_normal_must_fire() {
    assert_detector_fires(
        "libsql-credentials",
        "libsql://78167825",
        "78167825",
    );
}

#[test]
fn adv102_libsql_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "libsql-credentials",
        "dummy_prefix_0://xxxxxxxx",
    );
}

#[test]
fn adv102_libsql_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "libsql-credentials",
        "libsql://7816\u{200B}7825",
        "78167825",
    );
}

#[test]
fn adv102_libsql_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "libsql-credentials",
        "libsql://7816\u{00AD}7825",
        "78167825",
    );
}

#[test]
fn adv102_libsql_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "libsql-credentials",
        "libsql://7816\u{200C}7825",
        "78167825",
    );
}

#[test]
fn adv102_libsql_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "libsql-credentials",
        "libsql://7816\u{200D}7825",
        "78167825",
    );
}

#[test]
fn adv102_libsql_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "libsql-credentials",
        "libsql://7816\u{FEFF}7825",
        "78167825",
    );
}

#[test]
fn adv102_libsql_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "libsql-credentials",
        "libsql://7816\u{2060}7825",
        "78167825",
    );
}

#[test]
fn adv102_libsql_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "libsql-credentials",
        "libsql://7816\u{180E}7825",
        "78167825",
    );
}

#[test]
fn adv102_libsql_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "libsql-credentials",
        "libsql://7816\u{202E}7825",
        "78167825",
    );
}

#[test]
fn adv102_libsql_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "libsql-credentials",
        "libsql://7816\u{202C}7825",
        "78167825",
    );
}

#[test]
fn adv102_libsql_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "libsql-credentials",
        "libsql://7816\u{200E}7825",
        "78167825",
    );
}

// =========================================================================
// 2. LIGHTSTEP ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv102_lightstep_access_token_normal_must_fire() {
    assert_detector_fires(
        "lightstep-access-token",
        "LIGHTSTEP_ACCESS_TOKEN=745f2198109b6eed5a2be2ab94a89e45",
        "745f2198109b6eed5a2be2ab94a89e45",
    );
}

#[test]
fn adv102_lightstep_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "lightstep-access-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv102_lightstep_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "lightstep-access-token",
        "LIGHTSTEP_ACCESS_TOKEN=745f2198109b6eed\u{200B}5a2be2ab94a89e45",
        "745f2198109b6eed5a2be2ab94a89e45",
    );
}

#[test]
fn adv102_lightstep_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "lightstep-access-token",
        "LIGHTSTEP_ACCESS_TOKEN=745f2198109b6eed\u{00AD}5a2be2ab94a89e45",
        "745f2198109b6eed5a2be2ab94a89e45",
    );
}

#[test]
fn adv102_lightstep_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "lightstep-access-token",
        "LIGHTSTEP_ACCESS_TOKEN=745f2198109b6eed\u{200C}5a2be2ab94a89e45",
        "745f2198109b6eed5a2be2ab94a89e45",
    );
}

#[test]
fn adv102_lightstep_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "lightstep-access-token",
        "LIGHTSTEP_ACCESS_TOKEN=745f2198109b6eed\u{200D}5a2be2ab94a89e45",
        "745f2198109b6eed5a2be2ab94a89e45",
    );
}

#[test]
fn adv102_lightstep_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "lightstep-access-token",
        "LIGHTSTEP_ACCESS_TOKEN=745f2198109b6eed\u{FEFF}5a2be2ab94a89e45",
        "745f2198109b6eed5a2be2ab94a89e45",
    );
}

#[test]
fn adv102_lightstep_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "lightstep-access-token",
        "LIGHTSTEP_ACCESS_TOKEN=745f2198109b6eed\u{2060}5a2be2ab94a89e45",
        "745f2198109b6eed5a2be2ab94a89e45",
    );
}

#[test]
fn adv102_lightstep_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "lightstep-access-token",
        "LIGHTSTEP_ACCESS_TOKEN=745f2198109b6eed\u{180E}5a2be2ab94a89e45",
        "745f2198109b6eed5a2be2ab94a89e45",
    );
}

#[test]
fn adv102_lightstep_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "lightstep-access-token",
        "LIGHTSTEP_ACCESS_TOKEN=745f2198109b6eed\u{202E}5a2be2ab94a89e45",
        "745f2198109b6eed5a2be2ab94a89e45",
    );
}

#[test]
fn adv102_lightstep_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "lightstep-access-token",
        "LIGHTSTEP_ACCESS_TOKEN=745f2198109b6eed\u{202C}5a2be2ab94a89e45",
        "745f2198109b6eed5a2be2ab94a89e45",
    );
}

#[test]
fn adv102_lightstep_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "lightstep-access-token",
        "LIGHTSTEP_ACCESS_TOKEN=745f2198109b6eed\u{200E}5a2be2ab94a89e45",
        "745f2198109b6eed5a2be2ab94a89e45",
    );
}

// =========================================================================
// 3. LINEAR API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv102_linear_api_key_normal_must_fire() {
    assert_detector_fires(
        "linear-api-key",
        "lin_api_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKq",
        "lin_api_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKq",
    );
}

#[test]
fn adv102_linear_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "linear-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv102_linear_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "linear-api-key",
        "lin_api_9X3kQp7VbT2hYRzN\u{200B}cMfWj4DgEsLuHaIoBnVkPxKq",
        "lin_api_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKq",
    );
}

#[test]
fn adv102_linear_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "linear-api-key",
        "lin_api_9X3kQp7VbT2hYRzN\u{00AD}cMfWj4DgEsLuHaIoBnVkPxKq",
        "lin_api_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKq",
    );
}

#[test]
fn adv102_linear_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "linear-api-key",
        "lin_api_9X3kQp7VbT2hYRzN\u{200C}cMfWj4DgEsLuHaIoBnVkPxKq",
        "lin_api_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKq",
    );
}

#[test]
fn adv102_linear_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "linear-api-key",
        "lin_api_9X3kQp7VbT2hYRzN\u{200D}cMfWj4DgEsLuHaIoBnVkPxKq",
        "lin_api_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKq",
    );
}

#[test]
fn adv102_linear_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "linear-api-key",
        "lin_api_9X3kQp7VbT2hYRzN\u{FEFF}cMfWj4DgEsLuHaIoBnVkPxKq",
        "lin_api_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKq",
    );
}

#[test]
fn adv102_linear_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "linear-api-key",
        "lin_api_9X3kQp7VbT2hYRzN\u{2060}cMfWj4DgEsLuHaIoBnVkPxKq",
        "lin_api_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKq",
    );
}

#[test]
fn adv102_linear_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "linear-api-key",
        "lin_api_9X3kQp7VbT2hYRzN\u{180E}cMfWj4DgEsLuHaIoBnVkPxKq",
        "lin_api_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKq",
    );
}

#[test]
fn adv102_linear_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "linear-api-key",
        "lin_api_9X3kQp7VbT2hYRzN\u{202E}cMfWj4DgEsLuHaIoBnVkPxKq",
        "lin_api_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKq",
    );
}

#[test]
fn adv102_linear_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "linear-api-key",
        "lin_api_9X3kQp7VbT2hYRzN\u{202C}cMfWj4DgEsLuHaIoBnVkPxKq",
        "lin_api_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKq",
    );
}

#[test]
fn adv102_linear_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "linear-api-key",
        "lin_api_9X3kQp7VbT2hYRzN\u{200E}cMfWj4DgEsLuHaIoBnVkPxKq",
        "lin_api_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKq",
    );
}

// =========================================================================
// 4. LINEAR OAUTH SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv102_linear_oauth_secret_normal_must_fire() {
    assert_detector_fires(
        "linear-oauth-secret",
        "LINEAR_OAUTH_SECRET=k8ecqBMUCY93S7rqWkKXdzUVi84vVIO55BCf5HL9",
        "k8ecqBMUCY93S7rqWkKXdzUVi84vVIO55BCf5HL9",
    );
}

#[test]
fn adv102_linear_oauth_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "linear-oauth-secret",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv102_linear_oauth_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "linear-oauth-secret",
        "LINEAR_OAUTH_SECRET=k8ecqBMUCY93S7rqWkKX\u{200B}dzUVi84vVIO55BCf5HL9",
        "k8ecqBMUCY93S7rqWkKXdzUVi84vVIO55BCf5HL9",
    );
}

#[test]
fn adv102_linear_oauth_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "linear-oauth-secret",
        "LINEAR_OAUTH_SECRET=k8ecqBMUCY93S7rqWkKX\u{00AD}dzUVi84vVIO55BCf5HL9",
        "k8ecqBMUCY93S7rqWkKXdzUVi84vVIO55BCf5HL9",
    );
}

#[test]
fn adv102_linear_oauth_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "linear-oauth-secret",
        "LINEAR_OAUTH_SECRET=k8ecqBMUCY93S7rqWkKX\u{200C}dzUVi84vVIO55BCf5HL9",
        "k8ecqBMUCY93S7rqWkKXdzUVi84vVIO55BCf5HL9",
    );
}

#[test]
fn adv102_linear_oauth_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "linear-oauth-secret",
        "LINEAR_OAUTH_SECRET=k8ecqBMUCY93S7rqWkKX\u{200D}dzUVi84vVIO55BCf5HL9",
        "k8ecqBMUCY93S7rqWkKXdzUVi84vVIO55BCf5HL9",
    );
}

#[test]
fn adv102_linear_oauth_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "linear-oauth-secret",
        "LINEAR_OAUTH_SECRET=k8ecqBMUCY93S7rqWkKX\u{FEFF}dzUVi84vVIO55BCf5HL9",
        "k8ecqBMUCY93S7rqWkKXdzUVi84vVIO55BCf5HL9",
    );
}

#[test]
fn adv102_linear_oauth_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "linear-oauth-secret",
        "LINEAR_OAUTH_SECRET=k8ecqBMUCY93S7rqWkKX\u{2060}dzUVi84vVIO55BCf5HL9",
        "k8ecqBMUCY93S7rqWkKXdzUVi84vVIO55BCf5HL9",
    );
}

#[test]
fn adv102_linear_oauth_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "linear-oauth-secret",
        "LINEAR_OAUTH_SECRET=k8ecqBMUCY93S7rqWkKX\u{180E}dzUVi84vVIO55BCf5HL9",
        "k8ecqBMUCY93S7rqWkKXdzUVi84vVIO55BCf5HL9",
    );
}

#[test]
fn adv102_linear_oauth_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "linear-oauth-secret",
        "LINEAR_OAUTH_SECRET=k8ecqBMUCY93S7rqWkKX\u{202E}dzUVi84vVIO55BCf5HL9",
        "k8ecqBMUCY93S7rqWkKXdzUVi84vVIO55BCf5HL9",
    );
}

#[test]
fn adv102_linear_oauth_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "linear-oauth-secret",
        "LINEAR_OAUTH_SECRET=k8ecqBMUCY93S7rqWkKX\u{202C}dzUVi84vVIO55BCf5HL9",
        "k8ecqBMUCY93S7rqWkKXdzUVi84vVIO55BCf5HL9",
    );
}

#[test]
fn adv102_linear_oauth_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "linear-oauth-secret",
        "LINEAR_OAUTH_SECRET=k8ecqBMUCY93S7rqWkKX\u{200E}dzUVi84vVIO55BCf5HL9",
        "k8ecqBMUCY93S7rqWkKXdzUVi84vVIO55BCf5HL9",
    );
}

// =========================================================================
// 5. LINODE PAT ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv102_linode_pat_normal_must_fire() {
    assert_detector_fires(
        "linode-pat",
        "LINODE_TOKEN=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv102_linode_pat_wrong_prefix_must_silent() {
    assert_detector_silent(
        "linode-pat",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv102_linode_pat_evade_zwsp_must_fire() {
    assert_detector_fires(
        "linode-pat",
        "LINODE_TOKEN=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200B}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv102_linode_pat_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "linode-pat",
        "LINODE_TOKEN=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{00AD}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv102_linode_pat_evade_zwnj_must_fire() {
    assert_detector_fires(
        "linode-pat",
        "LINODE_TOKEN=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200C}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv102_linode_pat_evade_zwj_must_fire() {
    assert_detector_fires(
        "linode-pat",
        "LINODE_TOKEN=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200D}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv102_linode_pat_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "linode-pat",
        "LINODE_TOKEN=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{FEFF}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv102_linode_pat_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "linode-pat",
        "LINODE_TOKEN=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{2060}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv102_linode_pat_evade_mongolian_must_fire() {
    assert_detector_fires(
        "linode-pat",
        "LINODE_TOKEN=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{180E}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv102_linode_pat_evade_rtl_must_fire() {
    assert_detector_fires(
        "linode-pat",
        "LINODE_TOKEN=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{202E}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv102_linode_pat_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "linode-pat",
        "LINODE_TOKEN=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{202C}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv102_linode_pat_evade_lrm_must_fire() {
    assert_detector_fires(
        "linode-pat",
        "LINODE_TOKEN=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200E}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 6. LITELLM CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv102_litellm_credentials_normal_must_fire() {
    assert_detector_fires(
        "litellm-credentials",
        "LITELLM_MASTER_KEY=sk-U322CNKR7TDP7rs3NNuI",
        "sk-U322CNKR7TDP7rs3NNuI",
    );
}

#[test]
fn adv102_litellm_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "litellm-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv102_litellm_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "litellm-credentials",
        "LITELLM_MASTER_KEY=sk-U322CNKR\u{200B}7TDP7rs3NNuI",
        "sk-U322CNKR7TDP7rs3NNuI",
    );
}

#[test]
fn adv102_litellm_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "litellm-credentials",
        "LITELLM_MASTER_KEY=sk-U322CNKR\u{00AD}7TDP7rs3NNuI",
        "sk-U322CNKR7TDP7rs3NNuI",
    );
}

#[test]
fn adv102_litellm_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "litellm-credentials",
        "LITELLM_MASTER_KEY=sk-U322CNKR\u{200C}7TDP7rs3NNuI",
        "sk-U322CNKR7TDP7rs3NNuI",
    );
}

#[test]
fn adv102_litellm_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "litellm-credentials",
        "LITELLM_MASTER_KEY=sk-U322CNKR\u{200D}7TDP7rs3NNuI",
        "sk-U322CNKR7TDP7rs3NNuI",
    );
}

#[test]
fn adv102_litellm_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "litellm-credentials",
        "LITELLM_MASTER_KEY=sk-U322CNKR\u{FEFF}7TDP7rs3NNuI",
        "sk-U322CNKR7TDP7rs3NNuI",
    );
}

#[test]
fn adv102_litellm_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "litellm-credentials",
        "LITELLM_MASTER_KEY=sk-U322CNKR\u{2060}7TDP7rs3NNuI",
        "sk-U322CNKR7TDP7rs3NNuI",
    );
}

#[test]
fn adv102_litellm_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "litellm-credentials",
        "LITELLM_MASTER_KEY=sk-U322CNKR\u{180E}7TDP7rs3NNuI",
        "sk-U322CNKR7TDP7rs3NNuI",
    );
}

#[test]
fn adv102_litellm_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "litellm-credentials",
        "LITELLM_MASTER_KEY=sk-U322CNKR\u{202E}7TDP7rs3NNuI",
        "sk-U322CNKR7TDP7rs3NNuI",
    );
}

#[test]
fn adv102_litellm_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "litellm-credentials",
        "LITELLM_MASTER_KEY=sk-U322CNKR\u{202C}7TDP7rs3NNuI",
        "sk-U322CNKR7TDP7rs3NNuI",
    );
}

#[test]
fn adv102_litellm_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "litellm-credentials",
        "LITELLM_MASTER_KEY=sk-U322CNKR\u{200E}7TDP7rs3NNuI",
        "sk-U322CNKR7TDP7rs3NNuI",
    );
}

// =========================================================================
// 7. LIVECHAT API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv102_livechat_api_token_normal_must_fire() {
    assert_detector_fires(
        "livechat-api-token",
        "dal:8dMWEafjh7Z2gnRpR2rJDIdfPoMOAXsw",
        "dal:8dMWEafjh7Z2gnRpR2rJDIdfPoMOAXsw",
    );
}

#[test]
fn adv102_livechat_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "livechat-api-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv102_livechat_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "livechat-api-token",
        "dal:8dMWEafjh7Z2gn\u{200B}RpR2rJDIdfPoMOAXsw",
        "dal:8dMWEafjh7Z2gnRpR2rJDIdfPoMOAXsw",
    );
}

#[test]
fn adv102_livechat_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "livechat-api-token",
        "dal:8dMWEafjh7Z2gn\u{00AD}RpR2rJDIdfPoMOAXsw",
        "dal:8dMWEafjh7Z2gnRpR2rJDIdfPoMOAXsw",
    );
}

#[test]
fn adv102_livechat_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "livechat-api-token",
        "dal:8dMWEafjh7Z2gn\u{200C}RpR2rJDIdfPoMOAXsw",
        "dal:8dMWEafjh7Z2gnRpR2rJDIdfPoMOAXsw",
    );
}

#[test]
fn adv102_livechat_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "livechat-api-token",
        "dal:8dMWEafjh7Z2gn\u{200D}RpR2rJDIdfPoMOAXsw",
        "dal:8dMWEafjh7Z2gnRpR2rJDIdfPoMOAXsw",
    );
}

#[test]
fn adv102_livechat_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "livechat-api-token",
        "dal:8dMWEafjh7Z2gn\u{FEFF}RpR2rJDIdfPoMOAXsw",
        "dal:8dMWEafjh7Z2gnRpR2rJDIdfPoMOAXsw",
    );
}

#[test]
fn adv102_livechat_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "livechat-api-token",
        "dal:8dMWEafjh7Z2gn\u{2060}RpR2rJDIdfPoMOAXsw",
        "dal:8dMWEafjh7Z2gnRpR2rJDIdfPoMOAXsw",
    );
}

#[test]
fn adv102_livechat_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "livechat-api-token",
        "dal:8dMWEafjh7Z2gn\u{180E}RpR2rJDIdfPoMOAXsw",
        "dal:8dMWEafjh7Z2gnRpR2rJDIdfPoMOAXsw",
    );
}

#[test]
fn adv102_livechat_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "livechat-api-token",
        "dal:8dMWEafjh7Z2gn\u{202E}RpR2rJDIdfPoMOAXsw",
        "dal:8dMWEafjh7Z2gnRpR2rJDIdfPoMOAXsw",
    );
}

#[test]
fn adv102_livechat_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "livechat-api-token",
        "dal:8dMWEafjh7Z2gn\u{202C}RpR2rJDIdfPoMOAXsw",
        "dal:8dMWEafjh7Z2gnRpR2rJDIdfPoMOAXsw",
    );
}

#[test]
fn adv102_livechat_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "livechat-api-token",
        "dal:8dMWEafjh7Z2gn\u{200E}RpR2rJDIdfPoMOAXsw",
        "dal:8dMWEafjh7Z2gnRpR2rJDIdfPoMOAXsw",
    );
}

// =========================================================================
// 8. LIVEKIT API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv102_livekit_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "livekit-api-credentials",
        "LIVEKIT_API_KEY=APIcXfzjJ8K",
        "APIcXfzjJ8K",
    );
}

#[test]
fn adv102_livekit_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "livekit-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxx",
    );
}

#[test]
fn adv102_livekit_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "livekit-api-credentials",
        "LIVEKIT_API_KEY=APIcX\u{200B}fzjJ8K",
        "APIcXfzjJ8K",
    );
}

#[test]
fn adv102_livekit_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "livekit-api-credentials",
        "LIVEKIT_API_KEY=APIcX\u{00AD}fzjJ8K",
        "APIcXfzjJ8K",
    );
}

#[test]
fn adv102_livekit_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "livekit-api-credentials",
        "LIVEKIT_API_KEY=APIcX\u{200C}fzjJ8K",
        "APIcXfzjJ8K",
    );
}

#[test]
fn adv102_livekit_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "livekit-api-credentials",
        "LIVEKIT_API_KEY=APIcX\u{200D}fzjJ8K",
        "APIcXfzjJ8K",
    );
}

#[test]
fn adv102_livekit_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "livekit-api-credentials",
        "LIVEKIT_API_KEY=APIcX\u{FEFF}fzjJ8K",
        "APIcXfzjJ8K",
    );
}

#[test]
fn adv102_livekit_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "livekit-api-credentials",
        "LIVEKIT_API_KEY=APIcX\u{2060}fzjJ8K",
        "APIcXfzjJ8K",
    );
}

#[test]
fn adv102_livekit_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "livekit-api-credentials",
        "LIVEKIT_API_KEY=APIcX\u{180E}fzjJ8K",
        "APIcXfzjJ8K",
    );
}

#[test]
fn adv102_livekit_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "livekit-api-credentials",
        "LIVEKIT_API_KEY=APIcX\u{202E}fzjJ8K",
        "APIcXfzjJ8K",
    );
}

#[test]
fn adv102_livekit_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "livekit-api-credentials",
        "LIVEKIT_API_KEY=APIcX\u{202C}fzjJ8K",
        "APIcXfzjJ8K",
    );
}

#[test]
fn adv102_livekit_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "livekit-api-credentials",
        "LIVEKIT_API_KEY=APIcX\u{200E}fzjJ8K",
        "APIcXfzjJ8K",
    );
}

// =========================================================================
// 9. LOB API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv102_lob_api_key_normal_must_fire() {
    assert_detector_fires(
        "lob-api-key",
        "live_56532f88eee3578779ffe1719b51efa2ae55222e",
        "live_56532f88eee3578779ffe1719b51efa2ae55222e",
    );
}

#[test]
fn adv102_lob_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "lob-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv102_lob_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "lob-api-key",
        "live_56532f88eee357877\u{200B}9ffe1719b51efa2ae55222e",
        "live_56532f88eee3578779ffe1719b51efa2ae55222e",
    );
}

#[test]
fn adv102_lob_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "lob-api-key",
        "live_56532f88eee357877\u{00AD}9ffe1719b51efa2ae55222e",
        "live_56532f88eee3578779ffe1719b51efa2ae55222e",
    );
}

#[test]
fn adv102_lob_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "lob-api-key",
        "live_56532f88eee357877\u{200C}9ffe1719b51efa2ae55222e",
        "live_56532f88eee3578779ffe1719b51efa2ae55222e",
    );
}

#[test]
fn adv102_lob_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "lob-api-key",
        "live_56532f88eee357877\u{200D}9ffe1719b51efa2ae55222e",
        "live_56532f88eee3578779ffe1719b51efa2ae55222e",
    );
}

#[test]
fn adv102_lob_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "lob-api-key",
        "live_56532f88eee357877\u{FEFF}9ffe1719b51efa2ae55222e",
        "live_56532f88eee3578779ffe1719b51efa2ae55222e",
    );
}

#[test]
fn adv102_lob_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "lob-api-key",
        "live_56532f88eee357877\u{2060}9ffe1719b51efa2ae55222e",
        "live_56532f88eee3578779ffe1719b51efa2ae55222e",
    );
}

#[test]
fn adv102_lob_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "lob-api-key",
        "live_56532f88eee357877\u{180E}9ffe1719b51efa2ae55222e",
        "live_56532f88eee3578779ffe1719b51efa2ae55222e",
    );
}

#[test]
fn adv102_lob_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "lob-api-key",
        "live_56532f88eee357877\u{202E}9ffe1719b51efa2ae55222e",
        "live_56532f88eee3578779ffe1719b51efa2ae55222e",
    );
}

#[test]
fn adv102_lob_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "lob-api-key",
        "live_56532f88eee357877\u{202C}9ffe1719b51efa2ae55222e",
        "live_56532f88eee3578779ffe1719b51efa2ae55222e",
    );
}

#[test]
fn adv102_lob_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "lob-api-key",
        "live_56532f88eee357877\u{200E}9ffe1719b51efa2ae55222e",
        "live_56532f88eee3578779ffe1719b51efa2ae55222e",
    );
}

// =========================================================================
// 10. LOCATIONIQ API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv102_locationiq_api_token_normal_must_fire() {
    assert_detector_fires(
        "locationiq-api-token",
        "LOCATIONIQ_API_KEY=pk.b02a70db24b788f217af47231d91e27e96c388b92f008b39c24addc0706",
        "pk.b02a70db24b788f217af47231d91e27e96c388b92f008b39c24addc0706",
    );
}

#[test]
fn adv102_locationiq_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "locationiq-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv102_locationiq_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "locationiq-api-token",
        "LOCATIONIQ_API_KEY=pk.b02a70db24b788f217af47231d91\u{200B}e27e96c388b92f008b39c24addc0706",
        "pk.b02a70db24b788f217af47231d91e27e96c388b92f008b39c24addc0706",
    );
}

#[test]
fn adv102_locationiq_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "locationiq-api-token",
        "LOCATIONIQ_API_KEY=pk.b02a70db24b788f217af47231d91\u{00AD}e27e96c388b92f008b39c24addc0706",
        "pk.b02a70db24b788f217af47231d91e27e96c388b92f008b39c24addc0706",
    );
}

#[test]
fn adv102_locationiq_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "locationiq-api-token",
        "LOCATIONIQ_API_KEY=pk.b02a70db24b788f217af47231d91\u{200C}e27e96c388b92f008b39c24addc0706",
        "pk.b02a70db24b788f217af47231d91e27e96c388b92f008b39c24addc0706",
    );
}

#[test]
fn adv102_locationiq_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "locationiq-api-token",
        "LOCATIONIQ_API_KEY=pk.b02a70db24b788f217af47231d91\u{200D}e27e96c388b92f008b39c24addc0706",
        "pk.b02a70db24b788f217af47231d91e27e96c388b92f008b39c24addc0706",
    );
}

#[test]
fn adv102_locationiq_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "locationiq-api-token",
        "LOCATIONIQ_API_KEY=pk.b02a70db24b788f217af47231d91\u{FEFF}e27e96c388b92f008b39c24addc0706",
        "pk.b02a70db24b788f217af47231d91e27e96c388b92f008b39c24addc0706",
    );
}

#[test]
fn adv102_locationiq_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "locationiq-api-token",
        "LOCATIONIQ_API_KEY=pk.b02a70db24b788f217af47231d91\u{2060}e27e96c388b92f008b39c24addc0706",
        "pk.b02a70db24b788f217af47231d91e27e96c388b92f008b39c24addc0706",
    );
}

#[test]
fn adv102_locationiq_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "locationiq-api-token",
        "LOCATIONIQ_API_KEY=pk.b02a70db24b788f217af47231d91\u{180E}e27e96c388b92f008b39c24addc0706",
        "pk.b02a70db24b788f217af47231d91e27e96c388b92f008b39c24addc0706",
    );
}

#[test]
fn adv102_locationiq_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "locationiq-api-token",
        "LOCATIONIQ_API_KEY=pk.b02a70db24b788f217af47231d91\u{202E}e27e96c388b92f008b39c24addc0706",
        "pk.b02a70db24b788f217af47231d91e27e96c388b92f008b39c24addc0706",
    );
}

#[test]
fn adv102_locationiq_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "locationiq-api-token",
        "LOCATIONIQ_API_KEY=pk.b02a70db24b788f217af47231d91\u{202C}e27e96c388b92f008b39c24addc0706",
        "pk.b02a70db24b788f217af47231d91e27e96c388b92f008b39c24addc0706",
    );
}

#[test]
fn adv102_locationiq_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "locationiq-api-token",
        "LOCATIONIQ_API_KEY=pk.b02a70db24b788f217af47231d91\u{200E}e27e96c388b92f008b39c24addc0706",
        "pk.b02a70db24b788f217af47231d91e27e96c388b92f008b39c24addc0706",
    );
}


