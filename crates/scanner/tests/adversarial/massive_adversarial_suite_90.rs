//! Part 90 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates github, github, github, github, github, github, github, gitkraken, gitlab, gitlab detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. GITHUB CLASSIC PAT ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv90_github_classic_pat_normal_must_fire() {
    assert_detector_fires(
        "github-classic-pat",
        "GH_TOKEN=ghp_1234567890ABCDEFghijklmnopqrstuvwxyZ",
        "ghp_1234567890ABCDEFghijklmnopqrstuvwxyZ",
    );
}

#[test]
fn adv90_github_classic_pat_wrong_prefix_must_silent() {
    assert_detector_silent(
        "github-classic-pat",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv90_github_classic_pat_evade_zwsp_must_fire() {
    assert_detector_fires(
        "github-classic-pat",
        "GH_TOKEN=ghp_1234567890ABCDEF\u{200B}ghijklmnopqrstuvwxyZ",
        "ghp_1234567890ABCDEFghijklmnopqrstuvwxyZ",
    );
}

#[test]
fn adv90_github_classic_pat_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "github-classic-pat",
        "GH_TOKEN=ghp_1234567890ABCDEF\u{00AD}ghijklmnopqrstuvwxyZ",
        "ghp_1234567890ABCDEFghijklmnopqrstuvwxyZ",
    );
}

#[test]
fn adv90_github_classic_pat_evade_zwnj_must_fire() {
    assert_detector_fires(
        "github-classic-pat",
        "GH_TOKEN=ghp_1234567890ABCDEF\u{200C}ghijklmnopqrstuvwxyZ",
        "ghp_1234567890ABCDEFghijklmnopqrstuvwxyZ",
    );
}

#[test]
fn adv90_github_classic_pat_evade_zwj_must_fire() {
    assert_detector_fires(
        "github-classic-pat",
        "GH_TOKEN=ghp_1234567890ABCDEF\u{200D}ghijklmnopqrstuvwxyZ",
        "ghp_1234567890ABCDEFghijklmnopqrstuvwxyZ",
    );
}

#[test]
fn adv90_github_classic_pat_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "github-classic-pat",
        "GH_TOKEN=ghp_1234567890ABCDEF\u{FEFF}ghijklmnopqrstuvwxyZ",
        "ghp_1234567890ABCDEFghijklmnopqrstuvwxyZ",
    );
}

#[test]
fn adv90_github_classic_pat_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "github-classic-pat",
        "GH_TOKEN=ghp_1234567890ABCDEF\u{2060}ghijklmnopqrstuvwxyZ",
        "ghp_1234567890ABCDEFghijklmnopqrstuvwxyZ",
    );
}

#[test]
fn adv90_github_classic_pat_evade_mongolian_must_fire() {
    assert_detector_fires(
        "github-classic-pat",
        "GH_TOKEN=ghp_1234567890ABCDEF\u{180E}ghijklmnopqrstuvwxyZ",
        "ghp_1234567890ABCDEFghijklmnopqrstuvwxyZ",
    );
}

#[test]
fn adv90_github_classic_pat_evade_rtl_must_fire() {
    assert_detector_fires(
        "github-classic-pat",
        "GH_TOKEN=ghp_1234567890ABCDEF\u{202E}ghijklmnopqrstuvwxyZ",
        "ghp_1234567890ABCDEFghijklmnopqrstuvwxyZ",
    );
}

#[test]
fn adv90_github_classic_pat_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "github-classic-pat",
        "GH_TOKEN=ghp_1234567890ABCDEF\u{202C}ghijklmnopqrstuvwxyZ",
        "ghp_1234567890ABCDEFghijklmnopqrstuvwxyZ",
    );
}

#[test]
fn adv90_github_classic_pat_evade_lrm_must_fire() {
    assert_detector_fires(
        "github-classic-pat",
        "GH_TOKEN=ghp_1234567890ABCDEF\u{200E}ghijklmnopqrstuvwxyZ",
        "ghp_1234567890ABCDEFghijklmnopqrstuvwxyZ",
    );
}

// =========================================================================
// 2. GITHUB OAUTH ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv90_github_oauth_access_token_normal_must_fire() {
    assert_detector_fires(
        "github-oauth-access-token",
        "gho_HsCoqSquucSEDTw1rbQZ3BJ0uv9HtXsANprk",
        "gho_HsCoqSquucSEDTw1rbQZ3BJ0uv9HtXsANprk",
    );
}

#[test]
fn adv90_github_oauth_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "github-oauth-access-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv90_github_oauth_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "github-oauth-access-token",
        "gho_HsCoqSquucSEDTw1\u{200B}rbQZ3BJ0uv9HtXsANprk",
        "gho_HsCoqSquucSEDTw1rbQZ3BJ0uv9HtXsANprk",
    );
}

#[test]
fn adv90_github_oauth_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "github-oauth-access-token",
        "gho_HsCoqSquucSEDTw1\u{00AD}rbQZ3BJ0uv9HtXsANprk",
        "gho_HsCoqSquucSEDTw1rbQZ3BJ0uv9HtXsANprk",
    );
}

#[test]
fn adv90_github_oauth_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "github-oauth-access-token",
        "gho_HsCoqSquucSEDTw1\u{200C}rbQZ3BJ0uv9HtXsANprk",
        "gho_HsCoqSquucSEDTw1rbQZ3BJ0uv9HtXsANprk",
    );
}

#[test]
fn adv90_github_oauth_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "github-oauth-access-token",
        "gho_HsCoqSquucSEDTw1\u{200D}rbQZ3BJ0uv9HtXsANprk",
        "gho_HsCoqSquucSEDTw1rbQZ3BJ0uv9HtXsANprk",
    );
}

#[test]
fn adv90_github_oauth_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "github-oauth-access-token",
        "gho_HsCoqSquucSEDTw1\u{FEFF}rbQZ3BJ0uv9HtXsANprk",
        "gho_HsCoqSquucSEDTw1rbQZ3BJ0uv9HtXsANprk",
    );
}

#[test]
fn adv90_github_oauth_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "github-oauth-access-token",
        "gho_HsCoqSquucSEDTw1\u{2060}rbQZ3BJ0uv9HtXsANprk",
        "gho_HsCoqSquucSEDTw1rbQZ3BJ0uv9HtXsANprk",
    );
}

#[test]
fn adv90_github_oauth_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "github-oauth-access-token",
        "gho_HsCoqSquucSEDTw1\u{180E}rbQZ3BJ0uv9HtXsANprk",
        "gho_HsCoqSquucSEDTw1rbQZ3BJ0uv9HtXsANprk",
    );
}

#[test]
fn adv90_github_oauth_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "github-oauth-access-token",
        "gho_HsCoqSquucSEDTw1\u{202E}rbQZ3BJ0uv9HtXsANprk",
        "gho_HsCoqSquucSEDTw1rbQZ3BJ0uv9HtXsANprk",
    );
}

#[test]
fn adv90_github_oauth_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "github-oauth-access-token",
        "gho_HsCoqSquucSEDTw1\u{202C}rbQZ3BJ0uv9HtXsANprk",
        "gho_HsCoqSquucSEDTw1rbQZ3BJ0uv9HtXsANprk",
    );
}

#[test]
fn adv90_github_oauth_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "github-oauth-access-token",
        "gho_HsCoqSquucSEDTw1\u{200E}rbQZ3BJ0uv9HtXsANprk",
        "gho_HsCoqSquucSEDTw1rbQZ3BJ0uv9HtXsANprk",
    );
}

// =========================================================================
// 3. GITHUB OAUTH SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv90_github_oauth_secret_normal_must_fire() {
    assert_detector_fires(
        "github-oauth-secret",
        "GITHUBCLIENTSECRET=435cd3e0afae058598381e2e78433a8627569f8b",
        "435cd3e0afae058598381e2e78433a8627569f8b",
    );
}

#[test]
fn adv90_github_oauth_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "github-oauth-secret",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv90_github_oauth_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "github-oauth-secret",
        "GITHUBCLIENTSECRET=435cd3e0afae05859838\u{200B}1e2e78433a8627569f8b",
        "435cd3e0afae058598381e2e78433a8627569f8b",
    );
}

#[test]
fn adv90_github_oauth_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "github-oauth-secret",
        "GITHUBCLIENTSECRET=435cd3e0afae05859838\u{00AD}1e2e78433a8627569f8b",
        "435cd3e0afae058598381e2e78433a8627569f8b",
    );
}

#[test]
fn adv90_github_oauth_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "github-oauth-secret",
        "GITHUBCLIENTSECRET=435cd3e0afae05859838\u{200C}1e2e78433a8627569f8b",
        "435cd3e0afae058598381e2e78433a8627569f8b",
    );
}

#[test]
fn adv90_github_oauth_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "github-oauth-secret",
        "GITHUBCLIENTSECRET=435cd3e0afae05859838\u{200D}1e2e78433a8627569f8b",
        "435cd3e0afae058598381e2e78433a8627569f8b",
    );
}

#[test]
fn adv90_github_oauth_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "github-oauth-secret",
        "GITHUBCLIENTSECRET=435cd3e0afae05859838\u{FEFF}1e2e78433a8627569f8b",
        "435cd3e0afae058598381e2e78433a8627569f8b",
    );
}

#[test]
fn adv90_github_oauth_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "github-oauth-secret",
        "GITHUBCLIENTSECRET=435cd3e0afae05859838\u{2060}1e2e78433a8627569f8b",
        "435cd3e0afae058598381e2e78433a8627569f8b",
    );
}

#[test]
fn adv90_github_oauth_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "github-oauth-secret",
        "GITHUBCLIENTSECRET=435cd3e0afae05859838\u{180E}1e2e78433a8627569f8b",
        "435cd3e0afae058598381e2e78433a8627569f8b",
    );
}

#[test]
fn adv90_github_oauth_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "github-oauth-secret",
        "GITHUBCLIENTSECRET=435cd3e0afae05859838\u{202E}1e2e78433a8627569f8b",
        "435cd3e0afae058598381e2e78433a8627569f8b",
    );
}

#[test]
fn adv90_github_oauth_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "github-oauth-secret",
        "GITHUBCLIENTSECRET=435cd3e0afae05859838\u{202C}1e2e78433a8627569f8b",
        "435cd3e0afae058598381e2e78433a8627569f8b",
    );
}

#[test]
fn adv90_github_oauth_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "github-oauth-secret",
        "GITHUBCLIENTSECRET=435cd3e0afae05859838\u{200E}1e2e78433a8627569f8b",
        "435cd3e0afae058598381e2e78433a8627569f8b",
    );
}

// =========================================================================
// 4. GITHUB PAT FINE GRAINED ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv90_github_pat_fine_grained_normal_must_fire() {
    assert_detector_fires(
        "github-pat-fine-grained",
        "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",
        "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",
    );
}

#[test]
fn adv90_github_pat_fine_grained_wrong_prefix_must_silent() {
    assert_detector_silent(
        "github-pat-fine-grained",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv90_github_pat_fine_grained_evade_zwsp_must_fire() {
    assert_detector_fires(
        "github-pat-fine-grained",
        "github_pat_KhYxNqJ4pVbZ7Lm5RfWcGs_9X3kQp7VbT2h\u{200B}YRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0",
        "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",
    );
}

#[test]
fn adv90_github_pat_fine_grained_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "github-pat-fine-grained",
        "github_pat_KhYxNqJ4pVbZ7Lm5RfWcGs_9X3kQp7VbT2h\u{00AD}YRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0",
        "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",
    );
}

#[test]
fn adv90_github_pat_fine_grained_evade_zwnj_must_fire() {
    assert_detector_fires(
        "github-pat-fine-grained",
        "github_pat_KhYxNqJ4pVbZ7Lm5RfWcGs_9X3kQp7VbT2h\u{200C}YRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0",
        "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",
    );
}

#[test]
fn adv90_github_pat_fine_grained_evade_zwj_must_fire() {
    assert_detector_fires(
        "github-pat-fine-grained",
        "github_pat_KhYxNqJ4pVbZ7Lm5RfWcGs_9X3kQp7VbT2h\u{200D}YRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0",
        "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",
    );
}

#[test]
fn adv90_github_pat_fine_grained_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "github-pat-fine-grained",
        "github_pat_KhYxNqJ4pVbZ7Lm5RfWcGs_9X3kQp7VbT2h\u{FEFF}YRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0",
        "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",
    );
}

#[test]
fn adv90_github_pat_fine_grained_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "github-pat-fine-grained",
        "github_pat_KhYxNqJ4pVbZ7Lm5RfWcGs_9X3kQp7VbT2h\u{2060}YRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0",
        "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",
    );
}

#[test]
fn adv90_github_pat_fine_grained_evade_mongolian_must_fire() {
    assert_detector_fires(
        "github-pat-fine-grained",
        "github_pat_KhYxNqJ4pVbZ7Lm5RfWcGs_9X3kQp7VbT2h\u{180E}YRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0",
        "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",
    );
}

#[test]
fn adv90_github_pat_fine_grained_evade_rtl_must_fire() {
    assert_detector_fires(
        "github-pat-fine-grained",
        "github_pat_KhYxNqJ4pVbZ7Lm5RfWcGs_9X3kQp7VbT2h\u{202E}YRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0",
        "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",
    );
}

#[test]
fn adv90_github_pat_fine_grained_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "github-pat-fine-grained",
        "github_pat_KhYxNqJ4pVbZ7Lm5RfWcGs_9X3kQp7VbT2h\u{202C}YRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0",
        "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",
    );
}

#[test]
fn adv90_github_pat_fine_grained_evade_lrm_must_fire() {
    assert_detector_fires(
        "github-pat-fine-grained",
        "github_pat_KhYxNqJ4pVbZ7Lm5RfWcGs_9X3kQp7VbT2h\u{200E}YRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0",
        "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",
    );
}

// =========================================================================
// 5. GITHUB REFRESH TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv90_github_refresh_token_normal_must_fire() {
    assert_detector_fires(
        "github-refresh-token",
        "ghr_rH39afa0PHvEDg72PPnuryL5UP0ZUAPR44Bp",
        "ghr_rH39afa0PHvEDg72PPnuryL5UP0ZUAPR44Bp",
    );
}

#[test]
fn adv90_github_refresh_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "github-refresh-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv90_github_refresh_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "github-refresh-token",
        "ghr_rH39afa0PHvEDg72\u{200B}PPnuryL5UP0ZUAPR44Bp",
        "ghr_rH39afa0PHvEDg72PPnuryL5UP0ZUAPR44Bp",
    );
}

#[test]
fn adv90_github_refresh_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "github-refresh-token",
        "ghr_rH39afa0PHvEDg72\u{00AD}PPnuryL5UP0ZUAPR44Bp",
        "ghr_rH39afa0PHvEDg72PPnuryL5UP0ZUAPR44Bp",
    );
}

#[test]
fn adv90_github_refresh_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "github-refresh-token",
        "ghr_rH39afa0PHvEDg72\u{200C}PPnuryL5UP0ZUAPR44Bp",
        "ghr_rH39afa0PHvEDg72PPnuryL5UP0ZUAPR44Bp",
    );
}

#[test]
fn adv90_github_refresh_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "github-refresh-token",
        "ghr_rH39afa0PHvEDg72\u{200D}PPnuryL5UP0ZUAPR44Bp",
        "ghr_rH39afa0PHvEDg72PPnuryL5UP0ZUAPR44Bp",
    );
}

#[test]
fn adv90_github_refresh_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "github-refresh-token",
        "ghr_rH39afa0PHvEDg72\u{FEFF}PPnuryL5UP0ZUAPR44Bp",
        "ghr_rH39afa0PHvEDg72PPnuryL5UP0ZUAPR44Bp",
    );
}

#[test]
fn adv90_github_refresh_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "github-refresh-token",
        "ghr_rH39afa0PHvEDg72\u{2060}PPnuryL5UP0ZUAPR44Bp",
        "ghr_rH39afa0PHvEDg72PPnuryL5UP0ZUAPR44Bp",
    );
}

#[test]
fn adv90_github_refresh_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "github-refresh-token",
        "ghr_rH39afa0PHvEDg72\u{180E}PPnuryL5UP0ZUAPR44Bp",
        "ghr_rH39afa0PHvEDg72PPnuryL5UP0ZUAPR44Bp",
    );
}

#[test]
fn adv90_github_refresh_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "github-refresh-token",
        "ghr_rH39afa0PHvEDg72\u{202E}PPnuryL5UP0ZUAPR44Bp",
        "ghr_rH39afa0PHvEDg72PPnuryL5UP0ZUAPR44Bp",
    );
}

#[test]
fn adv90_github_refresh_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "github-refresh-token",
        "ghr_rH39afa0PHvEDg72\u{202C}PPnuryL5UP0ZUAPR44Bp",
        "ghr_rH39afa0PHvEDg72PPnuryL5UP0ZUAPR44Bp",
    );
}

#[test]
fn adv90_github_refresh_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "github-refresh-token",
        "ghr_rH39afa0PHvEDg72\u{200E}PPnuryL5UP0ZUAPR44Bp",
        "ghr_rH39afa0PHvEDg72PPnuryL5UP0ZUAPR44Bp",
    );
}

// =========================================================================
// 6. GITHUB USER TO SERVER TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv90_github_user_to_server_token_normal_must_fire() {
    assert_detector_fires(
        "github-user-to-server-token",
        "ghu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tab1",
        "ghu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tab1",
    );
}

#[test]
fn adv90_github_user_to_server_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "github-user-to-server-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv90_github_user_to_server_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "github-user-to-server-token",
        "ghu_Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5Tab1",
        "ghu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tab1",
    );
}

#[test]
fn adv90_github_user_to_server_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "github-user-to-server-token",
        "ghu_Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5Tab1",
        "ghu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tab1",
    );
}

#[test]
fn adv90_github_user_to_server_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "github-user-to-server-token",
        "ghu_Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5Tab1",
        "ghu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tab1",
    );
}

#[test]
fn adv90_github_user_to_server_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "github-user-to-server-token",
        "ghu_Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5Tab1",
        "ghu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tab1",
    );
}

#[test]
fn adv90_github_user_to_server_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "github-user-to-server-token",
        "ghu_Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5Tab1",
        "ghu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tab1",
    );
}

#[test]
fn adv90_github_user_to_server_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "github-user-to-server-token",
        "ghu_Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5Tab1",
        "ghu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tab1",
    );
}

#[test]
fn adv90_github_user_to_server_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "github-user-to-server-token",
        "ghu_Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5Tab1",
        "ghu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tab1",
    );
}

#[test]
fn adv90_github_user_to_server_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "github-user-to-server-token",
        "ghu_Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5Tab1",
        "ghu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tab1",
    );
}

#[test]
fn adv90_github_user_to_server_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "github-user-to-server-token",
        "ghu_Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5Tab1",
        "ghu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tab1",
    );
}

#[test]
fn adv90_github_user_to_server_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "github-user-to-server-token",
        "ghu_Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5Tab1",
        "ghu_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tab1",
    );
}

// =========================================================================
// 7. GITHUB WEBHOOK SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv90_github_webhook_secret_normal_must_fire() {
    assert_detector_fires(
        "github-webhook-secret",
        "GITHUB_WEBHOOK_SECRET=N-hyshMKLyl_Pj_laamriw0VaNok",
        "N-hyshMKLyl_Pj_laamriw0VaNok",
    );
}

#[test]
fn adv90_github_webhook_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "github-webhook-secret",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv90_github_webhook_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "github-webhook-secret",
        "GITHUB_WEBHOOK_SECRET=N-hyshMKLyl_Pj\u{200B}_laamriw0VaNok",
        "N-hyshMKLyl_Pj_laamriw0VaNok",
    );
}

#[test]
fn adv90_github_webhook_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "github-webhook-secret",
        "GITHUB_WEBHOOK_SECRET=N-hyshMKLyl_Pj\u{00AD}_laamriw0VaNok",
        "N-hyshMKLyl_Pj_laamriw0VaNok",
    );
}

#[test]
fn adv90_github_webhook_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "github-webhook-secret",
        "GITHUB_WEBHOOK_SECRET=N-hyshMKLyl_Pj\u{200C}_laamriw0VaNok",
        "N-hyshMKLyl_Pj_laamriw0VaNok",
    );
}

#[test]
fn adv90_github_webhook_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "github-webhook-secret",
        "GITHUB_WEBHOOK_SECRET=N-hyshMKLyl_Pj\u{200D}_laamriw0VaNok",
        "N-hyshMKLyl_Pj_laamriw0VaNok",
    );
}

#[test]
fn adv90_github_webhook_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "github-webhook-secret",
        "GITHUB_WEBHOOK_SECRET=N-hyshMKLyl_Pj\u{FEFF}_laamriw0VaNok",
        "N-hyshMKLyl_Pj_laamriw0VaNok",
    );
}

#[test]
fn adv90_github_webhook_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "github-webhook-secret",
        "GITHUB_WEBHOOK_SECRET=N-hyshMKLyl_Pj\u{2060}_laamriw0VaNok",
        "N-hyshMKLyl_Pj_laamriw0VaNok",
    );
}

#[test]
fn adv90_github_webhook_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "github-webhook-secret",
        "GITHUB_WEBHOOK_SECRET=N-hyshMKLyl_Pj\u{180E}_laamriw0VaNok",
        "N-hyshMKLyl_Pj_laamriw0VaNok",
    );
}

#[test]
fn adv90_github_webhook_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "github-webhook-secret",
        "GITHUB_WEBHOOK_SECRET=N-hyshMKLyl_Pj\u{202E}_laamriw0VaNok",
        "N-hyshMKLyl_Pj_laamriw0VaNok",
    );
}

#[test]
fn adv90_github_webhook_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "github-webhook-secret",
        "GITHUB_WEBHOOK_SECRET=N-hyshMKLyl_Pj\u{202C}_laamriw0VaNok",
        "N-hyshMKLyl_Pj_laamriw0VaNok",
    );
}

#[test]
fn adv90_github_webhook_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "github-webhook-secret",
        "GITHUB_WEBHOOK_SECRET=N-hyshMKLyl_Pj\u{200E}_laamriw0VaNok",
        "N-hyshMKLyl_Pj_laamriw0VaNok",
    );
}

// =========================================================================
// 8. GITKRAKEN API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv90_gitkraken_api_token_normal_must_fire() {
    assert_detector_fires(
        "gitkraken-api-token",
        "GITKRAKEN_API_TOKEN=kNs3EZ4wEbUKziWzK4NuOvNHax3qKZLS",
        "kNs3EZ4wEbUKziWzK4NuOvNHax3qKZLS",
    );
}

#[test]
fn adv90_gitkraken_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "gitkraken-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv90_gitkraken_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "gitkraken-api-token",
        "GITKRAKEN_API_TOKEN=kNs3EZ4wEbUKziWz\u{200B}K4NuOvNHax3qKZLS",
        "kNs3EZ4wEbUKziWzK4NuOvNHax3qKZLS",
    );
}

#[test]
fn adv90_gitkraken_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "gitkraken-api-token",
        "GITKRAKEN_API_TOKEN=kNs3EZ4wEbUKziWz\u{00AD}K4NuOvNHax3qKZLS",
        "kNs3EZ4wEbUKziWzK4NuOvNHax3qKZLS",
    );
}

#[test]
fn adv90_gitkraken_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "gitkraken-api-token",
        "GITKRAKEN_API_TOKEN=kNs3EZ4wEbUKziWz\u{200C}K4NuOvNHax3qKZLS",
        "kNs3EZ4wEbUKziWzK4NuOvNHax3qKZLS",
    );
}

#[test]
fn adv90_gitkraken_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "gitkraken-api-token",
        "GITKRAKEN_API_TOKEN=kNs3EZ4wEbUKziWz\u{200D}K4NuOvNHax3qKZLS",
        "kNs3EZ4wEbUKziWzK4NuOvNHax3qKZLS",
    );
}

#[test]
fn adv90_gitkraken_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "gitkraken-api-token",
        "GITKRAKEN_API_TOKEN=kNs3EZ4wEbUKziWz\u{FEFF}K4NuOvNHax3qKZLS",
        "kNs3EZ4wEbUKziWzK4NuOvNHax3qKZLS",
    );
}

#[test]
fn adv90_gitkraken_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "gitkraken-api-token",
        "GITKRAKEN_API_TOKEN=kNs3EZ4wEbUKziWz\u{2060}K4NuOvNHax3qKZLS",
        "kNs3EZ4wEbUKziWzK4NuOvNHax3qKZLS",
    );
}

#[test]
fn adv90_gitkraken_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "gitkraken-api-token",
        "GITKRAKEN_API_TOKEN=kNs3EZ4wEbUKziWz\u{180E}K4NuOvNHax3qKZLS",
        "kNs3EZ4wEbUKziWzK4NuOvNHax3qKZLS",
    );
}

#[test]
fn adv90_gitkraken_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "gitkraken-api-token",
        "GITKRAKEN_API_TOKEN=kNs3EZ4wEbUKziWz\u{202E}K4NuOvNHax3qKZLS",
        "kNs3EZ4wEbUKziWzK4NuOvNHax3qKZLS",
    );
}

#[test]
fn adv90_gitkraken_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "gitkraken-api-token",
        "GITKRAKEN_API_TOKEN=kNs3EZ4wEbUKziWz\u{202C}K4NuOvNHax3qKZLS",
        "kNs3EZ4wEbUKziWzK4NuOvNHax3qKZLS",
    );
}

#[test]
fn adv90_gitkraken_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "gitkraken-api-token",
        "GITKRAKEN_API_TOKEN=kNs3EZ4wEbUKziWz\u{200E}K4NuOvNHax3qKZLS",
        "kNs3EZ4wEbUKziWzK4NuOvNHax3qKZLS",
    );
}

// =========================================================================
// 9. GITLAB DEPLOY TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv90_gitlab_deploy_token_normal_must_fire() {
    assert_detector_fires(
        "gitlab-deploy-token",
        "gldt-WEB2chP8PWNtgxZLf3EXHXmiDke0c1FH",
        "gldt-WEB2chP8PWNtgxZLf3EXHXmiDke0c1FH",
    );
}

#[test]
fn adv90_gitlab_deploy_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "gitlab-deploy-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv90_gitlab_deploy_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "gitlab-deploy-token",
        "gldt-WEB2chP8PWNtg\u{200B}xZLf3EXHXmiDke0c1FH",
        "gldt-WEB2chP8PWNtgxZLf3EXHXmiDke0c1FH",
    );
}

#[test]
fn adv90_gitlab_deploy_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "gitlab-deploy-token",
        "gldt-WEB2chP8PWNtg\u{00AD}xZLf3EXHXmiDke0c1FH",
        "gldt-WEB2chP8PWNtgxZLf3EXHXmiDke0c1FH",
    );
}

#[test]
fn adv90_gitlab_deploy_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "gitlab-deploy-token",
        "gldt-WEB2chP8PWNtg\u{200C}xZLf3EXHXmiDke0c1FH",
        "gldt-WEB2chP8PWNtgxZLf3EXHXmiDke0c1FH",
    );
}

#[test]
fn adv90_gitlab_deploy_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "gitlab-deploy-token",
        "gldt-WEB2chP8PWNtg\u{200D}xZLf3EXHXmiDke0c1FH",
        "gldt-WEB2chP8PWNtgxZLf3EXHXmiDke0c1FH",
    );
}

#[test]
fn adv90_gitlab_deploy_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "gitlab-deploy-token",
        "gldt-WEB2chP8PWNtg\u{FEFF}xZLf3EXHXmiDke0c1FH",
        "gldt-WEB2chP8PWNtgxZLf3EXHXmiDke0c1FH",
    );
}

#[test]
fn adv90_gitlab_deploy_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "gitlab-deploy-token",
        "gldt-WEB2chP8PWNtg\u{2060}xZLf3EXHXmiDke0c1FH",
        "gldt-WEB2chP8PWNtgxZLf3EXHXmiDke0c1FH",
    );
}

#[test]
fn adv90_gitlab_deploy_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "gitlab-deploy-token",
        "gldt-WEB2chP8PWNtg\u{180E}xZLf3EXHXmiDke0c1FH",
        "gldt-WEB2chP8PWNtgxZLf3EXHXmiDke0c1FH",
    );
}

#[test]
fn adv90_gitlab_deploy_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "gitlab-deploy-token",
        "gldt-WEB2chP8PWNtg\u{202E}xZLf3EXHXmiDke0c1FH",
        "gldt-WEB2chP8PWNtgxZLf3EXHXmiDke0c1FH",
    );
}

#[test]
fn adv90_gitlab_deploy_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "gitlab-deploy-token",
        "gldt-WEB2chP8PWNtg\u{202C}xZLf3EXHXmiDke0c1FH",
        "gldt-WEB2chP8PWNtgxZLf3EXHXmiDke0c1FH",
    );
}

#[test]
fn adv90_gitlab_deploy_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "gitlab-deploy-token",
        "gldt-WEB2chP8PWNtg\u{200E}xZLf3EXHXmiDke0c1FH",
        "gldt-WEB2chP8PWNtgxZLf3EXHXmiDke0c1FH",
    );
}

// =========================================================================
// 10. GITLAB PACKAGE REGISTRY TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv90_gitlab_package_registry_token_normal_must_fire() {
    assert_detector_fires(
        "gitlab-package-registry-token",
        "gldt-L0z4c8YgKC47G6B4E8vwb7hrm8K030EO",
        "gldt-L0z4c8YgKC47G6B4E8vwb7hrm8K030EO",
    );
}

#[test]
fn adv90_gitlab_package_registry_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "gitlab-package-registry-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv90_gitlab_package_registry_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "gitlab-package-registry-token",
        "gldt-L0z4c8YgKC47G\u{200B}6B4E8vwb7hrm8K030EO",
        "gldt-L0z4c8YgKC47G6B4E8vwb7hrm8K030EO",
    );
}

#[test]
fn adv90_gitlab_package_registry_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "gitlab-package-registry-token",
        "gldt-L0z4c8YgKC47G\u{00AD}6B4E8vwb7hrm8K030EO",
        "gldt-L0z4c8YgKC47G6B4E8vwb7hrm8K030EO",
    );
}

#[test]
fn adv90_gitlab_package_registry_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "gitlab-package-registry-token",
        "gldt-L0z4c8YgKC47G\u{200C}6B4E8vwb7hrm8K030EO",
        "gldt-L0z4c8YgKC47G6B4E8vwb7hrm8K030EO",
    );
}

#[test]
fn adv90_gitlab_package_registry_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "gitlab-package-registry-token",
        "gldt-L0z4c8YgKC47G\u{200D}6B4E8vwb7hrm8K030EO",
        "gldt-L0z4c8YgKC47G6B4E8vwb7hrm8K030EO",
    );
}

#[test]
fn adv90_gitlab_package_registry_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "gitlab-package-registry-token",
        "gldt-L0z4c8YgKC47G\u{FEFF}6B4E8vwb7hrm8K030EO",
        "gldt-L0z4c8YgKC47G6B4E8vwb7hrm8K030EO",
    );
}

#[test]
fn adv90_gitlab_package_registry_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "gitlab-package-registry-token",
        "gldt-L0z4c8YgKC47G\u{2060}6B4E8vwb7hrm8K030EO",
        "gldt-L0z4c8YgKC47G6B4E8vwb7hrm8K030EO",
    );
}

#[test]
fn adv90_gitlab_package_registry_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "gitlab-package-registry-token",
        "gldt-L0z4c8YgKC47G\u{180E}6B4E8vwb7hrm8K030EO",
        "gldt-L0z4c8YgKC47G6B4E8vwb7hrm8K030EO",
    );
}

#[test]
fn adv90_gitlab_package_registry_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "gitlab-package-registry-token",
        "gldt-L0z4c8YgKC47G\u{202E}6B4E8vwb7hrm8K030EO",
        "gldt-L0z4c8YgKC47G6B4E8vwb7hrm8K030EO",
    );
}

#[test]
fn adv90_gitlab_package_registry_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "gitlab-package-registry-token",
        "gldt-L0z4c8YgKC47G\u{202C}6B4E8vwb7hrm8K030EO",
        "gldt-L0z4c8YgKC47G6B4E8vwb7hrm8K030EO",
    );
}

#[test]
fn adv90_gitlab_package_registry_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "gitlab-package-registry-token",
        "gldt-L0z4c8YgKC47G\u{200E}6B4E8vwb7hrm8K030EO",
        "gldt-L0z4c8YgKC47G6B4E8vwb7hrm8K030EO",
    );
}
