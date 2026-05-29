//! Part 37 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates genesys, genius, gentrace, geocodio, getresponse, ghost,
//! and github detectors against zero-width spaces, soft hyphens, combining
//! marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. GENESYS CLOUD CLIENT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv37_genesys_normal_must_fire() {
    assert_detector_fires(
        "genesys-cloud-credentials",
        "genesys_client_id = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv37_genesys_wrong_prefix_must_silent() {
    assert_detector_silent(
        "genesys-cloud-credentials",
        "gienesys_client_id = \"00000000-0000-0000-0000-000000000000\"",
    );
}

#[test]
fn adv37_genesys_evade_zwsp_must_fire() {
    assert_detector_fires(
        "genesys-cloud-credentials",
        "genesys_client_id = \"00000000-0000-0000-0000-\u{200B}000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv37_genesys_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "genesys-cloud-credentials",
        "genesys_client_id = \"00000000-0000-0000-0000-0000\u{00AD}00000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv37_genesys_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "genesys-cloud-credentials",
        "g\u{0435}nesys_client_id = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

// =========================================================================
// 2. GENIUS API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv37_genius_normal_must_fire() {
    assert_detector_fires(
        "genius-api-token",
        "genius_token = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv37_genius_wrong_prefix_must_silent() {
    assert_detector_silent(
        "genius-api-token",
        "oenius_token = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv37_genius_evade_zwsp_must_fire() {
    assert_detector_fires(
        "genius-api-token",
        "genius_token = \"abcde12345\u{200B}abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv37_genius_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "genius-api-token",
        "genius_token = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv37_genius_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "genius-api-token",
        "g\u{0435}n\u{0456}us_token = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

// =========================================================================
// 3. GENTRACE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv37_gentrace_normal_must_fire() {
    assert_detector_fires(
        "gentrace-api-key",
        "GENTRACE_API_KEY = \"abcde12345abcde12345abcde12345abcde12345\"",
        "abcde12345abcde12345abcde12345abcde12345",
    );
}

#[test]
fn adv37_gentrace_wrong_prefix_must_silent() {
    assert_detector_silent(
        "gentrace-api-key",
        "HENTRACE_API_KEY = \"abcde12345abcde12345abcde12345abcde12345\"",
    );
}

#[test]
fn adv37_gentrace_evade_zwsp_must_fire() {
    assert_detector_fires(
        "gentrace-api-key",
        "GENTRACE_API_KEY = \"abcde12345abcde12345\u{200B}abcde12345abcde12345\"",
        "abcde12345abcde12345abcde12345abcde12345",
    );
}

#[test]
fn adv37_gentrace_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "gentrace-api-key",
        "GENTRACE_API_KEY = \"abcde12345abcde12345abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345abcde12345abcde12345",
    );
}

#[test]
fn adv37_gentrace_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "gentrace-api-key",
        "G\u{0415}NTRACE_API_KEY = \"abcde12345abcde12345abcde12345abcde12345\"",
        "abcde12345abcde12345abcde12345abcde12345",
    );
}

// =========================================================================
// 4. GEOCODIO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv37_geocodio_normal_must_fire() {
    assert_detector_fires(
        "geocodio-api-key",
        "geocodio_api_key = \"abcde12345abcde12345abcde12345abcde12345\"",
        "abcde12345abcde12345abcde12345abcde12345",
    );
}

#[test]
fn adv37_geocodio_wrong_prefix_must_silent() {
    assert_detector_silent(
        "geocodio-api-key",
        "heocodio_api_key = \"abcde12345abcde12345abcde12345abcde12345\"",
    );
}

#[test]
fn adv37_geocodio_evade_zwsp_must_fire() {
    assert_detector_fires(
        "geocodio-api-key",
        "geocodio_api_key = \"abcde12345abcde12345\u{200B}abcde12345abcde12345\"",
        "abcde12345abcde12345abcde12345abcde12345",
    );
}

#[test]
fn adv37_geocodio_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "geocodio-api-key",
        "geocodio_api_key = \"abcde12345abcde12345abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345abcde12345abcde12345",
    );
}

#[test]
fn adv37_geocodio_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "geocodio-api-key",
        "g\u{0435}\u{043e}c\u{043e}d\u{0456}\u{043e}_api_key = \"abcde12345abcde12345abcde12345abcde12345\"",
        "abcde12345abcde12345abcde12345abcde12345",
    );
}

// =========================================================================
// 5. GETRESPONSE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv37_getresponse_normal_must_fire() {
    assert_detector_fires(
        "getresponse-api-key",
        "getresponse_key: abcde12345abcde12345",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv37_getresponse_wrong_prefix_must_silent() {
    assert_detector_silent(
        "getresponse-api-key",
        "oetresponse_key: abcde12345abcde12345",
    );
}

#[test]
fn adv37_getresponse_evade_zwsp_must_fire() {
    assert_detector_fires(
        "getresponse-api-key",
        "getresponse_key: abcde12345\u{200B}abcde12345",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv37_getresponse_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "getresponse-api-key",
        "getresponse_key: abcde12345abcde\u{00AD}12345",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv37_getresponse_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "getresponse-api-key",
        "g\u{0435}tresp\u{043e}nse_key: abcde12345abcde12345",
        "abcde12345abcde12345",
    );
}

// =========================================================================
// 6. GHOST CMS ADMIN API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv37_ghost_normal_must_fire() {
    assert_detector_fires(
        "ghost-api-key",
        "ghost = \"123456789012345678901234:1234567890123456789012345678901234567890123456789012345678901234\"",
        "123456789012345678901234:1234567890123456789012345678901234567890123456789012345678901234",
    );
}

#[test]
fn adv37_ghost_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ghost-api-key",
        "host = \"123456789012345678901234:1234567890123456789012345678901234567890123456789012345678901234\"",
    );
}

#[test]
fn adv37_ghost_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ghost-api-key",
        "ghost = \"123456789012345678901234:123456789012345678901234\u{200B}5678901234567890123456789012345678901234\"",
        "123456789012345678901234:1234567890123456789012345678901234567890123456789012345678901234",
    );
}

#[test]
fn adv37_ghost_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ghost-api-key",
        "ghost = \"123456789012345678901234:1234567890123456789012345678901234567890123456789012\u{00AD}345678901234\"",
        "123456789012345678901234:1234567890123456789012345678901234567890123456789012345678901234",
    );
}

#[test]
fn adv37_ghost_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "ghost-api-key",
        "gh\u{043e}st = \"123456789012345678901234:1234567890123456789012345678901234567890123456789012345678901234\"",
        "123456789012345678901234:1234567890123456789012345678901234567890123456789012345678901234",
    );
}

// =========================================================================
// 7. GITHUB APP INSTALLATION TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv37_github_app_installation_normal_must_fire() {
    assert_detector_fires(
        "github-app-installation-token",
        "ghs_123456789012345678901234567890123456",
        "ghs_123456789012345678901234567890123456",
    );
}

#[test]
fn adv37_github_app_installation_wrong_prefix_must_silent() {
    assert_detector_silent(
        "github-app-installation-token",
        "hhs_123456789012345678901234567890123456",
    );
}

#[test]
fn adv37_github_app_installation_evade_zwsp_must_fire() {
    assert_detector_fires(
        "github-app-installation-token",
        "ghs_\u{200B}123456789012345678901234567890123456",
        "ghs_123456789012345678901234567890123456",
    );
}

#[test]
fn adv37_github_app_installation_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "github-app-installation-token",
        "ghs_123456789012345678901234567890\u{00AD}123456",
        "ghs_123456789012345678901234567890123456",
    );
}

#[test]
fn adv37_github_app_installation_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "github-app-installation-token",
        "g\u{04BB}s_123456789012345678901234567890123456",
        "ghs_123456789012345678901234567890123456",
    );
}

// =========================================================================
// 8. GITHUB CLASSIC PAT ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv37_github_classic_normal_must_fire() {
    assert_detector_fires(
        "github-classic-pat",
        "ghp_123456789012345678901234567890123456",
        "ghp_123456789012345678901234567890123456",
    );
}

#[test]
fn adv37_github_classic_wrong_prefix_must_silent() {
    assert_detector_silent(
        "github-classic-pat",
        "hhp_123456789012345678901234567890123456",
    );
}

#[test]
fn adv37_github_classic_evade_zwsp_must_fire() {
    assert_detector_fires(
        "github-classic-pat",
        "ghp_\u{200B}123456789012345678901234567890123456",
        "ghp_123456789012345678901234567890123456",
    );
}

#[test]
fn adv37_github_classic_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "github-classic-pat",
        "ghp_123456789012345678901234567890\u{00AD}123456",
        "ghp_123456789012345678901234567890123456",
    );
}

#[test]
fn adv37_github_classic_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "github-classic-pat",
        "g\u{04BB}p_123456789012345678901234567890123456",
        "ghp_123456789012345678901234567890123456",
    );
}

// =========================================================================
// 9. GITHUB OAUTH ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv37_github_oauth_access_normal_must_fire() {
    assert_detector_fires(
        "github-oauth-access-token",
        "gho_123456789012345678901234567890123456",
        "gho_123456789012345678901234567890123456",
    );
}

#[test]
fn adv37_github_oauth_access_wrong_prefix_must_silent() {
    assert_detector_silent(
        "github-oauth-access-token",
        "hho_123456789012345678901234567890123456",
    );
}

#[test]
fn adv37_github_oauth_access_evade_zwsp_must_fire() {
    assert_detector_fires(
        "github-oauth-access-token",
        "gho_\u{200B}123456789012345678901234567890123456",
        "gho_123456789012345678901234567890123456",
    );
}

#[test]
fn adv37_github_oauth_access_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "github-oauth-access-token",
        "gho_123456789012345678901234567890\u{00AD}123456",
        "gho_123456789012345678901234567890123456",
    );
}

#[test]
fn adv37_github_oauth_access_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "github-oauth-access-token",
        "g\u{04BB}o_123456789012345678901234567890123456",
        "gho_123456789012345678901234567890123456",
    );
}

// =========================================================================
// 10. GITHUB OAUTH CLIENT SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv37_github_oauth_secret_normal_must_fire() {
    assert_detector_fires(
        "github-oauth-secret",
        "github_client_secret = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    );
}

#[test]
fn adv37_github_oauth_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "github-oauth-secret",
        "hithub_client_secret = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\"",
    );
}

#[test]
fn adv37_github_oauth_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "github-oauth-secret",
        "github_client_secret = \"a1b2c3d4e5f6a1b2c3\u{200B}d4e5f6a1b2c3d4e5f6a1b2\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    );
}

#[test]
fn adv37_github_oauth_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "github-oauth-secret",
        "github_client_secret = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5\u{00AD}f6a1b2\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    );
}

#[test]
fn adv37_github_oauth_secret_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "github-oauth-secret",
        "g\u{0456}thub_cl\u{0456}\u{0435}nt_s\u{0435}cr\u{0435}t = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    );
}

// =========================================================================
// 11. GITHUB FINE-GRAINED PAT ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv37_github_pat_normal_must_fire() {
    assert_detector_fires(
        "github-pat-fine-grained",
        "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",
        "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",
    );
}

#[test]
fn adv37_github_pat_wrong_prefix_must_silent() {
    assert_detector_silent(
        "github-pat-fine-grained",
        "hithub_pat_KhYxNqJ4pVbZ7Lm5RfWcGs_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0",
    );
}

#[test]
fn adv37_github_pat_evade_zwsp_must_fire() {
    assert_detector_fires(
        "github-pat-fine-grained",
        "github_pat_KhYxNqJ4pVbZ7Lm5RfWcGs_9X3kQp7VbT2h\u{200B}YRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0",
        "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",
    );
}

#[test]
fn adv37_github_pat_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "github-pat-fine-grained",
        "github_pat_KhYxNqJ4pVbZ7Lm5RfWcGs_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIo\u{00AD}X0",
        "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",
    );
}

#[test]
fn adv37_github_pat_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "github-pat-fine-grained",
        "g\u{0456}thub_pat_KhYxNqJ4pVbZ7Lm5RfWcGs_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0",
        "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",
    );
}

// =========================================================================
// 12. GITHUB REFRESH TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv37_github_refresh_normal_must_fire() {
    assert_detector_fires(
        "github-refresh-token",
        "ghr_123456789012345678901234567890123456",
        "ghr_123456789012345678901234567890123456",
    );
}

#[test]
fn adv37_github_refresh_wrong_prefix_must_silent() {
    assert_detector_silent(
        "github-refresh-token",
        "hhr_123456789012345678901234567890123456",
    );
}

#[test]
fn adv37_github_refresh_evade_zwsp_must_fire() {
    assert_detector_fires(
        "github-refresh-token",
        "ghr_\u{200B}123456789012345678901234567890123456",
        "ghr_123456789012345678901234567890123456",
    );
}

#[test]
fn adv37_github_refresh_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "github-refresh-token",
        "ghr_123456789012345678901234567890\u{00AD}123456",
        "ghr_123456789012345678901234567890123456",
    );
}

#[test]
fn adv37_github_refresh_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "github-refresh-token",
        "g\u{04BB}r_123456789012345678901234567890123456",
        "ghr_123456789012345678901234567890123456",
    );
}
