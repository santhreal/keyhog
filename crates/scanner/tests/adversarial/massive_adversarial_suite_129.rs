//! Part 129 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates snyk, socure, solana, sonarcloud, sonarqube, soracom, sourcetree, south, sovos, spacelift detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. SNYK API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv129_snyk_api_token_normal_must_fire() {
    assert_detector_fires(
        "snyk-api-token",
        "SNYK_TOKEN=01234567-89ab-cdef-0123-456789abcdef",
        "01234567-89ab-cdef-0123-456789abcdef",
    );
}

#[test]
fn adv129_snyk_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "snyk-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv129_snyk_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "snyk-api-token",
        "SNYK_TOKEN=01234567-89ab-cdef\u{200B}-0123-456789abcdef",
        "01234567-89ab-cdef-0123-456789abcdef",
    );
}

#[test]
fn adv129_snyk_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "snyk-api-token",
        "SNYK_TOKEN=01234567-89ab-cdef\u{00AD}-0123-456789abcdef",
        "01234567-89ab-cdef-0123-456789abcdef",
    );
}

#[test]
fn adv129_snyk_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "snyk-api-token",
        "SNYK_TOKEN=01234567-89ab-cdef\u{200C}-0123-456789abcdef",
        "01234567-89ab-cdef-0123-456789abcdef",
    );
}

#[test]
fn adv129_snyk_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "snyk-api-token",
        "SNYK_TOKEN=01234567-89ab-cdef\u{200D}-0123-456789abcdef",
        "01234567-89ab-cdef-0123-456789abcdef",
    );
}

#[test]
fn adv129_snyk_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "snyk-api-token",
        "SNYK_TOKEN=01234567-89ab-cdef\u{FEFF}-0123-456789abcdef",
        "01234567-89ab-cdef-0123-456789abcdef",
    );
}

#[test]
fn adv129_snyk_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "snyk-api-token",
        "SNYK_TOKEN=01234567-89ab-cdef\u{2060}-0123-456789abcdef",
        "01234567-89ab-cdef-0123-456789abcdef",
    );
}

#[test]
fn adv129_snyk_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "snyk-api-token",
        "SNYK_TOKEN=01234567-89ab-cdef\u{180E}-0123-456789abcdef",
        "01234567-89ab-cdef-0123-456789abcdef",
    );
}

#[test]
fn adv129_snyk_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "snyk-api-token",
        "SNYK_TOKEN=01234567-89ab-cdef\u{202E}-0123-456789abcdef",
        "01234567-89ab-cdef-0123-456789abcdef",
    );
}

#[test]
fn adv129_snyk_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "snyk-api-token",
        "SNYK_TOKEN=01234567-89ab-cdef\u{202C}-0123-456789abcdef",
        "01234567-89ab-cdef-0123-456789abcdef",
    );
}

#[test]
fn adv129_snyk_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "snyk-api-token",
        "SNYK_TOKEN=01234567-89ab-cdef\u{200E}-0123-456789abcdef",
        "01234567-89ab-cdef-0123-456789abcdef",
    );
}

// =========================================================================
// 2. SOCURE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv129_socure_api_key_normal_must_fire() {
    assert_detector_fires(
        "socure-api-key",
        "SOCURE sdk_key=\"abcdefghijklmnopqrstuvwx123456",
        "abcdefghijklmnopqrstuvwx123456",
    );
}

#[test]
fn adv129_socure_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "socure-api-key",
        "dummy_prefix_0 =\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv129_socure_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "socure-api-key",
        "SOCURE sdk_key=\"abcdefghijklmno\u{200B}pqrstuvwx123456",
        "abcdefghijklmnopqrstuvwx123456",
    );
}

#[test]
fn adv129_socure_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "socure-api-key",
        "SOCURE sdk_key=\"abcdefghijklmno\u{00AD}pqrstuvwx123456",
        "abcdefghijklmnopqrstuvwx123456",
    );
}

#[test]
fn adv129_socure_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "socure-api-key",
        "SOCURE sdk_key=\"abcdefghijklmno\u{200C}pqrstuvwx123456",
        "abcdefghijklmnopqrstuvwx123456",
    );
}

#[test]
fn adv129_socure_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "socure-api-key",
        "SOCURE sdk_key=\"abcdefghijklmno\u{200D}pqrstuvwx123456",
        "abcdefghijklmnopqrstuvwx123456",
    );
}

#[test]
fn adv129_socure_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "socure-api-key",
        "SOCURE sdk_key=\"abcdefghijklmno\u{FEFF}pqrstuvwx123456",
        "abcdefghijklmnopqrstuvwx123456",
    );
}

#[test]
fn adv129_socure_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "socure-api-key",
        "SOCURE sdk_key=\"abcdefghijklmno\u{2060}pqrstuvwx123456",
        "abcdefghijklmnopqrstuvwx123456",
    );
}

#[test]
fn adv129_socure_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "socure-api-key",
        "SOCURE sdk_key=\"abcdefghijklmno\u{180E}pqrstuvwx123456",
        "abcdefghijklmnopqrstuvwx123456",
    );
}

#[test]
fn adv129_socure_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "socure-api-key",
        "SOCURE sdk_key=\"abcdefghijklmno\u{202E}pqrstuvwx123456",
        "abcdefghijklmnopqrstuvwx123456",
    );
}

#[test]
fn adv129_socure_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "socure-api-key",
        "SOCURE sdk_key=\"abcdefghijklmno\u{202C}pqrstuvwx123456",
        "abcdefghijklmnopqrstuvwx123456",
    );
}

#[test]
fn adv129_socure_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "socure-api-key",
        "SOCURE sdk_key=\"abcdefghijklmno\u{200E}pqrstuvwx123456",
        "abcdefghijklmnopqrstuvwx123456",
    );
}

// =========================================================================
// 3. SOLANA RPC CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv129_solana_rpc_credentials_normal_must_fire() {
    assert_detector_fires(
        "solana-rpc-credentials",
        "SOLANA_RPC_URL=https://api.mainnet-beta.solana.com/abc123token",
        "https://api.mainnet-beta.solana.com/abc123token",
    );
}

#[test]
fn adv129_solana_rpc_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "solana-rpc-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv129_solana_rpc_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "solana-rpc-credentials",
        "SOLANA_RPC_URL=https://api.mainnet-bet\u{200B}a.solana.com/abc123token",
        "https://api.mainnet-beta.solana.com/abc123token",
    );
}

#[test]
fn adv129_solana_rpc_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "solana-rpc-credentials",
        "SOLANA_RPC_URL=https://api.mainnet-bet\u{00AD}a.solana.com/abc123token",
        "https://api.mainnet-beta.solana.com/abc123token",
    );
}

#[test]
fn adv129_solana_rpc_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "solana-rpc-credentials",
        "SOLANA_RPC_URL=https://api.mainnet-bet\u{200C}a.solana.com/abc123token",
        "https://api.mainnet-beta.solana.com/abc123token",
    );
}

#[test]
fn adv129_solana_rpc_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "solana-rpc-credentials",
        "SOLANA_RPC_URL=https://api.mainnet-bet\u{200D}a.solana.com/abc123token",
        "https://api.mainnet-beta.solana.com/abc123token",
    );
}

#[test]
fn adv129_solana_rpc_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "solana-rpc-credentials",
        "SOLANA_RPC_URL=https://api.mainnet-bet\u{FEFF}a.solana.com/abc123token",
        "https://api.mainnet-beta.solana.com/abc123token",
    );
}

#[test]
fn adv129_solana_rpc_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "solana-rpc-credentials",
        "SOLANA_RPC_URL=https://api.mainnet-bet\u{2060}a.solana.com/abc123token",
        "https://api.mainnet-beta.solana.com/abc123token",
    );
}

#[test]
fn adv129_solana_rpc_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "solana-rpc-credentials",
        "SOLANA_RPC_URL=https://api.mainnet-bet\u{180E}a.solana.com/abc123token",
        "https://api.mainnet-beta.solana.com/abc123token",
    );
}

#[test]
fn adv129_solana_rpc_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "solana-rpc-credentials",
        "SOLANA_RPC_URL=https://api.mainnet-bet\u{202E}a.solana.com/abc123token",
        "https://api.mainnet-beta.solana.com/abc123token",
    );
}

#[test]
fn adv129_solana_rpc_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "solana-rpc-credentials",
        "SOLANA_RPC_URL=https://api.mainnet-bet\u{202C}a.solana.com/abc123token",
        "https://api.mainnet-beta.solana.com/abc123token",
    );
}

#[test]
fn adv129_solana_rpc_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "solana-rpc-credentials",
        "SOLANA_RPC_URL=https://api.mainnet-bet\u{200E}a.solana.com/abc123token",
        "https://api.mainnet-beta.solana.com/abc123token",
    );
}

// =========================================================================
// 4. SONARCLOUD TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv129_sonarcloud_token_normal_must_fire() {
    assert_detector_fires(
        "sonarcloud-token",
        "SONAR=800f231fa32c35248b0ccb25668b8f4e691e9381",
        "800f231fa32c35248b0ccb25668b8f4e691e9381",
    );
}

#[test]
fn adv129_sonarcloud_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "sonarcloud-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv129_sonarcloud_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sonarcloud-token",
        "SONAR=800f231fa32c35248b0c\u{200B}cb25668b8f4e691e9381",
        "800f231fa32c35248b0ccb25668b8f4e691e9381",
    );
}

#[test]
fn adv129_sonarcloud_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sonarcloud-token",
        "SONAR=800f231fa32c35248b0c\u{00AD}cb25668b8f4e691e9381",
        "800f231fa32c35248b0ccb25668b8f4e691e9381",
    );
}

#[test]
fn adv129_sonarcloud_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "sonarcloud-token",
        "SONAR=800f231fa32c35248b0c\u{200C}cb25668b8f4e691e9381",
        "800f231fa32c35248b0ccb25668b8f4e691e9381",
    );
}

#[test]
fn adv129_sonarcloud_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "sonarcloud-token",
        "SONAR=800f231fa32c35248b0c\u{200D}cb25668b8f4e691e9381",
        "800f231fa32c35248b0ccb25668b8f4e691e9381",
    );
}

#[test]
fn adv129_sonarcloud_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "sonarcloud-token",
        "SONAR=800f231fa32c35248b0c\u{FEFF}cb25668b8f4e691e9381",
        "800f231fa32c35248b0ccb25668b8f4e691e9381",
    );
}

#[test]
fn adv129_sonarcloud_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "sonarcloud-token",
        "SONAR=800f231fa32c35248b0c\u{2060}cb25668b8f4e691e9381",
        "800f231fa32c35248b0ccb25668b8f4e691e9381",
    );
}

#[test]
fn adv129_sonarcloud_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "sonarcloud-token",
        "SONAR=800f231fa32c35248b0c\u{180E}cb25668b8f4e691e9381",
        "800f231fa32c35248b0ccb25668b8f4e691e9381",
    );
}

#[test]
fn adv129_sonarcloud_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "sonarcloud-token",
        "SONAR=800f231fa32c35248b0c\u{202E}cb25668b8f4e691e9381",
        "800f231fa32c35248b0ccb25668b8f4e691e9381",
    );
}

#[test]
fn adv129_sonarcloud_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "sonarcloud-token",
        "SONAR=800f231fa32c35248b0c\u{202C}cb25668b8f4e691e9381",
        "800f231fa32c35248b0ccb25668b8f4e691e9381",
    );
}

#[test]
fn adv129_sonarcloud_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "sonarcloud-token",
        "SONAR=800f231fa32c35248b0c\u{200E}cb25668b8f4e691e9381",
        "800f231fa32c35248b0ccb25668b8f4e691e9381",
    );
}

// =========================================================================
// 5. SONARQUBE TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv129_sonarqube_token_normal_must_fire() {
    assert_detector_fires(
        "sonarqube-token",
        "SONAR=204f1387a0335f63afce7b2685befb39f7cf1d26",
        "204f1387a0335f63afce7b2685befb39f7cf1d26",
    );
}

#[test]
fn adv129_sonarqube_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "sonarqube-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv129_sonarqube_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sonarqube-token",
        "SONAR=204f1387a0335f63afce\u{200B}7b2685befb39f7cf1d26",
        "204f1387a0335f63afce7b2685befb39f7cf1d26",
    );
}

#[test]
fn adv129_sonarqube_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sonarqube-token",
        "SONAR=204f1387a0335f63afce\u{00AD}7b2685befb39f7cf1d26",
        "204f1387a0335f63afce7b2685befb39f7cf1d26",
    );
}

#[test]
fn adv129_sonarqube_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "sonarqube-token",
        "SONAR=204f1387a0335f63afce\u{200C}7b2685befb39f7cf1d26",
        "204f1387a0335f63afce7b2685befb39f7cf1d26",
    );
}

#[test]
fn adv129_sonarqube_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "sonarqube-token",
        "SONAR=204f1387a0335f63afce\u{200D}7b2685befb39f7cf1d26",
        "204f1387a0335f63afce7b2685befb39f7cf1d26",
    );
}

#[test]
fn adv129_sonarqube_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "sonarqube-token",
        "SONAR=204f1387a0335f63afce\u{FEFF}7b2685befb39f7cf1d26",
        "204f1387a0335f63afce7b2685befb39f7cf1d26",
    );
}

#[test]
fn adv129_sonarqube_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "sonarqube-token",
        "SONAR=204f1387a0335f63afce\u{2060}7b2685befb39f7cf1d26",
        "204f1387a0335f63afce7b2685befb39f7cf1d26",
    );
}

#[test]
fn adv129_sonarqube_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "sonarqube-token",
        "SONAR=204f1387a0335f63afce\u{180E}7b2685befb39f7cf1d26",
        "204f1387a0335f63afce7b2685befb39f7cf1d26",
    );
}

#[test]
fn adv129_sonarqube_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "sonarqube-token",
        "SONAR=204f1387a0335f63afce\u{202E}7b2685befb39f7cf1d26",
        "204f1387a0335f63afce7b2685befb39f7cf1d26",
    );
}

#[test]
fn adv129_sonarqube_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "sonarqube-token",
        "SONAR=204f1387a0335f63afce\u{202C}7b2685befb39f7cf1d26",
        "204f1387a0335f63afce7b2685befb39f7cf1d26",
    );
}

#[test]
fn adv129_sonarqube_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "sonarqube-token",
        "SONAR=204f1387a0335f63afce\u{200E}7b2685befb39f7cf1d26",
        "204f1387a0335f63afce7b2685befb39f7cf1d26",
    );
}

// =========================================================================
// 6. SORACOM API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv129_soracom_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "soracom-api-credentials",
        "keyId-fWeqR7Ch-gpIA-kP1f-hatI-fNcS7cg8NnPp",
        "keyId-fWeqR7Ch-gpIA-kP1f-hatI-fNcS7cg8NnPp",
    );
}

#[test]
fn adv129_soracom_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "soracom-api-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv129_soracom_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "soracom-api-credentials",
        "keyId-fWeqR7Ch-gpIA-k\u{200B}P1f-hatI-fNcS7cg8NnPp",
        "keyId-fWeqR7Ch-gpIA-kP1f-hatI-fNcS7cg8NnPp",
    );
}

#[test]
fn adv129_soracom_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "soracom-api-credentials",
        "keyId-fWeqR7Ch-gpIA-k\u{00AD}P1f-hatI-fNcS7cg8NnPp",
        "keyId-fWeqR7Ch-gpIA-kP1f-hatI-fNcS7cg8NnPp",
    );
}

#[test]
fn adv129_soracom_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "soracom-api-credentials",
        "keyId-fWeqR7Ch-gpIA-k\u{200C}P1f-hatI-fNcS7cg8NnPp",
        "keyId-fWeqR7Ch-gpIA-kP1f-hatI-fNcS7cg8NnPp",
    );
}

#[test]
fn adv129_soracom_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "soracom-api-credentials",
        "keyId-fWeqR7Ch-gpIA-k\u{200D}P1f-hatI-fNcS7cg8NnPp",
        "keyId-fWeqR7Ch-gpIA-kP1f-hatI-fNcS7cg8NnPp",
    );
}

#[test]
fn adv129_soracom_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "soracom-api-credentials",
        "keyId-fWeqR7Ch-gpIA-k\u{FEFF}P1f-hatI-fNcS7cg8NnPp",
        "keyId-fWeqR7Ch-gpIA-kP1f-hatI-fNcS7cg8NnPp",
    );
}

#[test]
fn adv129_soracom_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "soracom-api-credentials",
        "keyId-fWeqR7Ch-gpIA-k\u{2060}P1f-hatI-fNcS7cg8NnPp",
        "keyId-fWeqR7Ch-gpIA-kP1f-hatI-fNcS7cg8NnPp",
    );
}

#[test]
fn adv129_soracom_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "soracom-api-credentials",
        "keyId-fWeqR7Ch-gpIA-k\u{180E}P1f-hatI-fNcS7cg8NnPp",
        "keyId-fWeqR7Ch-gpIA-kP1f-hatI-fNcS7cg8NnPp",
    );
}

#[test]
fn adv129_soracom_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "soracom-api-credentials",
        "keyId-fWeqR7Ch-gpIA-k\u{202E}P1f-hatI-fNcS7cg8NnPp",
        "keyId-fWeqR7Ch-gpIA-kP1f-hatI-fNcS7cg8NnPp",
    );
}

#[test]
fn adv129_soracom_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "soracom-api-credentials",
        "keyId-fWeqR7Ch-gpIA-k\u{202C}P1f-hatI-fNcS7cg8NnPp",
        "keyId-fWeqR7Ch-gpIA-kP1f-hatI-fNcS7cg8NnPp",
    );
}

#[test]
fn adv129_soracom_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "soracom-api-credentials",
        "keyId-fWeqR7Ch-gpIA-k\u{200E}P1f-hatI-fNcS7cg8NnPp",
        "keyId-fWeqR7Ch-gpIA-kP1f-hatI-fNcS7cg8NnPp",
    );
}

// =========================================================================
// 7. SOURCETREE CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv129_sourcetree_credentials_normal_must_fire() {
    assert_detector_fires(
        "sourcetree-credentials",
        "SOURCETREE_PASSWORD=SourceTreePass1234!",
        "SourceTreePass1234!",
    );
}

#[test]
fn adv129_sourcetree_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "sourcetree-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv129_sourcetree_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sourcetree-credentials",
        "SOURCETREE_PASSWORD=SourceTre\u{200B}ePass1234!",
        "SourceTreePass1234!",
    );
}

#[test]
fn adv129_sourcetree_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sourcetree-credentials",
        "SOURCETREE_PASSWORD=SourceTre\u{00AD}ePass1234!",
        "SourceTreePass1234!",
    );
}

#[test]
fn adv129_sourcetree_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "sourcetree-credentials",
        "SOURCETREE_PASSWORD=SourceTre\u{200C}ePass1234!",
        "SourceTreePass1234!",
    );
}

#[test]
fn adv129_sourcetree_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "sourcetree-credentials",
        "SOURCETREE_PASSWORD=SourceTre\u{200D}ePass1234!",
        "SourceTreePass1234!",
    );
}

#[test]
fn adv129_sourcetree_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "sourcetree-credentials",
        "SOURCETREE_PASSWORD=SourceTre\u{FEFF}ePass1234!",
        "SourceTreePass1234!",
    );
}

#[test]
fn adv129_sourcetree_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "sourcetree-credentials",
        "SOURCETREE_PASSWORD=SourceTre\u{2060}ePass1234!",
        "SourceTreePass1234!",
    );
}

#[test]
fn adv129_sourcetree_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "sourcetree-credentials",
        "SOURCETREE_PASSWORD=SourceTre\u{180E}ePass1234!",
        "SourceTreePass1234!",
    );
}

#[test]
fn adv129_sourcetree_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "sourcetree-credentials",
        "SOURCETREE_PASSWORD=SourceTre\u{202E}ePass1234!",
        "SourceTreePass1234!",
    );
}

#[test]
fn adv129_sourcetree_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "sourcetree-credentials",
        "SOURCETREE_PASSWORD=SourceTre\u{202C}ePass1234!",
        "SourceTreePass1234!",
    );
}

#[test]
fn adv129_sourcetree_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "sourcetree-credentials",
        "SOURCETREE_PASSWORD=SourceTre\u{200E}ePass1234!",
        "SourceTreePass1234!",
    );
}

// =========================================================================
// 8. SOUTH KOREA DATAGOKR API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv129_south_korea_datagokr_api_key_normal_must_fire() {
    assert_detector_fires(
        "south-korea-datagokr-api-key",
        "data.go.krapi_key kVZ1IaWiI91uDEBI6tzGKy9soXY7baXffP0dRA9FjLiH1CWx",
        "kVZ1IaWiI91uDEBI6tzGKy9soXY7baXffP0dRA9FjLiH1CWx",
    );
}

#[test]
fn adv129_south_korea_datagokr_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "south-korea-datagokr-api-key",
        "dummy.go.krapi_key xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv129_south_korea_datagokr_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "south-korea-datagokr-api-key",
        "data.go.krapi_key kVZ1IaWiI91uDEBI6tzGKy9s\u{200B}oXY7baXffP0dRA9FjLiH1CWx",
        "kVZ1IaWiI91uDEBI6tzGKy9soXY7baXffP0dRA9FjLiH1CWx",
    );
}

#[test]
fn adv129_south_korea_datagokr_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "south-korea-datagokr-api-key",
        "data.go.krapi_key kVZ1IaWiI91uDEBI6tzGKy9s\u{00AD}oXY7baXffP0dRA9FjLiH1CWx",
        "kVZ1IaWiI91uDEBI6tzGKy9soXY7baXffP0dRA9FjLiH1CWx",
    );
}

#[test]
fn adv129_south_korea_datagokr_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "south-korea-datagokr-api-key",
        "data.go.krapi_key kVZ1IaWiI91uDEBI6tzGKy9s\u{200C}oXY7baXffP0dRA9FjLiH1CWx",
        "kVZ1IaWiI91uDEBI6tzGKy9soXY7baXffP0dRA9FjLiH1CWx",
    );
}

#[test]
fn adv129_south_korea_datagokr_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "south-korea-datagokr-api-key",
        "data.go.krapi_key kVZ1IaWiI91uDEBI6tzGKy9s\u{200D}oXY7baXffP0dRA9FjLiH1CWx",
        "kVZ1IaWiI91uDEBI6tzGKy9soXY7baXffP0dRA9FjLiH1CWx",
    );
}

#[test]
fn adv129_south_korea_datagokr_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "south-korea-datagokr-api-key",
        "data.go.krapi_key kVZ1IaWiI91uDEBI6tzGKy9s\u{FEFF}oXY7baXffP0dRA9FjLiH1CWx",
        "kVZ1IaWiI91uDEBI6tzGKy9soXY7baXffP0dRA9FjLiH1CWx",
    );
}

#[test]
fn adv129_south_korea_datagokr_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "south-korea-datagokr-api-key",
        "data.go.krapi_key kVZ1IaWiI91uDEBI6tzGKy9s\u{2060}oXY7baXffP0dRA9FjLiH1CWx",
        "kVZ1IaWiI91uDEBI6tzGKy9soXY7baXffP0dRA9FjLiH1CWx",
    );
}

#[test]
fn adv129_south_korea_datagokr_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "south-korea-datagokr-api-key",
        "data.go.krapi_key kVZ1IaWiI91uDEBI6tzGKy9s\u{180E}oXY7baXffP0dRA9FjLiH1CWx",
        "kVZ1IaWiI91uDEBI6tzGKy9soXY7baXffP0dRA9FjLiH1CWx",
    );
}

#[test]
fn adv129_south_korea_datagokr_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "south-korea-datagokr-api-key",
        "data.go.krapi_key kVZ1IaWiI91uDEBI6tzGKy9s\u{202E}oXY7baXffP0dRA9FjLiH1CWx",
        "kVZ1IaWiI91uDEBI6tzGKy9soXY7baXffP0dRA9FjLiH1CWx",
    );
}

#[test]
fn adv129_south_korea_datagokr_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "south-korea-datagokr-api-key",
        "data.go.krapi_key kVZ1IaWiI91uDEBI6tzGKy9s\u{202C}oXY7baXffP0dRA9FjLiH1CWx",
        "kVZ1IaWiI91uDEBI6tzGKy9soXY7baXffP0dRA9FjLiH1CWx",
    );
}

#[test]
fn adv129_south_korea_datagokr_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "south-korea-datagokr-api-key",
        "data.go.krapi_key kVZ1IaWiI91uDEBI6tzGKy9s\u{200E}oXY7baXffP0dRA9FjLiH1CWx",
        "kVZ1IaWiI91uDEBI6tzGKy9soXY7baXffP0dRA9FjLiH1CWx",
    );
}

// =========================================================================
// 9. SOVOS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv129_sovos_api_key_normal_must_fire() {
    assert_detector_fires(
        "sovos-api-key",
        "SOVOS_API_KEY=Z5bJgWzWferfBeuIonJB",
        "Z5bJgWzWferfBeuIonJB",
    );
}

#[test]
fn adv129_sovos_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("sovos-api-key", "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv129_sovos_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sovos-api-key",
        "SOVOS_API_KEY=Z5bJgWzWfe\u{200B}rfBeuIonJB",
        "Z5bJgWzWferfBeuIonJB",
    );
}

#[test]
fn adv129_sovos_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sovos-api-key",
        "SOVOS_API_KEY=Z5bJgWzWfe\u{00AD}rfBeuIonJB",
        "Z5bJgWzWferfBeuIonJB",
    );
}

#[test]
fn adv129_sovos_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "sovos-api-key",
        "SOVOS_API_KEY=Z5bJgWzWfe\u{200C}rfBeuIonJB",
        "Z5bJgWzWferfBeuIonJB",
    );
}

#[test]
fn adv129_sovos_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "sovos-api-key",
        "SOVOS_API_KEY=Z5bJgWzWfe\u{200D}rfBeuIonJB",
        "Z5bJgWzWferfBeuIonJB",
    );
}

#[test]
fn adv129_sovos_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "sovos-api-key",
        "SOVOS_API_KEY=Z5bJgWzWfe\u{FEFF}rfBeuIonJB",
        "Z5bJgWzWferfBeuIonJB",
    );
}

#[test]
fn adv129_sovos_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "sovos-api-key",
        "SOVOS_API_KEY=Z5bJgWzWfe\u{2060}rfBeuIonJB",
        "Z5bJgWzWferfBeuIonJB",
    );
}

#[test]
fn adv129_sovos_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "sovos-api-key",
        "SOVOS_API_KEY=Z5bJgWzWfe\u{180E}rfBeuIonJB",
        "Z5bJgWzWferfBeuIonJB",
    );
}

#[test]
fn adv129_sovos_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "sovos-api-key",
        "SOVOS_API_KEY=Z5bJgWzWfe\u{202E}rfBeuIonJB",
        "Z5bJgWzWferfBeuIonJB",
    );
}

#[test]
fn adv129_sovos_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "sovos-api-key",
        "SOVOS_API_KEY=Z5bJgWzWfe\u{202C}rfBeuIonJB",
        "Z5bJgWzWferfBeuIonJB",
    );
}

#[test]
fn adv129_sovos_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "sovos-api-key",
        "SOVOS_API_KEY=Z5bJgWzWfe\u{200E}rfBeuIonJB",
        "Z5bJgWzWferfBeuIonJB",
    );
}

// =========================================================================
// 10. SPACELIFT API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv129_spacelift_api_key_normal_must_fire() {
    assert_detector_fires(
        "spacelift-api-key",
        "SPACELIFT_TOKEN=eyJlh4gmpKuEvkwmoEhlBA1QPdLCTuoARuZx70KNqa6sYa6CucvELAWX-rSml4JuHm66N5_FJv7ONZs3urH.eyJ_Y-lC08IeiZDhXg-1jL475aE_LHd7Uu1E5C9N1.682JzA4aHBY6IEDHZhBz9uu2yN3cULBuNnWy",
        "eyJlh4gmpKuEvkwmoEhlBA1QPdLCTuoARuZx70KNqa6sYa6CucvELAWX-rSml4JuHm66N5_FJv7ONZs3urH.eyJ_Y-lC08IeiZDhXg-1jL475aE_LHd7Uu1E5C9N1.682JzA4aHBY6IEDHZhBz9uu2yN3cULBuNnWy",
    );
}

#[test]
fn adv129_spacelift_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "spacelift-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv129_spacelift_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "spacelift-api-key",
        "SPACELIFT_TOKEN=eyJlh4gmpKuEvkwmoEhlBA1QPdLCTuoARuZx70KNqa6sYa6CucvELAWX-rSml4JuHm66N5_FJv7ONZs3u\u{200B}rH.eyJ_Y-lC08IeiZDhXg-1jL475aE_LHd7Uu1E5C9N1.682JzA4aHBY6IEDHZhBz9uu2yN3cULBuNnWy",
        "eyJlh4gmpKuEvkwmoEhlBA1QPdLCTuoARuZx70KNqa6sYa6CucvELAWX-rSml4JuHm66N5_FJv7ONZs3urH.eyJ_Y-lC08IeiZDhXg-1jL475aE_LHd7Uu1E5C9N1.682JzA4aHBY6IEDHZhBz9uu2yN3cULBuNnWy",
    );
}

#[test]
fn adv129_spacelift_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "spacelift-api-key",
        "SPACELIFT_TOKEN=eyJlh4gmpKuEvkwmoEhlBA1QPdLCTuoARuZx70KNqa6sYa6CucvELAWX-rSml4JuHm66N5_FJv7ONZs3u\u{00AD}rH.eyJ_Y-lC08IeiZDhXg-1jL475aE_LHd7Uu1E5C9N1.682JzA4aHBY6IEDHZhBz9uu2yN3cULBuNnWy",
        "eyJlh4gmpKuEvkwmoEhlBA1QPdLCTuoARuZx70KNqa6sYa6CucvELAWX-rSml4JuHm66N5_FJv7ONZs3urH.eyJ_Y-lC08IeiZDhXg-1jL475aE_LHd7Uu1E5C9N1.682JzA4aHBY6IEDHZhBz9uu2yN3cULBuNnWy",
    );
}

#[test]
fn adv129_spacelift_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "spacelift-api-key",
        "SPACELIFT_TOKEN=eyJlh4gmpKuEvkwmoEhlBA1QPdLCTuoARuZx70KNqa6sYa6CucvELAWX-rSml4JuHm66N5_FJv7ONZs3u\u{200C}rH.eyJ_Y-lC08IeiZDhXg-1jL475aE_LHd7Uu1E5C9N1.682JzA4aHBY6IEDHZhBz9uu2yN3cULBuNnWy",
        "eyJlh4gmpKuEvkwmoEhlBA1QPdLCTuoARuZx70KNqa6sYa6CucvELAWX-rSml4JuHm66N5_FJv7ONZs3urH.eyJ_Y-lC08IeiZDhXg-1jL475aE_LHd7Uu1E5C9N1.682JzA4aHBY6IEDHZhBz9uu2yN3cULBuNnWy",
    );
}

#[test]
fn adv129_spacelift_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "spacelift-api-key",
        "SPACELIFT_TOKEN=eyJlh4gmpKuEvkwmoEhlBA1QPdLCTuoARuZx70KNqa6sYa6CucvELAWX-rSml4JuHm66N5_FJv7ONZs3u\u{200D}rH.eyJ_Y-lC08IeiZDhXg-1jL475aE_LHd7Uu1E5C9N1.682JzA4aHBY6IEDHZhBz9uu2yN3cULBuNnWy",
        "eyJlh4gmpKuEvkwmoEhlBA1QPdLCTuoARuZx70KNqa6sYa6CucvELAWX-rSml4JuHm66N5_FJv7ONZs3urH.eyJ_Y-lC08IeiZDhXg-1jL475aE_LHd7Uu1E5C9N1.682JzA4aHBY6IEDHZhBz9uu2yN3cULBuNnWy",
    );
}

#[test]
fn adv129_spacelift_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "spacelift-api-key",
        "SPACELIFT_TOKEN=eyJlh4gmpKuEvkwmoEhlBA1QPdLCTuoARuZx70KNqa6sYa6CucvELAWX-rSml4JuHm66N5_FJv7ONZs3u\u{FEFF}rH.eyJ_Y-lC08IeiZDhXg-1jL475aE_LHd7Uu1E5C9N1.682JzA4aHBY6IEDHZhBz9uu2yN3cULBuNnWy",
        "eyJlh4gmpKuEvkwmoEhlBA1QPdLCTuoARuZx70KNqa6sYa6CucvELAWX-rSml4JuHm66N5_FJv7ONZs3urH.eyJ_Y-lC08IeiZDhXg-1jL475aE_LHd7Uu1E5C9N1.682JzA4aHBY6IEDHZhBz9uu2yN3cULBuNnWy",
    );
}

#[test]
fn adv129_spacelift_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "spacelift-api-key",
        "SPACELIFT_TOKEN=eyJlh4gmpKuEvkwmoEhlBA1QPdLCTuoARuZx70KNqa6sYa6CucvELAWX-rSml4JuHm66N5_FJv7ONZs3u\u{2060}rH.eyJ_Y-lC08IeiZDhXg-1jL475aE_LHd7Uu1E5C9N1.682JzA4aHBY6IEDHZhBz9uu2yN3cULBuNnWy",
        "eyJlh4gmpKuEvkwmoEhlBA1QPdLCTuoARuZx70KNqa6sYa6CucvELAWX-rSml4JuHm66N5_FJv7ONZs3urH.eyJ_Y-lC08IeiZDhXg-1jL475aE_LHd7Uu1E5C9N1.682JzA4aHBY6IEDHZhBz9uu2yN3cULBuNnWy",
    );
}

#[test]
fn adv129_spacelift_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "spacelift-api-key",
        "SPACELIFT_TOKEN=eyJlh4gmpKuEvkwmoEhlBA1QPdLCTuoARuZx70KNqa6sYa6CucvELAWX-rSml4JuHm66N5_FJv7ONZs3u\u{180E}rH.eyJ_Y-lC08IeiZDhXg-1jL475aE_LHd7Uu1E5C9N1.682JzA4aHBY6IEDHZhBz9uu2yN3cULBuNnWy",
        "eyJlh4gmpKuEvkwmoEhlBA1QPdLCTuoARuZx70KNqa6sYa6CucvELAWX-rSml4JuHm66N5_FJv7ONZs3urH.eyJ_Y-lC08IeiZDhXg-1jL475aE_LHd7Uu1E5C9N1.682JzA4aHBY6IEDHZhBz9uu2yN3cULBuNnWy",
    );
}

#[test]
fn adv129_spacelift_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "spacelift-api-key",
        "SPACELIFT_TOKEN=eyJlh4gmpKuEvkwmoEhlBA1QPdLCTuoARuZx70KNqa6sYa6CucvELAWX-rSml4JuHm66N5_FJv7ONZs3u\u{202E}rH.eyJ_Y-lC08IeiZDhXg-1jL475aE_LHd7Uu1E5C9N1.682JzA4aHBY6IEDHZhBz9uu2yN3cULBuNnWy",
        "eyJlh4gmpKuEvkwmoEhlBA1QPdLCTuoARuZx70KNqa6sYa6CucvELAWX-rSml4JuHm66N5_FJv7ONZs3urH.eyJ_Y-lC08IeiZDhXg-1jL475aE_LHd7Uu1E5C9N1.682JzA4aHBY6IEDHZhBz9uu2yN3cULBuNnWy",
    );
}

#[test]
fn adv129_spacelift_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "spacelift-api-key",
        "SPACELIFT_TOKEN=eyJlh4gmpKuEvkwmoEhlBA1QPdLCTuoARuZx70KNqa6sYa6CucvELAWX-rSml4JuHm66N5_FJv7ONZs3u\u{202C}rH.eyJ_Y-lC08IeiZDhXg-1jL475aE_LHd7Uu1E5C9N1.682JzA4aHBY6IEDHZhBz9uu2yN3cULBuNnWy",
        "eyJlh4gmpKuEvkwmoEhlBA1QPdLCTuoARuZx70KNqa6sYa6CucvELAWX-rSml4JuHm66N5_FJv7ONZs3urH.eyJ_Y-lC08IeiZDhXg-1jL475aE_LHd7Uu1E5C9N1.682JzA4aHBY6IEDHZhBz9uu2yN3cULBuNnWy",
    );
}

#[test]
fn adv129_spacelift_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "spacelift-api-key",
        "SPACELIFT_TOKEN=eyJlh4gmpKuEvkwmoEhlBA1QPdLCTuoARuZx70KNqa6sYa6CucvELAWX-rSml4JuHm66N5_FJv7ONZs3u\u{200E}rH.eyJ_Y-lC08IeiZDhXg-1jL475aE_LHd7Uu1E5C9N1.682JzA4aHBY6IEDHZhBz9uu2yN3cULBuNnWy",
        "eyJlh4gmpKuEvkwmoEhlBA1QPdLCTuoARuZx70KNqa6sYa6CucvELAWX-rSml4JuHm66N5_FJv7ONZs3urH.eyJ_Y-lC08IeiZDhXg-1jL475aE_LHd7Uu1E5C9N1.682JzA4aHBY6IEDHZhBz9uu2yN3cULBuNnWy",
    );
}
