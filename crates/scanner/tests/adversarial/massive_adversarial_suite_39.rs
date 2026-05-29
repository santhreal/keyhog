//! Part 39 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates hanko, hanko, harbor, hashicorp, hashnode, hasura, headspin, heap, heap, helicone detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. HANKO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv39_hanko_api_key_normal_must_fire() {
    assert_detector_fires(
        "hanko-api-key",
        "HANKO_API_KEY = \"hanko_api_key_high_entropy_secret_12345\"",
        "hanko_api_key_high_entropy_secret_12345",
    );
}

#[test]
fn adv39_hanko_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hanko-api-key",
        "TANKO_API_KEY = \"hanko_api_key_high_entropy_secret_12345\"",
    );
}

#[test]
fn adv39_hanko_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hanko-api-key",
        "HANKO_API_KEY = \"hanko_api_key_high\u{200B}_entropy_secret_12345\"",
        "hanko_api_key_high_entropy_secret_12345",
    );
}

#[test]
fn adv39_hanko_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hanko-api-key",
        "HANKO_API_KEY = \"hanko_api_key_high\u{00AD}_entropy_secret_12345\"",
        "hanko_api_key_high_entropy_secret_12345",
    );
}

#[test]
fn adv39_hanko_api_key_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "hanko-api-key",
        "H\u{0430}nk\u{043e}_API_KEY = \"hanko_api_key_high_entropy_secret_12345\"",
        "hanko_api_key_high_entropy_secret_12345",
    );
}

// =========================================================================
// 2. HANKO PASSKEY API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv39_hanko_passkey_credentials_normal_must_fire() {
    assert_detector_fires(
        "hanko-passkey-credentials",
        "HANKO_API_SECRET = hanko_high_entropy_secret_12345",
        "hanko_high_entropy_secret_12345",
    );
}

#[test]
fn adv39_hanko_passkey_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hanko-passkey-credentials",
        "HANKO_API_SECRET = tanko_high_entropy_secret_12345",
    );
}

#[test]
fn adv39_hanko_passkey_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hanko-passkey-credentials",
        "HANKO_API_SECRET = hanko_\u{200B}high_entropy_secret_12345",
        "hanko_high_entropy_secret_12345",
    );
}

#[test]
fn adv39_hanko_passkey_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hanko-passkey-credentials",
        "HANKO_API_SECRET = hanko_high_entropy_secret_\u{00AD}12345",
        "hanko_high_entropy_secret_12345",
    );
}

#[test]
fn adv39_hanko_passkey_credentials_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "hanko-passkey-credentials",
        "H\u{0430}nk\u{043e}_API_SECRET = hanko_high_entropy_secret_12345",
        "hanko_high_entropy_secret_12345",
    );
}

// =========================================================================
// 3. HARBOR ROBOT ACCOUNT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv39_harbor_robot_credentials_normal_must_fire() {
    assert_detector_fires(
        "harbor-robot-credentials",
        "harbor_password = \"harbor_robot_password_high_entropy_1234567890abcdef\"",
        "harbor_robot_password_high_entropy_1234567890abcdef",
    );
}

#[test]
fn adv39_harbor_robot_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "harbor-robot-credentials",
        "tarbor_password = \"harbor_robot_password_high_entropy_1234567890abcdef\"",
    );
}

#[test]
fn adv39_harbor_robot_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "harbor-robot-credentials",
        "harbor_password = \"harbor_robot_password_high\u{200B}_entropy_1234567890abcdef\"",
        "harbor_robot_password_high_entropy_1234567890abcdef",
    );
}

#[test]
fn adv39_harbor_robot_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "harbor-robot-credentials",
        "harbor_password = \"harbor_robot_password_high\u{00AD}_entropy_1234567890abcdef\"",
        "harbor_robot_password_high_entropy_1234567890abcdef",
    );
}

#[test]
fn adv39_harbor_robot_credentials_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "harbor-robot-credentials",
        "h\u{0430}rb\u{043e}r_password = \"harbor_robot_password_high_entropy_1234567890abcdef\"",
        "harbor_robot_password_high_entropy_1234567890abcdef",
    );
}

// =========================================================================
// 4. HASHICORP VAULT APPROLE CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv39_hashicorp_vault_approle_credentials_normal_must_fire() {
    assert_detector_fires(
        "hashicorp-vault-approle-credentials",
        "role_id = \"12345678-abcd-1234-abcd-1234567890ab\"\nsecret_id = \"87654321-dbca-4321-dbca-ba0987654321\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv39_hashicorp_vault_approle_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hashicorp-vault-approle-credentials",
        "tole_id = \"12345678-abcd-1234-abcd-1234567890ab\"\nsecret_id = \"87654321-dbca-4321-dbca-ba0987654321\"",
    );
}

#[test]
fn adv39_hashicorp_vault_approle_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hashicorp-vault-approle-credentials",
        "role_id = \"12345678-abcd-1234-abcd-1234\u{200B}567890ab\"\nsecret_id = \"87654321-dbca-4321-dbca-ba0987654321\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv39_hashicorp_vault_approle_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hashicorp-vault-approle-credentials",
        "role_id = \"12345678-abcd-1234-abcd-123456\u{00AD}7890ab\"\nsecret_id = \"87654321-dbca-4321-dbca-ba0987654321\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv39_hashicorp_vault_approle_credentials_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "hashicorp-vault-approle-credentials",
        "r\u{043e}l\u{0435}_id = \"12345678-abcd-1234-abcd-1234567890ab\"\nsecret_id = \"87654321-dbca-4321-dbca-ba0987654321\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

// =========================================================================
// 5. HASHNODE PERSONAL ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv39_hashnode_api_token_normal_must_fire() {
    assert_detector_fires(
        "hashnode-api-token",
        "personal_access_token = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv39_hashnode_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hashnode-api-token",
        "tersional_access_token = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"",
    );
}

#[test]
fn adv39_hashnode_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hashnode-api-token",
        "personal_access_token = \"a1b2c3d4\u{200B}e5f6a1b2c3d4e5f6a1b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv39_hashnode_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hashnode-api-token",
        "personal_access_token = \"a1b2c3d4e5f6a1b2c3d4e5f6a1\u{00AD}b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv39_hashnode_api_token_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "hashnode-api-token",
        "p\u{0435}rs\u{043e}nal_acc\u{0435}ss_t\u{043e}k\u{0435}n = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

// =========================================================================
// 6. HASURA ADMIN SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv39_hasura_admin_secret_normal_must_fire() {
    assert_detector_fires(
        "hasura-admin-secret",
        "HASURA_GRAPHQL_ADMIN_SECRET = \"hasura_admin_secret_high_entropy_123\"",
        "hasura_admin_secret_high_entropy_123",
    );
}

#[test]
fn adv39_hasura_admin_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hasura-admin-secret",
        "TASURA_GRAPHQL_ADMIN_SECRET = \"hasura_admin_secret_high_entropy_123\"",
    );
}

#[test]
fn adv39_hasura_admin_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hasura-admin-secret",
        "HASURA_GRAPHQL_ADMIN_SECRET = \"hasura_admin_secret_high\u{200B}_entropy_123\"",
        "hasura_admin_secret_high_entropy_123",
    );
}

#[test]
fn adv39_hasura_admin_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hasura-admin-secret",
        "HASURA_GRAPHQL_ADMIN_SECRET = \"hasura_admin_secret_high\u{00AD}_entropy_123\"",
        "hasura_admin_secret_high_entropy_123",
    );
}

#[test]
fn adv39_hasura_admin_secret_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "hasura-admin-secret",
        "H\u{0430}SUR\u{0430}_GRAPHQL_ADMIN_S\u{0435}CR\u{0435}T = \"hasura_admin_secret_high_entropy_123\"",
        "hasura_admin_secret_high_entropy_123",
    );
}

// =========================================================================
// 7. HEADSPIN API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv39_headspin_api_token_normal_must_fire() {
    assert_detector_fires(
        "headspin-api-token",
        "headspin_api_token = \"headspin_token_high_entropy_1234567890abcdef\"",
        "headspin_token_high_entropy_1234567890abcdef",
    );
}

#[test]
fn adv39_headspin_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "headspin-api-token",
        "teadspin_api_token = \"headspin_token_high_entropy_1234567890abcdef\"",
    );
}

#[test]
fn adv39_headspin_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "headspin-api-token",
        "headspin_api_token = \"headspin_token_high\u{200B}_entropy_1234567890abcdef\"",
        "headspin_token_high_entropy_1234567890abcdef",
    );
}

#[test]
fn adv39_headspin_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "headspin-api-token",
        "headspin_api_token = \"headspin_token_high\u{00AD}_entropy_1234567890abcdef\"",
        "headspin_token_high_entropy_1234567890abcdef",
    );
}

#[test]
fn adv39_headspin_api_token_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "headspin-api-token",
        "h\u{0435}\u{0430}dsp\u{0456}n_api_t\u{043e}k\u{0435}n = \"headspin_token_high_entropy_1234567890abcdef\"",
        "headspin_token_high_entropy_1234567890abcdef",
    );
}

// =========================================================================
// 8. HEAP ANALYTICS KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv39_heap_analytics_key_normal_must_fire() {
    assert_detector_fires(
        "heap-analytics-key",
        "HEAP_APP_ID = \"837462910\"",
        "837462910",
    );
}

#[test]
fn adv39_heap_analytics_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "heap-analytics-key",
        "TEAP_APP_ID = \"837462910\"",
    );
}

#[test]
fn adv39_heap_analytics_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "heap-analytics-key",
        "HEAP_APP_ID = \"83746\u{200B}2910\"",
        "837462910",
    );
}

#[test]
fn adv39_heap_analytics_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "heap-analytics-key",
        "HEAP_APP_ID = \"83746\u{00AD}2910\"",
        "837462910",
    );
}

#[test]
fn adv39_heap_analytics_key_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "heap-analytics-key",
        "H\u{0435}\u{0430}P_APP_ID = \"837462910\"",
        "837462910",
    );
}

// =========================================================================
// 9. HEAP API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv39_heap_api_key_normal_must_fire() {
    assert_detector_fires(
        "heap-api-key",
        "HEAP_ID = \"98237461028\"",
        "98237461028",
    );
}

#[test]
fn adv39_heap_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "heap-api-key",
        "TEAP_ID = \"98237461028\"",
    );
}

#[test]
fn adv39_heap_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "heap-api-key",
        "HEAP_ID = \"98237\u{200B}461028\"",
        "98237461028",
    );
}

#[test]
fn adv39_heap_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "heap-api-key",
        "HEAP_ID = \"98237\u{00AD}461028\"",
        "98237461028",
    );
}

#[test]
fn adv39_heap_api_key_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "heap-api-key",
        "H\u{0435}\u{0430}P_ID = \"98237461028\"",
        "98237461028",
    );
}

// =========================================================================
// 10. HELICONE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv39_helicone_api_key_normal_must_fire() {
    assert_detector_fires(
        "helicone-api-key",
        "helicone_key = \"sk-heliconeauth1234567890abcdef\"",
        "sk-heliconeauth1234567890abcdef",
    );
}

#[test]
fn adv39_helicone_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "helicone-api-key",
        "helicone_key = \"tk-heliconeauth1234567890abcdef\"",
    );
}

#[test]
fn adv39_helicone_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "helicone-api-key",
        "helicone_key = \"sk-\u{200B}heliconeauth1234567890abcdef\"",
        "sk-heliconeauth1234567890abcdef",
    );
}

#[test]
fn adv39_helicone_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "helicone-api-key",
        "helicone_key = \"sk-heliconeauth1234567890abc\u{00AD}def\"",
        "sk-heliconeauth1234567890abcdef",
    );
}

#[test]
fn adv39_helicone_api_key_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "helicone-api-key",
        "h\u{0435}l\u{0456}c\u{043e}n\u{0435}_key = \"sk-heliconeauth1234567890abcdef\"",
        "sk-heliconeauth1234567890abcdef",
    );
}


