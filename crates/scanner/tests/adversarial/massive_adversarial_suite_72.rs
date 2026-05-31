//! Part 72 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates braintree, braintree, braintree, braze, brazil, brevo, brightcove, brightdata, brightspace, budibase detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. BRAINTREE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv72_braintree_api_key_normal_must_fire() {
    assert_detector_fires(
        "braintree-api-key",
        "braintree_public_key=kp4qx7rm_sn5tb8vw_3yzkp4qx",
        "kp4qx7rm_sn5tb8vw_3yzkp4qx",
    );
}

#[test]
fn adv72_braintree_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "braintree-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv72_braintree_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "braintree-api-key",
        "braintree_public_key=kp4qx7rm_sn5t\u{200B}b8vw_3yzkp4qx",
        "kp4qx7rm_sn5tb8vw_3yzkp4qx",
    );
}

#[test]
fn adv72_braintree_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "braintree-api-key",
        "braintree_public_key=kp4qx7rm_sn5t\u{00AD}b8vw_3yzkp4qx",
        "kp4qx7rm_sn5tb8vw_3yzkp4qx",
    );
}

#[test]
fn adv72_braintree_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "braintree-api-key",
        "braintree_public_key=kp4qx7rm_sn5t\u{200C}b8vw_3yzkp4qx",
        "kp4qx7rm_sn5tb8vw_3yzkp4qx",
    );
}

#[test]
fn adv72_braintree_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "braintree-api-key",
        "braintree_public_key=kp4qx7rm_sn5t\u{200D}b8vw_3yzkp4qx",
        "kp4qx7rm_sn5tb8vw_3yzkp4qx",
    );
}

#[test]
fn adv72_braintree_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "braintree-api-key",
        "braintree_public_key=kp4qx7rm_sn5t\u{FEFF}b8vw_3yzkp4qx",
        "kp4qx7rm_sn5tb8vw_3yzkp4qx",
    );
}

#[test]
fn adv72_braintree_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "braintree-api-key",
        "braintree_public_key=kp4qx7rm_sn5t\u{2060}b8vw_3yzkp4qx",
        "kp4qx7rm_sn5tb8vw_3yzkp4qx",
    );
}

#[test]
fn adv72_braintree_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "braintree-api-key",
        "braintree_public_key=kp4qx7rm_sn5t\u{180E}b8vw_3yzkp4qx",
        "kp4qx7rm_sn5tb8vw_3yzkp4qx",
    );
}

#[test]
fn adv72_braintree_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "braintree-api-key",
        "braintree_public_key=kp4qx7rm_sn5t\u{202E}b8vw_3yzkp4qx",
        "kp4qx7rm_sn5tb8vw_3yzkp4qx",
    );
}

#[test]
fn adv72_braintree_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "braintree-api-key",
        "braintree_public_key=kp4qx7rm_sn5t\u{202C}b8vw_3yzkp4qx",
        "kp4qx7rm_sn5tb8vw_3yzkp4qx",
    );
}

#[test]
fn adv72_braintree_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "braintree-api-key",
        "braintree_public_key=kp4qx7rm_sn5t\u{200E}b8vw_3yzkp4qx",
        "kp4qx7rm_sn5tb8vw_3yzkp4qx",
    );
}

// =========================================================================
// 2. BRAINTREE PRIVATE KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv72_braintree_private_key_normal_must_fire() {
    assert_detector_fires(
        "braintree-private-key",
        "braintree_private_key=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_braintree_private_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "braintree-private-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv72_braintree_private_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "braintree-private-key",
        "braintree_private_key=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_braintree_private_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "braintree-private-key",
        "braintree_private_key=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_braintree_private_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "braintree-private-key",
        "braintree_private_key=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_braintree_private_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "braintree-private-key",
        "braintree_private_key=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_braintree_private_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "braintree-private-key",
        "braintree_private_key=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_braintree_private_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "braintree-private-key",
        "braintree_private_key=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_braintree_private_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "braintree-private-key",
        "braintree_private_key=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_braintree_private_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "braintree-private-key",
        "braintree_private_key=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_braintree_private_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "braintree-private-key",
        "braintree_private_key=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_braintree_private_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "braintree-private-key",
        "braintree_private_key=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 3. BRAINTREE SANDBOX TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv72_braintree_sandbox_token_normal_must_fire() {
    assert_detector_fires(
        "braintree-sandbox-token",
        "sandbox_kp4qx7rm_sn5tb8vw_3yzkp4qx",
        "sandbox_kp4qx7rm_sn5tb8vw_3yzkp4qx",
    );
}

#[test]
fn adv72_braintree_sandbox_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "braintree-sandbox-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv72_braintree_sandbox_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "braintree-sandbox-token",
        "sandbox_kp4qx7rm_\u{200B}sn5tb8vw_3yzkp4qx",
        "sandbox_kp4qx7rm_sn5tb8vw_3yzkp4qx",
    );
}

#[test]
fn adv72_braintree_sandbox_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "braintree-sandbox-token",
        "sandbox_kp4qx7rm_\u{00AD}sn5tb8vw_3yzkp4qx",
        "sandbox_kp4qx7rm_sn5tb8vw_3yzkp4qx",
    );
}

#[test]
fn adv72_braintree_sandbox_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "braintree-sandbox-token",
        "sandbox_kp4qx7rm_\u{200C}sn5tb8vw_3yzkp4qx",
        "sandbox_kp4qx7rm_sn5tb8vw_3yzkp4qx",
    );
}

#[test]
fn adv72_braintree_sandbox_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "braintree-sandbox-token",
        "sandbox_kp4qx7rm_\u{200D}sn5tb8vw_3yzkp4qx",
        "sandbox_kp4qx7rm_sn5tb8vw_3yzkp4qx",
    );
}

#[test]
fn adv72_braintree_sandbox_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "braintree-sandbox-token",
        "sandbox_kp4qx7rm_\u{FEFF}sn5tb8vw_3yzkp4qx",
        "sandbox_kp4qx7rm_sn5tb8vw_3yzkp4qx",
    );
}

#[test]
fn adv72_braintree_sandbox_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "braintree-sandbox-token",
        "sandbox_kp4qx7rm_\u{2060}sn5tb8vw_3yzkp4qx",
        "sandbox_kp4qx7rm_sn5tb8vw_3yzkp4qx",
    );
}

#[test]
fn adv72_braintree_sandbox_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "braintree-sandbox-token",
        "sandbox_kp4qx7rm_\u{180E}sn5tb8vw_3yzkp4qx",
        "sandbox_kp4qx7rm_sn5tb8vw_3yzkp4qx",
    );
}

#[test]
fn adv72_braintree_sandbox_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "braintree-sandbox-token",
        "sandbox_kp4qx7rm_\u{202E}sn5tb8vw_3yzkp4qx",
        "sandbox_kp4qx7rm_sn5tb8vw_3yzkp4qx",
    );
}

#[test]
fn adv72_braintree_sandbox_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "braintree-sandbox-token",
        "sandbox_kp4qx7rm_\u{202C}sn5tb8vw_3yzkp4qx",
        "sandbox_kp4qx7rm_sn5tb8vw_3yzkp4qx",
    );
}

#[test]
fn adv72_braintree_sandbox_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "braintree-sandbox-token",
        "sandbox_kp4qx7rm_\u{200E}sn5tb8vw_3yzkp4qx",
        "sandbox_kp4qx7rm_sn5tb8vw_3yzkp4qx",
    );
}

// =========================================================================
// 4. BRAZE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv72_braze_api_key_normal_must_fire() {
    assert_detector_fires(
        "braze-api-key",
        "BRAZE_API_KEY=7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_braze_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "braze-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv72_braze_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "braze-api-key",
        "BRAZE_API_KEY=7b3e5d8c-1a9f-4e2b\u{200B}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_braze_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "braze-api-key",
        "BRAZE_API_KEY=7b3e5d8c-1a9f-4e2b\u{00AD}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_braze_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "braze-api-key",
        "BRAZE_API_KEY=7b3e5d8c-1a9f-4e2b\u{200C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_braze_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "braze-api-key",
        "BRAZE_API_KEY=7b3e5d8c-1a9f-4e2b\u{200D}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_braze_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "braze-api-key",
        "BRAZE_API_KEY=7b3e5d8c-1a9f-4e2b\u{FEFF}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_braze_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "braze-api-key",
        "BRAZE_API_KEY=7b3e5d8c-1a9f-4e2b\u{2060}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_braze_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "braze-api-key",
        "BRAZE_API_KEY=7b3e5d8c-1a9f-4e2b\u{180E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_braze_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "braze-api-key",
        "BRAZE_API_KEY=7b3e5d8c-1a9f-4e2b\u{202E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_braze_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "braze-api-key",
        "BRAZE_API_KEY=7b3e5d8c-1a9f-4e2b\u{202C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_braze_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "braze-api-key",
        "BRAZE_API_KEY=7b3e5d8c-1a9f-4e2b\u{200E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

// =========================================================================
// 5. BRAZIL DADOSGOVBR API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv72_brazil_dadosgovbr_api_key_normal_must_fire() {
    assert_detector_fires(
        "brazil-dadosgovbr-api-key",
        "DADOS_GOV_API_KEY=7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_brazil_dadosgovbr_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "brazil-dadosgovbr-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv72_brazil_dadosgovbr_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "brazil-dadosgovbr-api-key",
        "DADOS_GOV_API_KEY=7b3e5d8c-1a9f-4e2b\u{200B}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_brazil_dadosgovbr_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "brazil-dadosgovbr-api-key",
        "DADOS_GOV_API_KEY=7b3e5d8c-1a9f-4e2b\u{00AD}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_brazil_dadosgovbr_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "brazil-dadosgovbr-api-key",
        "DADOS_GOV_API_KEY=7b3e5d8c-1a9f-4e2b\u{200C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_brazil_dadosgovbr_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "brazil-dadosgovbr-api-key",
        "DADOS_GOV_API_KEY=7b3e5d8c-1a9f-4e2b\u{200D}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_brazil_dadosgovbr_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "brazil-dadosgovbr-api-key",
        "DADOS_GOV_API_KEY=7b3e5d8c-1a9f-4e2b\u{FEFF}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_brazil_dadosgovbr_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "brazil-dadosgovbr-api-key",
        "DADOS_GOV_API_KEY=7b3e5d8c-1a9f-4e2b\u{2060}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_brazil_dadosgovbr_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "brazil-dadosgovbr-api-key",
        "DADOS_GOV_API_KEY=7b3e5d8c-1a9f-4e2b\u{180E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_brazil_dadosgovbr_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "brazil-dadosgovbr-api-key",
        "DADOS_GOV_API_KEY=7b3e5d8c-1a9f-4e2b\u{202E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_brazil_dadosgovbr_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "brazil-dadosgovbr-api-key",
        "DADOS_GOV_API_KEY=7b3e5d8c-1a9f-4e2b\u{202C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_brazil_dadosgovbr_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "brazil-dadosgovbr-api-key",
        "DADOS_GOV_API_KEY=7b3e5d8c-1a9f-4e2b\u{200E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

// =========================================================================
// 6. BREVO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv72_brevo_api_key_normal_must_fire() {
    assert_detector_fires(
        "brevo-api-key",
        "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_brevo_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "brevo-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv72_brevo_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "brevo-api-key",
        "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b\u{200B}7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_brevo_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "brevo-api-key",
        "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b\u{00AD}7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_brevo_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "brevo-api-key",
        "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b\u{200C}7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_brevo_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "brevo-api-key",
        "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b\u{200D}7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_brevo_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "brevo-api-key",
        "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b\u{FEFF}7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_brevo_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "brevo-api-key",
        "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b\u{2060}7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_brevo_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "brevo-api-key",
        "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b\u{180E}7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_brevo_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "brevo-api-key",
        "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b\u{202E}7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_brevo_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "brevo-api-key",
        "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b\u{202C}7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv72_brevo_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "brevo-api-key",
        "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b\u{200E}7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 7. BRIGHTCOVE API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv72_brightcove_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "brightcove-api-credentials",
        "brightcove_client_id=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b",
    );
}

#[test]
fn adv72_brightcove_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "brightcove-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv72_brightcove_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "brightcove-api-credentials",
        "brightcove_client_id=7b3e5d8c1a9f4e2b6c8d\u{200B}3a5e9f1b7c4d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b",
    );
}

#[test]
fn adv72_brightcove_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "brightcove-api-credentials",
        "brightcove_client_id=7b3e5d8c1a9f4e2b6c8d\u{00AD}3a5e9f1b7c4d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b",
    );
}

#[test]
fn adv72_brightcove_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "brightcove-api-credentials",
        "brightcove_client_id=7b3e5d8c1a9f4e2b6c8d\u{200C}3a5e9f1b7c4d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b",
    );
}

#[test]
fn adv72_brightcove_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "brightcove-api-credentials",
        "brightcove_client_id=7b3e5d8c1a9f4e2b6c8d\u{200D}3a5e9f1b7c4d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b",
    );
}

#[test]
fn adv72_brightcove_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "brightcove-api-credentials",
        "brightcove_client_id=7b3e5d8c1a9f4e2b6c8d\u{FEFF}3a5e9f1b7c4d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b",
    );
}

#[test]
fn adv72_brightcove_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "brightcove-api-credentials",
        "brightcove_client_id=7b3e5d8c1a9f4e2b6c8d\u{2060}3a5e9f1b7c4d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b",
    );
}

#[test]
fn adv72_brightcove_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "brightcove-api-credentials",
        "brightcove_client_id=7b3e5d8c1a9f4e2b6c8d\u{180E}3a5e9f1b7c4d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b",
    );
}

#[test]
fn adv72_brightcove_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "brightcove-api-credentials",
        "brightcove_client_id=7b3e5d8c1a9f4e2b6c8d\u{202E}3a5e9f1b7c4d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b",
    );
}

#[test]
fn adv72_brightcove_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "brightcove-api-credentials",
        "brightcove_client_id=7b3e5d8c1a9f4e2b6c8d\u{202C}3a5e9f1b7c4d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b",
    );
}

#[test]
fn adv72_brightcove_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "brightcove-api-credentials",
        "brightcove_client_id=7b3e5d8c1a9f4e2b6c8d\u{200E}3a5e9f1b7c4d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b",
    );
}

// =========================================================================
// 8. BRIGHTDATA CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv72_brightdata_credentials_normal_must_fire() {
    assert_detector_fires(
        "brightdata-credentials",
        "brightdata=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b",
    );
}

#[test]
fn adv72_brightdata_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "brightdata-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx7",
    );
}

#[test]
fn adv72_brightdata_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "brightdata-credentials",
        "brightdata=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200B}3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b",
    );
}

#[test]
fn adv72_brightdata_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "brightdata-credentials",
        "brightdata=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{00AD}3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b",
    );
}

#[test]
fn adv72_brightdata_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "brightdata-credentials",
        "brightdata=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200C}3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b",
    );
}

#[test]
fn adv72_brightdata_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "brightdata-credentials",
        "brightdata=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200D}3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b",
    );
}

#[test]
fn adv72_brightdata_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "brightdata-credentials",
        "brightdata=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{FEFF}3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b",
    );
}

#[test]
fn adv72_brightdata_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "brightdata-credentials",
        "brightdata=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{2060}3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b",
    );
}

#[test]
fn adv72_brightdata_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "brightdata-credentials",
        "brightdata=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{180E}3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b",
    );
}

#[test]
fn adv72_brightdata_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "brightdata-credentials",
        "brightdata=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{202E}3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b",
    );
}

#[test]
fn adv72_brightdata_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "brightdata-credentials",
        "brightdata=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{202C}3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b",
    );
}

#[test]
fn adv72_brightdata_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "brightdata-credentials",
        "brightdata=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200E}3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b7c4d3a5e9f1b",
    );
}

// =========================================================================
// 9. BRIGHTSPACE API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv72_brightspace_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "brightspace-api-credentials",
        "brightspace_app_id=Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv72_brightspace_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "brightspace-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv72_brightspace_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "brightspace-api-credentials",
        "brightspace_app_id=Kp4Qx7Rm2S\u{200B}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv72_brightspace_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "brightspace-api-credentials",
        "brightspace_app_id=Kp4Qx7Rm2S\u{00AD}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv72_brightspace_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "brightspace-api-credentials",
        "brightspace_app_id=Kp4Qx7Rm2S\u{200C}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv72_brightspace_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "brightspace-api-credentials",
        "brightspace_app_id=Kp4Qx7Rm2S\u{200D}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv72_brightspace_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "brightspace-api-credentials",
        "brightspace_app_id=Kp4Qx7Rm2S\u{FEFF}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv72_brightspace_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "brightspace-api-credentials",
        "brightspace_app_id=Kp4Qx7Rm2S\u{2060}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv72_brightspace_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "brightspace-api-credentials",
        "brightspace_app_id=Kp4Qx7Rm2S\u{180E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv72_brightspace_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "brightspace-api-credentials",
        "brightspace_app_id=Kp4Qx7Rm2S\u{202E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv72_brightspace_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "brightspace-api-credentials",
        "brightspace_app_id=Kp4Qx7Rm2S\u{202C}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv72_brightspace_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "brightspace-api-credentials",
        "brightspace_app_id=Kp4Qx7Rm2S\u{200E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 10. BUDIBASE CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv72_budibase_credentials_normal_must_fire() {
    assert_detector_fires(
        "budibase-credentials",
        "BUDIBASE_INTERNAL_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv72_budibase_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "budibase-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv72_budibase_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "budibase-credentials",
        "BUDIBASE_INTERNAL_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv72_budibase_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "budibase-credentials",
        "BUDIBASE_INTERNAL_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv72_budibase_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "budibase-credentials",
        "BUDIBASE_INTERNAL_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv72_budibase_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "budibase-credentials",
        "BUDIBASE_INTERNAL_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv72_budibase_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "budibase-credentials",
        "BUDIBASE_INTERNAL_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv72_budibase_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "budibase-credentials",
        "BUDIBASE_INTERNAL_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv72_budibase_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "budibase-credentials",
        "BUDIBASE_INTERNAL_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv72_budibase_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "budibase-credentials",
        "BUDIBASE_INTERNAL_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv72_budibase_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "budibase-credentials",
        "BUDIBASE_INTERNAL_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv72_budibase_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "budibase-credentials",
        "BUDIBASE_INTERNAL_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}
