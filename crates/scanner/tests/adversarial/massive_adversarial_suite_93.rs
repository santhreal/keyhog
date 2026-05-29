//! Part 93 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates graph, gravity, greynoise, groq, gumroad, gusto, hanko, hanko, harbor, hashicorp detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. GRAPH DEPLOY KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv93_graph_deploy_key_normal_must_fire() {
    assert_detector_fires(
        "graph-deploy-key",
        "GRAPH deploy_key=37cb496acf2f25e15b2485167eab3182",
        "37cb496acf2f25e15b2485167eab3182",
    );
}

#[test]
fn adv93_graph_deploy_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "graph-deploy-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv93_graph_deploy_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "graph-deploy-key",
        "GRAPH deploy_key=37cb496acf2f25e1\u{200B}5b2485167eab3182",
        "37cb496acf2f25e15b2485167eab3182",
    );
}

#[test]
fn adv93_graph_deploy_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "graph-deploy-key",
        "GRAPH deploy_key=37cb496acf2f25e1\u{00AD}5b2485167eab3182",
        "37cb496acf2f25e15b2485167eab3182",
    );
}

#[test]
fn adv93_graph_deploy_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "graph-deploy-key",
        "GRAPH deploy_key=37cb496acf2f25e1\u{200C}5b2485167eab3182",
        "37cb496acf2f25e15b2485167eab3182",
    );
}

#[test]
fn adv93_graph_deploy_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "graph-deploy-key",
        "GRAPH deploy_key=37cb496acf2f25e1\u{200D}5b2485167eab3182",
        "37cb496acf2f25e15b2485167eab3182",
    );
}

#[test]
fn adv93_graph_deploy_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "graph-deploy-key",
        "GRAPH deploy_key=37cb496acf2f25e1\u{FEFF}5b2485167eab3182",
        "37cb496acf2f25e15b2485167eab3182",
    );
}

#[test]
fn adv93_graph_deploy_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "graph-deploy-key",
        "GRAPH deploy_key=37cb496acf2f25e1\u{2060}5b2485167eab3182",
        "37cb496acf2f25e15b2485167eab3182",
    );
}

#[test]
fn adv93_graph_deploy_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "graph-deploy-key",
        "GRAPH deploy_key=37cb496acf2f25e1\u{180E}5b2485167eab3182",
        "37cb496acf2f25e15b2485167eab3182",
    );
}

#[test]
fn adv93_graph_deploy_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "graph-deploy-key",
        "GRAPH deploy_key=37cb496acf2f25e1\u{202E}5b2485167eab3182",
        "37cb496acf2f25e15b2485167eab3182",
    );
}

#[test]
fn adv93_graph_deploy_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "graph-deploy-key",
        "GRAPH deploy_key=37cb496acf2f25e1\u{202C}5b2485167eab3182",
        "37cb496acf2f25e15b2485167eab3182",
    );
}

#[test]
fn adv93_graph_deploy_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "graph-deploy-key",
        "GRAPH deploy_key=37cb496acf2f25e1\u{200E}5b2485167eab3182",
        "37cb496acf2f25e15b2485167eab3182",
    );
}

// =========================================================================
// 2. GRAVITY FORMS REST API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv93_gravity_forms_rest_api_key_normal_must_fire() {
    assert_detector_fires(
        "gravity-forms-rest-api-key",
        "GRAVITY FORMS api_key 963950e3ed2e3dc49d5740982bac6a94",
        "963950e3ed2e3dc49d5740982bac6a94",
    );
}

#[test]
fn adv93_gravity_forms_rest_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "gravity-forms-rest-api-key",
        "dummyITY FORMS api_key xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv93_gravity_forms_rest_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "gravity-forms-rest-api-key",
        "GRAVITY FORMS api_key 963950e3ed2e3dc4\u{200B}9d5740982bac6a94",
        "963950e3ed2e3dc49d5740982bac6a94",
    );
}

#[test]
fn adv93_gravity_forms_rest_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "gravity-forms-rest-api-key",
        "GRAVITY FORMS api_key 963950e3ed2e3dc4\u{00AD}9d5740982bac6a94",
        "963950e3ed2e3dc49d5740982bac6a94",
    );
}

#[test]
fn adv93_gravity_forms_rest_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "gravity-forms-rest-api-key",
        "GRAVITY FORMS api_key 963950e3ed2e3dc4\u{200C}9d5740982bac6a94",
        "963950e3ed2e3dc49d5740982bac6a94",
    );
}

#[test]
fn adv93_gravity_forms_rest_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "gravity-forms-rest-api-key",
        "GRAVITY FORMS api_key 963950e3ed2e3dc4\u{200D}9d5740982bac6a94",
        "963950e3ed2e3dc49d5740982bac6a94",
    );
}

#[test]
fn adv93_gravity_forms_rest_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "gravity-forms-rest-api-key",
        "GRAVITY FORMS api_key 963950e3ed2e3dc4\u{FEFF}9d5740982bac6a94",
        "963950e3ed2e3dc49d5740982bac6a94",
    );
}

#[test]
fn adv93_gravity_forms_rest_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "gravity-forms-rest-api-key",
        "GRAVITY FORMS api_key 963950e3ed2e3dc4\u{2060}9d5740982bac6a94",
        "963950e3ed2e3dc49d5740982bac6a94",
    );
}

#[test]
fn adv93_gravity_forms_rest_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "gravity-forms-rest-api-key",
        "GRAVITY FORMS api_key 963950e3ed2e3dc4\u{180E}9d5740982bac6a94",
        "963950e3ed2e3dc49d5740982bac6a94",
    );
}

#[test]
fn adv93_gravity_forms_rest_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "gravity-forms-rest-api-key",
        "GRAVITY FORMS api_key 963950e3ed2e3dc4\u{202E}9d5740982bac6a94",
        "963950e3ed2e3dc49d5740982bac6a94",
    );
}

#[test]
fn adv93_gravity_forms_rest_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "gravity-forms-rest-api-key",
        "GRAVITY FORMS api_key 963950e3ed2e3dc4\u{202C}9d5740982bac6a94",
        "963950e3ed2e3dc49d5740982bac6a94",
    );
}

#[test]
fn adv93_gravity_forms_rest_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "gravity-forms-rest-api-key",
        "GRAVITY FORMS api_key 963950e3ed2e3dc4\u{200E}9d5740982bac6a94",
        "963950e3ed2e3dc49d5740982bac6a94",
    );
}

// =========================================================================
// 3. GREYNOISE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv93_greynoise_api_key_normal_must_fire() {
    assert_detector_fires(
        "greynoise-api-key",
        "GREYNOISE=_4XCZ6jfqICQrr43YH0c",
        "_4XCZ6jfqICQrr43YH0c",
    );
}

#[test]
fn adv93_greynoise_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "greynoise-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv93_greynoise_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "greynoise-api-key",
        "GREYNOISE=_4XCZ6jfqI\u{200B}CQrr43YH0c",
        "_4XCZ6jfqICQrr43YH0c",
    );
}

#[test]
fn adv93_greynoise_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "greynoise-api-key",
        "GREYNOISE=_4XCZ6jfqI\u{00AD}CQrr43YH0c",
        "_4XCZ6jfqICQrr43YH0c",
    );
}

#[test]
fn adv93_greynoise_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "greynoise-api-key",
        "GREYNOISE=_4XCZ6jfqI\u{200C}CQrr43YH0c",
        "_4XCZ6jfqICQrr43YH0c",
    );
}

#[test]
fn adv93_greynoise_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "greynoise-api-key",
        "GREYNOISE=_4XCZ6jfqI\u{200D}CQrr43YH0c",
        "_4XCZ6jfqICQrr43YH0c",
    );
}

#[test]
fn adv93_greynoise_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "greynoise-api-key",
        "GREYNOISE=_4XCZ6jfqI\u{FEFF}CQrr43YH0c",
        "_4XCZ6jfqICQrr43YH0c",
    );
}

#[test]
fn adv93_greynoise_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "greynoise-api-key",
        "GREYNOISE=_4XCZ6jfqI\u{2060}CQrr43YH0c",
        "_4XCZ6jfqICQrr43YH0c",
    );
}

#[test]
fn adv93_greynoise_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "greynoise-api-key",
        "GREYNOISE=_4XCZ6jfqI\u{180E}CQrr43YH0c",
        "_4XCZ6jfqICQrr43YH0c",
    );
}

#[test]
fn adv93_greynoise_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "greynoise-api-key",
        "GREYNOISE=_4XCZ6jfqI\u{202E}CQrr43YH0c",
        "_4XCZ6jfqICQrr43YH0c",
    );
}

#[test]
fn adv93_greynoise_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "greynoise-api-key",
        "GREYNOISE=_4XCZ6jfqI\u{202C}CQrr43YH0c",
        "_4XCZ6jfqICQrr43YH0c",
    );
}

#[test]
fn adv93_greynoise_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "greynoise-api-key",
        "GREYNOISE=_4XCZ6jfqI\u{200E}CQrr43YH0c",
        "_4XCZ6jfqICQrr43YH0c",
    );
}

// =========================================================================
// 4. GROQ API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv93_groq_api_key_normal_must_fire() {
    assert_detector_fires(
        "groq-api-key",
        "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",
        "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",
    );
}

#[test]
fn adv93_groq_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "groq-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv93_groq_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "groq-api-key",
        "gsk_nRwoCiIvJaS7sS6gRsJsSEJh\u{200B}tMxhhvfTfsnBlOvkJChBwiTw7Zjn",
        "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",
    );
}

#[test]
fn adv93_groq_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "groq-api-key",
        "gsk_nRwoCiIvJaS7sS6gRsJsSEJh\u{00AD}tMxhhvfTfsnBlOvkJChBwiTw7Zjn",
        "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",
    );
}

#[test]
fn adv93_groq_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "groq-api-key",
        "gsk_nRwoCiIvJaS7sS6gRsJsSEJh\u{200C}tMxhhvfTfsnBlOvkJChBwiTw7Zjn",
        "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",
    );
}

#[test]
fn adv93_groq_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "groq-api-key",
        "gsk_nRwoCiIvJaS7sS6gRsJsSEJh\u{200D}tMxhhvfTfsnBlOvkJChBwiTw7Zjn",
        "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",
    );
}

#[test]
fn adv93_groq_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "groq-api-key",
        "gsk_nRwoCiIvJaS7sS6gRsJsSEJh\u{FEFF}tMxhhvfTfsnBlOvkJChBwiTw7Zjn",
        "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",
    );
}

#[test]
fn adv93_groq_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "groq-api-key",
        "gsk_nRwoCiIvJaS7sS6gRsJsSEJh\u{2060}tMxhhvfTfsnBlOvkJChBwiTw7Zjn",
        "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",
    );
}

#[test]
fn adv93_groq_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "groq-api-key",
        "gsk_nRwoCiIvJaS7sS6gRsJsSEJh\u{180E}tMxhhvfTfsnBlOvkJChBwiTw7Zjn",
        "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",
    );
}

#[test]
fn adv93_groq_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "groq-api-key",
        "gsk_nRwoCiIvJaS7sS6gRsJsSEJh\u{202E}tMxhhvfTfsnBlOvkJChBwiTw7Zjn",
        "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",
    );
}

#[test]
fn adv93_groq_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "groq-api-key",
        "gsk_nRwoCiIvJaS7sS6gRsJsSEJh\u{202C}tMxhhvfTfsnBlOvkJChBwiTw7Zjn",
        "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",
    );
}

#[test]
fn adv93_groq_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "groq-api-key",
        "gsk_nRwoCiIvJaS7sS6gRsJsSEJh\u{200E}tMxhhvfTfsnBlOvkJChBwiTw7Zjn",
        "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",
    );
}

// =========================================================================
// 5. GUMROAD API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv93_gumroad_api_key_normal_must_fire() {
    assert_detector_fires(
        "gumroad-api-key",
        "gumroad access_token=b2963950e3ed2e3dc49d5740982bac6a94",
        "b2963950e3ed2e3dc49d5740982bac6a94",
    );
}

#[test]
fn adv93_gumroad_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "gumroad-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv93_gumroad_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "gumroad-api-key",
        "gumroad access_token=b2963950e3ed2e3dc\u{200B}49d5740982bac6a94",
        "b2963950e3ed2e3dc49d5740982bac6a94",
    );
}

#[test]
fn adv93_gumroad_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "gumroad-api-key",
        "gumroad access_token=b2963950e3ed2e3dc\u{00AD}49d5740982bac6a94",
        "b2963950e3ed2e3dc49d5740982bac6a94",
    );
}

#[test]
fn adv93_gumroad_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "gumroad-api-key",
        "gumroad access_token=b2963950e3ed2e3dc\u{200C}49d5740982bac6a94",
        "b2963950e3ed2e3dc49d5740982bac6a94",
    );
}

#[test]
fn adv93_gumroad_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "gumroad-api-key",
        "gumroad access_token=b2963950e3ed2e3dc\u{200D}49d5740982bac6a94",
        "b2963950e3ed2e3dc49d5740982bac6a94",
    );
}

#[test]
fn adv93_gumroad_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "gumroad-api-key",
        "gumroad access_token=b2963950e3ed2e3dc\u{FEFF}49d5740982bac6a94",
        "b2963950e3ed2e3dc49d5740982bac6a94",
    );
}

#[test]
fn adv93_gumroad_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "gumroad-api-key",
        "gumroad access_token=b2963950e3ed2e3dc\u{2060}49d5740982bac6a94",
        "b2963950e3ed2e3dc49d5740982bac6a94",
    );
}

#[test]
fn adv93_gumroad_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "gumroad-api-key",
        "gumroad access_token=b2963950e3ed2e3dc\u{180E}49d5740982bac6a94",
        "b2963950e3ed2e3dc49d5740982bac6a94",
    );
}

#[test]
fn adv93_gumroad_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "gumroad-api-key",
        "gumroad access_token=b2963950e3ed2e3dc\u{202E}49d5740982bac6a94",
        "b2963950e3ed2e3dc49d5740982bac6a94",
    );
}

#[test]
fn adv93_gumroad_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "gumroad-api-key",
        "gumroad access_token=b2963950e3ed2e3dc\u{202C}49d5740982bac6a94",
        "b2963950e3ed2e3dc49d5740982bac6a94",
    );
}

#[test]
fn adv93_gumroad_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "gumroad-api-key",
        "gumroad access_token=b2963950e3ed2e3dc\u{200E}49d5740982bac6a94",
        "b2963950e3ed2e3dc49d5740982bac6a94",
    );
}

// =========================================================================
// 6. GUSTO API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv93_gusto_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "gusto-api-credentials",
        "GUSTO_CLIENT_ID=81c7e93a50e1ea561882a182ab6b82f7809300bf",
        "81c7e93a50e1ea561882a182ab6b82f7809300bf",
    );
}

#[test]
fn adv93_gusto_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "gusto-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv93_gusto_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "gusto-api-credentials",
        "GUSTO_CLIENT_ID=81c7e93a50e1ea561882\u{200B}a182ab6b82f7809300bf",
        "81c7e93a50e1ea561882a182ab6b82f7809300bf",
    );
}

#[test]
fn adv93_gusto_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "gusto-api-credentials",
        "GUSTO_CLIENT_ID=81c7e93a50e1ea561882\u{00AD}a182ab6b82f7809300bf",
        "81c7e93a50e1ea561882a182ab6b82f7809300bf",
    );
}

#[test]
fn adv93_gusto_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "gusto-api-credentials",
        "GUSTO_CLIENT_ID=81c7e93a50e1ea561882\u{200C}a182ab6b82f7809300bf",
        "81c7e93a50e1ea561882a182ab6b82f7809300bf",
    );
}

#[test]
fn adv93_gusto_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "gusto-api-credentials",
        "GUSTO_CLIENT_ID=81c7e93a50e1ea561882\u{200D}a182ab6b82f7809300bf",
        "81c7e93a50e1ea561882a182ab6b82f7809300bf",
    );
}

#[test]
fn adv93_gusto_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "gusto-api-credentials",
        "GUSTO_CLIENT_ID=81c7e93a50e1ea561882\u{FEFF}a182ab6b82f7809300bf",
        "81c7e93a50e1ea561882a182ab6b82f7809300bf",
    );
}

#[test]
fn adv93_gusto_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "gusto-api-credentials",
        "GUSTO_CLIENT_ID=81c7e93a50e1ea561882\u{2060}a182ab6b82f7809300bf",
        "81c7e93a50e1ea561882a182ab6b82f7809300bf",
    );
}

#[test]
fn adv93_gusto_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "gusto-api-credentials",
        "GUSTO_CLIENT_ID=81c7e93a50e1ea561882\u{180E}a182ab6b82f7809300bf",
        "81c7e93a50e1ea561882a182ab6b82f7809300bf",
    );
}

#[test]
fn adv93_gusto_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "gusto-api-credentials",
        "GUSTO_CLIENT_ID=81c7e93a50e1ea561882\u{202E}a182ab6b82f7809300bf",
        "81c7e93a50e1ea561882a182ab6b82f7809300bf",
    );
}

#[test]
fn adv93_gusto_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "gusto-api-credentials",
        "GUSTO_CLIENT_ID=81c7e93a50e1ea561882\u{202C}a182ab6b82f7809300bf",
        "81c7e93a50e1ea561882a182ab6b82f7809300bf",
    );
}

#[test]
fn adv93_gusto_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "gusto-api-credentials",
        "GUSTO_CLIENT_ID=81c7e93a50e1ea561882\u{200E}a182ab6b82f7809300bf",
        "81c7e93a50e1ea561882a182ab6b82f7809300bf",
    );
}

// =========================================================================
// 7. HANKO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv93_hanko_api_key_normal_must_fire() {
    assert_detector_fires(
        "hanko-api-key",
        "HANKO_API_KEY=QXjK-nCvdgB1eKnjRTfl",
        "QXjK-nCvdgB1eKnjRTfl",
    );
}

#[test]
fn adv93_hanko_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hanko-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv93_hanko_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hanko-api-key",
        "HANKO_API_KEY=QXjK-nCvdg\u{200B}B1eKnjRTfl",
        "QXjK-nCvdgB1eKnjRTfl",
    );
}

#[test]
fn adv93_hanko_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hanko-api-key",
        "HANKO_API_KEY=QXjK-nCvdg\u{00AD}B1eKnjRTfl",
        "QXjK-nCvdgB1eKnjRTfl",
    );
}

#[test]
fn adv93_hanko_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "hanko-api-key",
        "HANKO_API_KEY=QXjK-nCvdg\u{200C}B1eKnjRTfl",
        "QXjK-nCvdgB1eKnjRTfl",
    );
}

#[test]
fn adv93_hanko_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "hanko-api-key",
        "HANKO_API_KEY=QXjK-nCvdg\u{200D}B1eKnjRTfl",
        "QXjK-nCvdgB1eKnjRTfl",
    );
}

#[test]
fn adv93_hanko_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "hanko-api-key",
        "HANKO_API_KEY=QXjK-nCvdg\u{FEFF}B1eKnjRTfl",
        "QXjK-nCvdgB1eKnjRTfl",
    );
}

#[test]
fn adv93_hanko_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "hanko-api-key",
        "HANKO_API_KEY=QXjK-nCvdg\u{2060}B1eKnjRTfl",
        "QXjK-nCvdgB1eKnjRTfl",
    );
}

#[test]
fn adv93_hanko_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "hanko-api-key",
        "HANKO_API_KEY=QXjK-nCvdg\u{180E}B1eKnjRTfl",
        "QXjK-nCvdgB1eKnjRTfl",
    );
}

#[test]
fn adv93_hanko_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "hanko-api-key",
        "HANKO_API_KEY=QXjK-nCvdg\u{202E}B1eKnjRTfl",
        "QXjK-nCvdgB1eKnjRTfl",
    );
}

#[test]
fn adv93_hanko_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "hanko-api-key",
        "HANKO_API_KEY=QXjK-nCvdg\u{202C}B1eKnjRTfl",
        "QXjK-nCvdgB1eKnjRTfl",
    );
}

#[test]
fn adv93_hanko_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "hanko-api-key",
        "HANKO_API_KEY=QXjK-nCvdg\u{200E}B1eKnjRTfl",
        "QXjK-nCvdgB1eKnjRTfl",
    );
}

// =========================================================================
// 8. HANKO PASSKEY CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv93_hanko_passkey_credentials_normal_must_fire() {
    assert_detector_fires(
        "hanko-passkey-credentials",
        "hanko_w5rqbu3NdOSohlPl0gstZPf_n6SdF",
        "hanko_w5rqbu3NdOSohlPl0gstZPf_n6SdF",
    );
}

#[test]
fn adv93_hanko_passkey_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hanko-passkey-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv93_hanko_passkey_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hanko-passkey-credentials",
        "hanko_w5rqbu3NdOS\u{200B}ohlPl0gstZPf_n6SdF",
        "hanko_w5rqbu3NdOSohlPl0gstZPf_n6SdF",
    );
}

#[test]
fn adv93_hanko_passkey_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hanko-passkey-credentials",
        "hanko_w5rqbu3NdOS\u{00AD}ohlPl0gstZPf_n6SdF",
        "hanko_w5rqbu3NdOSohlPl0gstZPf_n6SdF",
    );
}

#[test]
fn adv93_hanko_passkey_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "hanko-passkey-credentials",
        "hanko_w5rqbu3NdOS\u{200C}ohlPl0gstZPf_n6SdF",
        "hanko_w5rqbu3NdOSohlPl0gstZPf_n6SdF",
    );
}

#[test]
fn adv93_hanko_passkey_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "hanko-passkey-credentials",
        "hanko_w5rqbu3NdOS\u{200D}ohlPl0gstZPf_n6SdF",
        "hanko_w5rqbu3NdOSohlPl0gstZPf_n6SdF",
    );
}

#[test]
fn adv93_hanko_passkey_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "hanko-passkey-credentials",
        "hanko_w5rqbu3NdOS\u{FEFF}ohlPl0gstZPf_n6SdF",
        "hanko_w5rqbu3NdOSohlPl0gstZPf_n6SdF",
    );
}

#[test]
fn adv93_hanko_passkey_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "hanko-passkey-credentials",
        "hanko_w5rqbu3NdOS\u{2060}ohlPl0gstZPf_n6SdF",
        "hanko_w5rqbu3NdOSohlPl0gstZPf_n6SdF",
    );
}

#[test]
fn adv93_hanko_passkey_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "hanko-passkey-credentials",
        "hanko_w5rqbu3NdOS\u{180E}ohlPl0gstZPf_n6SdF",
        "hanko_w5rqbu3NdOSohlPl0gstZPf_n6SdF",
    );
}

#[test]
fn adv93_hanko_passkey_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "hanko-passkey-credentials",
        "hanko_w5rqbu3NdOS\u{202E}ohlPl0gstZPf_n6SdF",
        "hanko_w5rqbu3NdOSohlPl0gstZPf_n6SdF",
    );
}

#[test]
fn adv93_hanko_passkey_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "hanko-passkey-credentials",
        "hanko_w5rqbu3NdOS\u{202C}ohlPl0gstZPf_n6SdF",
        "hanko_w5rqbu3NdOSohlPl0gstZPf_n6SdF",
    );
}

#[test]
fn adv93_hanko_passkey_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "hanko-passkey-credentials",
        "hanko_w5rqbu3NdOS\u{200E}ohlPl0gstZPf_n6SdF",
        "hanko_w5rqbu3NdOSohlPl0gstZPf_n6SdF",
    );
}

// =========================================================================
// 9. HARBOR ROBOT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv93_harbor_robot_credentials_normal_must_fire() {
    assert_detector_fires(
        "harbor-robot-credentials",
        "robot_password=AyRAn1jcr9OMzmqXYd0OfTuVUz3cUtGgFGTsMvK15lkcvd6PTCI-",
        "AyRAn1jcr9OMzmqXYd0OfTuVUz3cUtGgFGTsMvK15lkcvd6PTCI-",
    );
}

#[test]
fn adv93_harbor_robot_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "harbor-robot-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv93_harbor_robot_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "harbor-robot-credentials",
        "robot_password=AyRAn1jcr9OMzmqXYd0OfTuVUz\u{200B}3cUtGgFGTsMvK15lkcvd6PTCI-",
        "AyRAn1jcr9OMzmqXYd0OfTuVUz3cUtGgFGTsMvK15lkcvd6PTCI-",
    );
}

#[test]
fn adv93_harbor_robot_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "harbor-robot-credentials",
        "robot_password=AyRAn1jcr9OMzmqXYd0OfTuVUz\u{00AD}3cUtGgFGTsMvK15lkcvd6PTCI-",
        "AyRAn1jcr9OMzmqXYd0OfTuVUz3cUtGgFGTsMvK15lkcvd6PTCI-",
    );
}

#[test]
fn adv93_harbor_robot_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "harbor-robot-credentials",
        "robot_password=AyRAn1jcr9OMzmqXYd0OfTuVUz\u{200C}3cUtGgFGTsMvK15lkcvd6PTCI-",
        "AyRAn1jcr9OMzmqXYd0OfTuVUz3cUtGgFGTsMvK15lkcvd6PTCI-",
    );
}

#[test]
fn adv93_harbor_robot_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "harbor-robot-credentials",
        "robot_password=AyRAn1jcr9OMzmqXYd0OfTuVUz\u{200D}3cUtGgFGTsMvK15lkcvd6PTCI-",
        "AyRAn1jcr9OMzmqXYd0OfTuVUz3cUtGgFGTsMvK15lkcvd6PTCI-",
    );
}

#[test]
fn adv93_harbor_robot_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "harbor-robot-credentials",
        "robot_password=AyRAn1jcr9OMzmqXYd0OfTuVUz\u{FEFF}3cUtGgFGTsMvK15lkcvd6PTCI-",
        "AyRAn1jcr9OMzmqXYd0OfTuVUz3cUtGgFGTsMvK15lkcvd6PTCI-",
    );
}

#[test]
fn adv93_harbor_robot_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "harbor-robot-credentials",
        "robot_password=AyRAn1jcr9OMzmqXYd0OfTuVUz\u{2060}3cUtGgFGTsMvK15lkcvd6PTCI-",
        "AyRAn1jcr9OMzmqXYd0OfTuVUz3cUtGgFGTsMvK15lkcvd6PTCI-",
    );
}

#[test]
fn adv93_harbor_robot_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "harbor-robot-credentials",
        "robot_password=AyRAn1jcr9OMzmqXYd0OfTuVUz\u{180E}3cUtGgFGTsMvK15lkcvd6PTCI-",
        "AyRAn1jcr9OMzmqXYd0OfTuVUz3cUtGgFGTsMvK15lkcvd6PTCI-",
    );
}

#[test]
fn adv93_harbor_robot_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "harbor-robot-credentials",
        "robot_password=AyRAn1jcr9OMzmqXYd0OfTuVUz\u{202E}3cUtGgFGTsMvK15lkcvd6PTCI-",
        "AyRAn1jcr9OMzmqXYd0OfTuVUz3cUtGgFGTsMvK15lkcvd6PTCI-",
    );
}

#[test]
fn adv93_harbor_robot_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "harbor-robot-credentials",
        "robot_password=AyRAn1jcr9OMzmqXYd0OfTuVUz\u{202C}3cUtGgFGTsMvK15lkcvd6PTCI-",
        "AyRAn1jcr9OMzmqXYd0OfTuVUz3cUtGgFGTsMvK15lkcvd6PTCI-",
    );
}

#[test]
fn adv93_harbor_robot_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "harbor-robot-credentials",
        "robot_password=AyRAn1jcr9OMzmqXYd0OfTuVUz\u{200E}3cUtGgFGTsMvK15lkcvd6PTCI-",
        "AyRAn1jcr9OMzmqXYd0OfTuVUz3cUtGgFGTsMvK15lkcvd6PTCI-",
    );
}

// =========================================================================
// 10. HASHICORP VAULT APPROLE CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv93_hashicorp_vault_approle_credentials_normal_must_fire() {
    assert_detector_fires(
        "hashicorp-vault-approle-credentials",
        "VAULT_ROLE_ID=6994e225-eb46-e3ed-0312-0e0c10f2b2b7",
        "6994e225-eb46-e3ed-0312-0e0c10f2b2b7",
    );
}

#[test]
fn adv93_hashicorp_vault_approle_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hashicorp-vault-approle-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv93_hashicorp_vault_approle_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hashicorp-vault-approle-credentials",
        "VAULT_ROLE_ID=6994e225-eb46-e3ed\u{200B}-0312-0e0c10f2b2b7",
        "6994e225-eb46-e3ed-0312-0e0c10f2b2b7",
    );
}

#[test]
fn adv93_hashicorp_vault_approle_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hashicorp-vault-approle-credentials",
        "VAULT_ROLE_ID=6994e225-eb46-e3ed\u{00AD}-0312-0e0c10f2b2b7",
        "6994e225-eb46-e3ed-0312-0e0c10f2b2b7",
    );
}

#[test]
fn adv93_hashicorp_vault_approle_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "hashicorp-vault-approle-credentials",
        "VAULT_ROLE_ID=6994e225-eb46-e3ed\u{200C}-0312-0e0c10f2b2b7",
        "6994e225-eb46-e3ed-0312-0e0c10f2b2b7",
    );
}

#[test]
fn adv93_hashicorp_vault_approle_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "hashicorp-vault-approle-credentials",
        "VAULT_ROLE_ID=6994e225-eb46-e3ed\u{200D}-0312-0e0c10f2b2b7",
        "6994e225-eb46-e3ed-0312-0e0c10f2b2b7",
    );
}

#[test]
fn adv93_hashicorp_vault_approle_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "hashicorp-vault-approle-credentials",
        "VAULT_ROLE_ID=6994e225-eb46-e3ed\u{FEFF}-0312-0e0c10f2b2b7",
        "6994e225-eb46-e3ed-0312-0e0c10f2b2b7",
    );
}

#[test]
fn adv93_hashicorp_vault_approle_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "hashicorp-vault-approle-credentials",
        "VAULT_ROLE_ID=6994e225-eb46-e3ed\u{2060}-0312-0e0c10f2b2b7",
        "6994e225-eb46-e3ed-0312-0e0c10f2b2b7",
    );
}

#[test]
fn adv93_hashicorp_vault_approle_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "hashicorp-vault-approle-credentials",
        "VAULT_ROLE_ID=6994e225-eb46-e3ed\u{180E}-0312-0e0c10f2b2b7",
        "6994e225-eb46-e3ed-0312-0e0c10f2b2b7",
    );
}

#[test]
fn adv93_hashicorp_vault_approle_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "hashicorp-vault-approle-credentials",
        "VAULT_ROLE_ID=6994e225-eb46-e3ed\u{202E}-0312-0e0c10f2b2b7",
        "6994e225-eb46-e3ed-0312-0e0c10f2b2b7",
    );
}

#[test]
fn adv93_hashicorp_vault_approle_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "hashicorp-vault-approle-credentials",
        "VAULT_ROLE_ID=6994e225-eb46-e3ed\u{202C}-0312-0e0c10f2b2b7",
        "6994e225-eb46-e3ed-0312-0e0c10f2b2b7",
    );
}

#[test]
fn adv93_hashicorp_vault_approle_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "hashicorp-vault-approle-credentials",
        "VAULT_ROLE_ID=6994e225-eb46-e3ed\u{200E}-0312-0e0c10f2b2b7",
        "6994e225-eb46-e3ed-0312-0e0c10f2b2b7",
    );
}


