//! Part 49 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates openrouter, openweathermap, opsgenie, opsgenie, optimism, optimizely, oracle, oracle, ovh, oxylabs detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. OPENROUTER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv49_openrouter_api_key_normal_must_fire() {
    assert_detector_fires(
        "openrouter-api-key",
        "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",
        "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",
    );
}

#[test]
fn adv49_openrouter_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "openrouter-api-key",
        "dummyr-v1-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv49_openrouter_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "openrouter-api-key",
        "sk-or-v1-7b3e5d8c1a9f4e2b6c8d3a5e9f1\u{200B}b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "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",
    );
}

#[test]
fn adv49_openrouter_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "openrouter-api-key",
        "sk-or-v1-7b3e5d8c1a9f4e2b6c8d3a5e9f1\u{00AD}b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "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",
    );
}

// =========================================================================
// 2. OPENWEATHERMAP API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv49_openweathermap_api_key_normal_must_fire() {
    assert_detector_fires(
        "openweathermap-api-key",
        "OPENWEATHERMAP_API_KEY=c0ab6abfd5091fb4abc882544f009965",
        "c0ab6abfd5091fb4abc882544f009965",
    );
}

#[test]
fn adv49_openweathermap_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "openweathermap-api-key",
        "dummy_prefix_0 =xxxb6abfd5091fb4abc882544f009965",
    );
}

#[test]
fn adv49_openweathermap_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "openweathermap-api-key",
        "OPENWEATHERMAP_API_KEY=c0ab6abfd5091fb4\u{200B}abc882544f009965",
        "c0ab6abfd5091fb4abc882544f009965",
    );
}

#[test]
fn adv49_openweathermap_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "openweathermap-api-key",
        "OPENWEATHERMAP_API_KEY=c0ab6abfd5091fb4\u{00AD}abc882544f009965",
        "c0ab6abfd5091fb4abc882544f009965",
    );
}

// =========================================================================
// 3. OPSGENIE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv49_opsgenie_api_key_normal_must_fire() {
    assert_detector_fires(
        "opsgenie-api-key",
        "opsgenie=6b15696d-bb3e-5040-215f-e28bb6ac69a4",
        "6b15696d-bb3e-5040-215f-e28bb6ac69a4",
    );
}

#[test]
fn adv49_opsgenie_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "opsgenie-api-key",
        "dummy_prefix_0 =xxx5696d-bb3e-5040-215f-e28bb6ac69a4",
    );
}

#[test]
fn adv49_opsgenie_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "opsgenie-api-key",
        "opsgenie=6b15696d-bb3e-5040\u{200B}-215f-e28bb6ac69a4",
        "6b15696d-bb3e-5040-215f-e28bb6ac69a4",
    );
}

#[test]
fn adv49_opsgenie_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "opsgenie-api-key",
        "opsgenie=6b15696d-bb3e-5040\u{00AD}-215f-e28bb6ac69a4",
        "6b15696d-bb3e-5040-215f-e28bb6ac69a4",
    );
}

// =========================================================================
// 4. OPSGENIE HEARTBEAT API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv49_opsgenie_heartbeat_api_key_normal_must_fire() {
    assert_detector_fires(
        "opsgenie-heartbeat-api-key",
        "OPSGENIE_HEARTBEAT=740abf96-f0bb-5397-0c19-8650db0db039",
        "740abf96-f0bb-5397-0c19-8650db0db039",
    );
}

#[test]
fn adv49_opsgenie_heartbeat_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "opsgenie-heartbeat-api-key",
        "dummy_prefix_0 =xxxabf96-f0bb-5397-0c19-8650db0db039",
    );
}

#[test]
fn adv49_opsgenie_heartbeat_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "opsgenie-heartbeat-api-key",
        "OPSGENIE_HEARTBEAT=740abf96-f0bb-5397\u{200B}-0c19-8650db0db039",
        "740abf96-f0bb-5397-0c19-8650db0db039",
    );
}

#[test]
fn adv49_opsgenie_heartbeat_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "opsgenie-heartbeat-api-key",
        "OPSGENIE_HEARTBEAT=740abf96-f0bb-5397\u{00AD}-0c19-8650db0db039",
        "740abf96-f0bb-5397-0c19-8650db0db039",
    );
}

// =========================================================================
// 5. OPTIMISM API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv49_optimism_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "optimism-api-credentials",
        "optimismapikey=c578e12156b26a6eb50d9a1064627b62",
        "c578e12156b26a6eb50d9a1064627b62",
    );
}

#[test]
fn adv49_optimism_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "optimism-api-credentials",
        "dummy_prefix_0 =xxx8e12156b26a6eb50d9a1064627b62",
    );
}

#[test]
fn adv49_optimism_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "optimism-api-credentials",
        "optimismapikey=c578e12156b26a6e\u{200B}b50d9a1064627b62",
        "c578e12156b26a6eb50d9a1064627b62",
    );
}

#[test]
fn adv49_optimism_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "optimism-api-credentials",
        "optimismapikey=c578e12156b26a6e\u{00AD}b50d9a1064627b62",
        "c578e12156b26a6eb50d9a1064627b62",
    );
}

// =========================================================================
// 6. OPTIMIZELY SDK KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv49_optimizely_sdk_key_normal_must_fire() {
    assert_detector_fires(
        "optimizely-sdk-key",
        "OPTIMIZELY_SDK_KEY=EDOQtgXpGDWj1Dll",
        "EDOQtgXpGDWj1Dll",
    );
}

#[test]
fn adv49_optimizely_sdk_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "optimizely-sdk-key",
        "dummy_prefix_0 =xxxQtgXpGDWj1Dll",
    );
}

#[test]
fn adv49_optimizely_sdk_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "optimizely-sdk-key",
        "OPTIMIZELY_SDK_KEY=EDOQtgXp\u{200B}GDWj1Dll",
        "EDOQtgXpGDWj1Dll",
    );
}

#[test]
fn adv49_optimizely_sdk_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "optimizely-sdk-key",
        "OPTIMIZELY_SDK_KEY=EDOQtgXp\u{00AD}GDWj1Dll",
        "EDOQtgXpGDWj1Dll",
    );
}

// =========================================================================
// 7. ORACLE CLOUD API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv49_oracle_cloud_api_key_normal_must_fire() {
    assert_detector_fires(
        "oracle-cloud-api-key",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6hsegd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6hsegd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
    );
}

#[test]
fn adv49_oracle_cloud_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "oracle-cloud-api-key",
        "dummy1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6hsegd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
    );
}

#[test]
fn adv49_oracle_cloud_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "oracle-cloud-api-key",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6h\u{200B}segd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6hsegd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
    );
}

#[test]
fn adv49_oracle_cloud_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "oracle-cloud-api-key",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6h\u{00AD}segd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6hsegd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
    );
}

// =========================================================================
// 8. ORACLE CLOUD GOVERNMENT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv49_oracle_cloud_government_credentials_normal_must_fire() {
    assert_detector_fires(
        "oracle-cloud-government-credentials",
        "OCI_GOVERNMENT TENANCY=ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
}

#[test]
fn adv49_oracle_cloud_government_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "oracle-cloud-government-credentials",
        "dummy_prefix_0 =xxxd1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
}

#[test]
fn adv49_oracle_cloud_government_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "oracle-cloud-government-credentials",
        "OCI_GOVERNMENT TENANCY=ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbb\u{200B}bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
}

#[test]
fn adv49_oracle_cloud_government_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "oracle-cloud-government-credentials",
        "OCI_GOVERNMENT TENANCY=ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbb\u{00AD}bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
}

// =========================================================================
// 9. OVH API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv49_ovh_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "ovh-api-credentials",
        "OVH_APPLICATION_KEY=zv5mr12kbiab0vke",
        "zv5mr12kbiab0vke",
    );
}

#[test]
fn adv49_ovh_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ovh-api-credentials",
        "dummy_prefix_0 =xxxmr12kbiab0vke",
    );
}

#[test]
fn adv49_ovh_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ovh-api-credentials",
        "OVH_APPLICATION_KEY=zv5mr12k\u{200B}biab0vke",
        "zv5mr12kbiab0vke",
    );
}

#[test]
fn adv49_ovh_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ovh-api-credentials",
        "OVH_APPLICATION_KEY=zv5mr12k\u{00AD}biab0vke",
        "zv5mr12kbiab0vke",
    );
}

// =========================================================================
// 10. OXYLABS CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv49_oxylabs_credentials_normal_must_fire() {
    assert_detector_fires(
        "oxylabs-credentials",
        "customer-ytESOCaL1aAHcTJ8N:3zAAw4x0g2B7ztTxjFoc3",
        "customer-ytESOCaL1aAHcTJ8N:3zAAw4x0g2B7ztTxjFoc3",
    );
}

#[test]
fn adv49_oxylabs_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "oxylabs-credentials",
        "dummy_prefix_0:3zAAw4x0g2B7ztTxjFoc3",
    );
}

#[test]
fn adv49_oxylabs_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "oxylabs-credentials",
        "customer-ytESOCaL1aAHcTJ\u{200B}8N:3zAAw4x0g2B7ztTxjFoc3",
        "customer-ytESOCaL1aAHcTJ8N:3zAAw4x0g2B7ztTxjFoc3",
    );
}

#[test]
fn adv49_oxylabs_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "oxylabs-credentials",
        "customer-ytESOCaL1aAHcTJ\u{00AD}8N:3zAAw4x0g2B7ztTxjFoc3",
        "customer-ytESOCaL1aAHcTJ8N:3zAAw4x0g2B7ztTxjFoc3",
    );
}


