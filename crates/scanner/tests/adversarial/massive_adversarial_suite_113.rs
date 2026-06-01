//! Part 113 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates opsgenie, optimism, optimizely, oracle, oracle, ovh, oxylabs, packagist, packer, paddle detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. OPSGENIE HEARTBEAT API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv113_opsgenie_heartbeat_api_key_normal_must_fire() {
    assert_detector_fires(
        "opsgenie-heartbeat-api-key",
        "OPSGENIE_HEARTBEAT=740abf96-f0bb-5397-0c19-8650db0db039",
        "740abf96-f0bb-5397-0c19-8650db0db039",
    );
}

#[test]
fn adv113_opsgenie_heartbeat_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "opsgenie-heartbeat-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv113_opsgenie_heartbeat_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "opsgenie-heartbeat-api-key",
        "OPSGENIE_HEARTBEAT=740abf96-f0bb-5397\u{200B}-0c19-8650db0db039",
        "740abf96-f0bb-5397-0c19-8650db0db039",
    );
}

#[test]
fn adv113_opsgenie_heartbeat_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "opsgenie-heartbeat-api-key",
        "OPSGENIE_HEARTBEAT=740abf96-f0bb-5397\u{00AD}-0c19-8650db0db039",
        "740abf96-f0bb-5397-0c19-8650db0db039",
    );
}

#[test]
fn adv113_opsgenie_heartbeat_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "opsgenie-heartbeat-api-key",
        "OPSGENIE_HEARTBEAT=740abf96-f0bb-5397\u{200C}-0c19-8650db0db039",
        "740abf96-f0bb-5397-0c19-8650db0db039",
    );
}

#[test]
fn adv113_opsgenie_heartbeat_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "opsgenie-heartbeat-api-key",
        "OPSGENIE_HEARTBEAT=740abf96-f0bb-5397\u{200D}-0c19-8650db0db039",
        "740abf96-f0bb-5397-0c19-8650db0db039",
    );
}

#[test]
fn adv113_opsgenie_heartbeat_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "opsgenie-heartbeat-api-key",
        "OPSGENIE_HEARTBEAT=740abf96-f0bb-5397\u{FEFF}-0c19-8650db0db039",
        "740abf96-f0bb-5397-0c19-8650db0db039",
    );
}

#[test]
fn adv113_opsgenie_heartbeat_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "opsgenie-heartbeat-api-key",
        "OPSGENIE_HEARTBEAT=740abf96-f0bb-5397\u{2060}-0c19-8650db0db039",
        "740abf96-f0bb-5397-0c19-8650db0db039",
    );
}

#[test]
fn adv113_opsgenie_heartbeat_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "opsgenie-heartbeat-api-key",
        "OPSGENIE_HEARTBEAT=740abf96-f0bb-5397\u{180E}-0c19-8650db0db039",
        "740abf96-f0bb-5397-0c19-8650db0db039",
    );
}

#[test]
fn adv113_opsgenie_heartbeat_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "opsgenie-heartbeat-api-key",
        "OPSGENIE_HEARTBEAT=740abf96-f0bb-5397\u{202E}-0c19-8650db0db039",
        "740abf96-f0bb-5397-0c19-8650db0db039",
    );
}

#[test]
fn adv113_opsgenie_heartbeat_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "opsgenie-heartbeat-api-key",
        "OPSGENIE_HEARTBEAT=740abf96-f0bb-5397\u{202C}-0c19-8650db0db039",
        "740abf96-f0bb-5397-0c19-8650db0db039",
    );
}

#[test]
fn adv113_opsgenie_heartbeat_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "opsgenie-heartbeat-api-key",
        "OPSGENIE_HEARTBEAT=740abf96-f0bb-5397\u{200E}-0c19-8650db0db039",
        "740abf96-f0bb-5397-0c19-8650db0db039",
    );
}

// =========================================================================
// 2. OPTIMISM API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv113_optimism_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "optimism-api-credentials",
        "optimismapikey=c578e12156b26a6eb50d9a1064627b62",
        "c578e12156b26a6eb50d9a1064627b62",
    );
}

#[test]
fn adv113_optimism_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "optimism-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv113_optimism_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "optimism-api-credentials",
        "optimismapikey=c578e12156b26a6e\u{200B}b50d9a1064627b62",
        "c578e12156b26a6eb50d9a1064627b62",
    );
}

#[test]
fn adv113_optimism_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "optimism-api-credentials",
        "optimismapikey=c578e12156b26a6e\u{00AD}b50d9a1064627b62",
        "c578e12156b26a6eb50d9a1064627b62",
    );
}

#[test]
fn adv113_optimism_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "optimism-api-credentials",
        "optimismapikey=c578e12156b26a6e\u{200C}b50d9a1064627b62",
        "c578e12156b26a6eb50d9a1064627b62",
    );
}

#[test]
fn adv113_optimism_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "optimism-api-credentials",
        "optimismapikey=c578e12156b26a6e\u{200D}b50d9a1064627b62",
        "c578e12156b26a6eb50d9a1064627b62",
    );
}

#[test]
fn adv113_optimism_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "optimism-api-credentials",
        "optimismapikey=c578e12156b26a6e\u{FEFF}b50d9a1064627b62",
        "c578e12156b26a6eb50d9a1064627b62",
    );
}

#[test]
fn adv113_optimism_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "optimism-api-credentials",
        "optimismapikey=c578e12156b26a6e\u{2060}b50d9a1064627b62",
        "c578e12156b26a6eb50d9a1064627b62",
    );
}

#[test]
fn adv113_optimism_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "optimism-api-credentials",
        "optimismapikey=c578e12156b26a6e\u{180E}b50d9a1064627b62",
        "c578e12156b26a6eb50d9a1064627b62",
    );
}

#[test]
fn adv113_optimism_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "optimism-api-credentials",
        "optimismapikey=c578e12156b26a6e\u{202E}b50d9a1064627b62",
        "c578e12156b26a6eb50d9a1064627b62",
    );
}

#[test]
fn adv113_optimism_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "optimism-api-credentials",
        "optimismapikey=c578e12156b26a6e\u{202C}b50d9a1064627b62",
        "c578e12156b26a6eb50d9a1064627b62",
    );
}

#[test]
fn adv113_optimism_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "optimism-api-credentials",
        "optimismapikey=c578e12156b26a6e\u{200E}b50d9a1064627b62",
        "c578e12156b26a6eb50d9a1064627b62",
    );
}

// =========================================================================
// 3. OPTIMIZELY SDK KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv113_optimizely_sdk_key_normal_must_fire() {
    assert_detector_fires(
        "optimizely-sdk-key",
        "OPTIMIZELY_SDK_KEY=EDOQtgXpGDWj1Dll",
        "EDOQtgXpGDWj1Dll",
    );
}

#[test]
fn adv113_optimizely_sdk_key_wrong_prefix_must_silent() {
    assert_detector_silent("optimizely-sdk-key", "dummy_prefix_0 =xxxxxxxxxxxxxxxx");
}

#[test]
fn adv113_optimizely_sdk_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "optimizely-sdk-key",
        "OPTIMIZELY_SDK_KEY=EDOQtgXp\u{200B}GDWj1Dll",
        "EDOQtgXpGDWj1Dll",
    );
}

#[test]
fn adv113_optimizely_sdk_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "optimizely-sdk-key",
        "OPTIMIZELY_SDK_KEY=EDOQtgXp\u{00AD}GDWj1Dll",
        "EDOQtgXpGDWj1Dll",
    );
}

#[test]
fn adv113_optimizely_sdk_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "optimizely-sdk-key",
        "OPTIMIZELY_SDK_KEY=EDOQtgXp\u{200C}GDWj1Dll",
        "EDOQtgXpGDWj1Dll",
    );
}

#[test]
fn adv113_optimizely_sdk_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "optimizely-sdk-key",
        "OPTIMIZELY_SDK_KEY=EDOQtgXp\u{200D}GDWj1Dll",
        "EDOQtgXpGDWj1Dll",
    );
}

#[test]
fn adv113_optimizely_sdk_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "optimizely-sdk-key",
        "OPTIMIZELY_SDK_KEY=EDOQtgXp\u{FEFF}GDWj1Dll",
        "EDOQtgXpGDWj1Dll",
    );
}

#[test]
fn adv113_optimizely_sdk_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "optimizely-sdk-key",
        "OPTIMIZELY_SDK_KEY=EDOQtgXp\u{2060}GDWj1Dll",
        "EDOQtgXpGDWj1Dll",
    );
}

#[test]
fn adv113_optimizely_sdk_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "optimizely-sdk-key",
        "OPTIMIZELY_SDK_KEY=EDOQtgXp\u{180E}GDWj1Dll",
        "EDOQtgXpGDWj1Dll",
    );
}

#[test]
fn adv113_optimizely_sdk_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "optimizely-sdk-key",
        "OPTIMIZELY_SDK_KEY=EDOQtgXp\u{202E}GDWj1Dll",
        "EDOQtgXpGDWj1Dll",
    );
}

#[test]
fn adv113_optimizely_sdk_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "optimizely-sdk-key",
        "OPTIMIZELY_SDK_KEY=EDOQtgXp\u{202C}GDWj1Dll",
        "EDOQtgXpGDWj1Dll",
    );
}

#[test]
fn adv113_optimizely_sdk_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "optimizely-sdk-key",
        "OPTIMIZELY_SDK_KEY=EDOQtgXp\u{200E}GDWj1Dll",
        "EDOQtgXpGDWj1Dll",
    );
}

// =========================================================================
// 4. ORACLE CLOUD API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv113_oracle_cloud_api_key_normal_must_fire() {
    assert_detector_fires(
        "oracle-cloud-api-key",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6hsegd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6hsegd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
    );
}

#[test]
fn adv113_oracle_cloud_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "oracle-cloud-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv113_oracle_cloud_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "oracle-cloud-api-key",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6h\u{200B}segd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6hsegd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
    );
}

#[test]
fn adv113_oracle_cloud_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "oracle-cloud-api-key",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6h\u{00AD}segd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6hsegd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
    );
}

#[test]
fn adv113_oracle_cloud_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "oracle-cloud-api-key",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6h\u{200C}segd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6hsegd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
    );
}

#[test]
fn adv113_oracle_cloud_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "oracle-cloud-api-key",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6h\u{200D}segd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6hsegd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
    );
}

#[test]
fn adv113_oracle_cloud_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "oracle-cloud-api-key",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6h\u{FEFF}segd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6hsegd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
    );
}

#[test]
fn adv113_oracle_cloud_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "oracle-cloud-api-key",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6h\u{2060}segd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6hsegd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
    );
}

#[test]
fn adv113_oracle_cloud_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "oracle-cloud-api-key",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6h\u{180E}segd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6hsegd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
    );
}

#[test]
fn adv113_oracle_cloud_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "oracle-cloud-api-key",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6h\u{202E}segd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6hsegd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
    );
}

#[test]
fn adv113_oracle_cloud_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "oracle-cloud-api-key",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6h\u{202C}segd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6hsegd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
    );
}

#[test]
fn adv113_oracle_cloud_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "oracle-cloud-api-key",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6h\u{200E}segd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
        "ocid1.user.oc1.mzks6yx4t4ccgj0myg6d0lm4ox2uush50dkkrmkkyrjn960x7560kzvq1m63t4yk7u2w13lo6hsegd223arj54.gcsxajsz0f04t9fbn8vhlnikxk7fpnge3blz5a53p5z3rp30p4xj851oqsbgruhnhv3ojp2icsyog",
    );
}

// =========================================================================
// 5. ORACLE CLOUD GOVERNMENT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv113_oracle_cloud_government_credentials_normal_must_fire() {
    assert_detector_fires(
        "oracle-cloud-government-credentials",
        "OCI_GOVERNMENT TENANCY=ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
}

#[test]
fn adv113_oracle_cloud_government_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "oracle-cloud-government-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv113_oracle_cloud_government_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "oracle-cloud-government-credentials",
        "OCI_GOVERNMENT TENANCY=ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbb\u{200B}bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
}

#[test]
fn adv113_oracle_cloud_government_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "oracle-cloud-government-credentials",
        "OCI_GOVERNMENT TENANCY=ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbb\u{00AD}bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
}

#[test]
fn adv113_oracle_cloud_government_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "oracle-cloud-government-credentials",
        "OCI_GOVERNMENT TENANCY=ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbb\u{200C}bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
}

#[test]
fn adv113_oracle_cloud_government_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "oracle-cloud-government-credentials",
        "OCI_GOVERNMENT TENANCY=ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbb\u{200D}bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
}

#[test]
fn adv113_oracle_cloud_government_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "oracle-cloud-government-credentials",
        "OCI_GOVERNMENT TENANCY=ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbb\u{FEFF}bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
}

#[test]
fn adv113_oracle_cloud_government_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "oracle-cloud-government-credentials",
        "OCI_GOVERNMENT TENANCY=ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbb\u{2060}bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
}

#[test]
fn adv113_oracle_cloud_government_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "oracle-cloud-government-credentials",
        "OCI_GOVERNMENT TENANCY=ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbb\u{180E}bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
}

#[test]
fn adv113_oracle_cloud_government_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "oracle-cloud-government-credentials",
        "OCI_GOVERNMENT TENANCY=ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbb\u{202E}bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
}

#[test]
fn adv113_oracle_cloud_government_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "oracle-cloud-government-credentials",
        "OCI_GOVERNMENT TENANCY=ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbb\u{202C}bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
}

#[test]
fn adv113_oracle_cloud_government_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "oracle-cloud-government-credentials",
        "OCI_GOVERNMENT TENANCY=ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbb\u{200E}bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "ocid1.tenancy.oc1.aaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
}

// =========================================================================
// 6. OVH API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv113_ovh_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "ovh-api-credentials",
        "OVH_APPLICATION_KEY=zv5mr12kbiab0vke",
        "zv5mr12kbiab0vke",
    );
}

#[test]
fn adv113_ovh_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent("ovh-api-credentials", "dummy_prefix_0 =xxxxxxxxxxxxxxxx");
}

#[test]
fn adv113_ovh_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ovh-api-credentials",
        "OVH_APPLICATION_KEY=zv5mr12k\u{200B}biab0vke",
        "zv5mr12kbiab0vke",
    );
}

#[test]
fn adv113_ovh_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ovh-api-credentials",
        "OVH_APPLICATION_KEY=zv5mr12k\u{00AD}biab0vke",
        "zv5mr12kbiab0vke",
    );
}

#[test]
fn adv113_ovh_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "ovh-api-credentials",
        "OVH_APPLICATION_KEY=zv5mr12k\u{200C}biab0vke",
        "zv5mr12kbiab0vke",
    );
}

#[test]
fn adv113_ovh_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "ovh-api-credentials",
        "OVH_APPLICATION_KEY=zv5mr12k\u{200D}biab0vke",
        "zv5mr12kbiab0vke",
    );
}

#[test]
fn adv113_ovh_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "ovh-api-credentials",
        "OVH_APPLICATION_KEY=zv5mr12k\u{FEFF}biab0vke",
        "zv5mr12kbiab0vke",
    );
}

#[test]
fn adv113_ovh_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "ovh-api-credentials",
        "OVH_APPLICATION_KEY=zv5mr12k\u{2060}biab0vke",
        "zv5mr12kbiab0vke",
    );
}

#[test]
fn adv113_ovh_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "ovh-api-credentials",
        "OVH_APPLICATION_KEY=zv5mr12k\u{180E}biab0vke",
        "zv5mr12kbiab0vke",
    );
}

#[test]
fn adv113_ovh_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "ovh-api-credentials",
        "OVH_APPLICATION_KEY=zv5mr12k\u{202E}biab0vke",
        "zv5mr12kbiab0vke",
    );
}

#[test]
fn adv113_ovh_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "ovh-api-credentials",
        "OVH_APPLICATION_KEY=zv5mr12k\u{202C}biab0vke",
        "zv5mr12kbiab0vke",
    );
}

#[test]
fn adv113_ovh_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "ovh-api-credentials",
        "OVH_APPLICATION_KEY=zv5mr12k\u{200E}biab0vke",
        "zv5mr12kbiab0vke",
    );
}

// =========================================================================
// 7. OXYLABS CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv113_oxylabs_credentials_normal_must_fire() {
    assert_detector_fires(
        "oxylabs-credentials",
        "customer-ytESOCaL1aAHcTJ8N:3zAAw4x0g2B7ztTxjFoc3",
        "customer-ytESOCaL1aAHcTJ8N:3zAAw4x0g2B7ztTxjFoc3",
    );
}

#[test]
fn adv113_oxylabs_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "oxylabs-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv113_oxylabs_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "oxylabs-credentials",
        "customer-ytESOCaL1aAHcTJ\u{200B}8N:3zAAw4x0g2B7ztTxjFoc3",
        "customer-ytESOCaL1aAHcTJ8N:3zAAw4x0g2B7ztTxjFoc3",
    );
}

#[test]
fn adv113_oxylabs_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "oxylabs-credentials",
        "customer-ytESOCaL1aAHcTJ\u{00AD}8N:3zAAw4x0g2B7ztTxjFoc3",
        "customer-ytESOCaL1aAHcTJ8N:3zAAw4x0g2B7ztTxjFoc3",
    );
}

#[test]
fn adv113_oxylabs_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "oxylabs-credentials",
        "customer-ytESOCaL1aAHcTJ\u{200C}8N:3zAAw4x0g2B7ztTxjFoc3",
        "customer-ytESOCaL1aAHcTJ8N:3zAAw4x0g2B7ztTxjFoc3",
    );
}

#[test]
fn adv113_oxylabs_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "oxylabs-credentials",
        "customer-ytESOCaL1aAHcTJ\u{200D}8N:3zAAw4x0g2B7ztTxjFoc3",
        "customer-ytESOCaL1aAHcTJ8N:3zAAw4x0g2B7ztTxjFoc3",
    );
}

#[test]
fn adv113_oxylabs_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "oxylabs-credentials",
        "customer-ytESOCaL1aAHcTJ\u{FEFF}8N:3zAAw4x0g2B7ztTxjFoc3",
        "customer-ytESOCaL1aAHcTJ8N:3zAAw4x0g2B7ztTxjFoc3",
    );
}

#[test]
fn adv113_oxylabs_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "oxylabs-credentials",
        "customer-ytESOCaL1aAHcTJ\u{2060}8N:3zAAw4x0g2B7ztTxjFoc3",
        "customer-ytESOCaL1aAHcTJ8N:3zAAw4x0g2B7ztTxjFoc3",
    );
}

#[test]
fn adv113_oxylabs_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "oxylabs-credentials",
        "customer-ytESOCaL1aAHcTJ\u{180E}8N:3zAAw4x0g2B7ztTxjFoc3",
        "customer-ytESOCaL1aAHcTJ8N:3zAAw4x0g2B7ztTxjFoc3",
    );
}

#[test]
fn adv113_oxylabs_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "oxylabs-credentials",
        "customer-ytESOCaL1aAHcTJ\u{202E}8N:3zAAw4x0g2B7ztTxjFoc3",
        "customer-ytESOCaL1aAHcTJ8N:3zAAw4x0g2B7ztTxjFoc3",
    );
}

#[test]
fn adv113_oxylabs_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "oxylabs-credentials",
        "customer-ytESOCaL1aAHcTJ\u{202C}8N:3zAAw4x0g2B7ztTxjFoc3",
        "customer-ytESOCaL1aAHcTJ8N:3zAAw4x0g2B7ztTxjFoc3",
    );
}

#[test]
fn adv113_oxylabs_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "oxylabs-credentials",
        "customer-ytESOCaL1aAHcTJ\u{200E}8N:3zAAw4x0g2B7ztTxjFoc3",
        "customer-ytESOCaL1aAHcTJ8N:3zAAw4x0g2B7ztTxjFoc3",
    );
}

// =========================================================================
// 8. PACKAGIST API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv113_packagist_api_token_normal_must_fire() {
    assert_detector_fires(
        "packagist-api-token",
        "PACKAGIST_API_KEY=a6a5effa36c91d47cb12be92bd74e20b3148bf5b",
        "a6a5effa36c91d47cb12be92bd74e20b3148bf5b",
    );
}

#[test]
fn adv113_packagist_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "packagist-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv113_packagist_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "packagist-api-token",
        "PACKAGIST_API_KEY=a6a5effa36c91d47cb12\u{200B}be92bd74e20b3148bf5b",
        "a6a5effa36c91d47cb12be92bd74e20b3148bf5b",
    );
}

#[test]
fn adv113_packagist_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "packagist-api-token",
        "PACKAGIST_API_KEY=a6a5effa36c91d47cb12\u{00AD}be92bd74e20b3148bf5b",
        "a6a5effa36c91d47cb12be92bd74e20b3148bf5b",
    );
}

#[test]
fn adv113_packagist_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "packagist-api-token",
        "PACKAGIST_API_KEY=a6a5effa36c91d47cb12\u{200C}be92bd74e20b3148bf5b",
        "a6a5effa36c91d47cb12be92bd74e20b3148bf5b",
    );
}

#[test]
fn adv113_packagist_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "packagist-api-token",
        "PACKAGIST_API_KEY=a6a5effa36c91d47cb12\u{200D}be92bd74e20b3148bf5b",
        "a6a5effa36c91d47cb12be92bd74e20b3148bf5b",
    );
}

#[test]
fn adv113_packagist_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "packagist-api-token",
        "PACKAGIST_API_KEY=a6a5effa36c91d47cb12\u{FEFF}be92bd74e20b3148bf5b",
        "a6a5effa36c91d47cb12be92bd74e20b3148bf5b",
    );
}

#[test]
fn adv113_packagist_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "packagist-api-token",
        "PACKAGIST_API_KEY=a6a5effa36c91d47cb12\u{2060}be92bd74e20b3148bf5b",
        "a6a5effa36c91d47cb12be92bd74e20b3148bf5b",
    );
}

#[test]
fn adv113_packagist_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "packagist-api-token",
        "PACKAGIST_API_KEY=a6a5effa36c91d47cb12\u{180E}be92bd74e20b3148bf5b",
        "a6a5effa36c91d47cb12be92bd74e20b3148bf5b",
    );
}

#[test]
fn adv113_packagist_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "packagist-api-token",
        "PACKAGIST_API_KEY=a6a5effa36c91d47cb12\u{202E}be92bd74e20b3148bf5b",
        "a6a5effa36c91d47cb12be92bd74e20b3148bf5b",
    );
}

#[test]
fn adv113_packagist_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "packagist-api-token",
        "PACKAGIST_API_KEY=a6a5effa36c91d47cb12\u{202C}be92bd74e20b3148bf5b",
        "a6a5effa36c91d47cb12be92bd74e20b3148bf5b",
    );
}

#[test]
fn adv113_packagist_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "packagist-api-token",
        "PACKAGIST_API_KEY=a6a5effa36c91d47cb12\u{200E}be92bd74e20b3148bf5b",
        "a6a5effa36c91d47cb12be92bd74e20b3148bf5b",
    );
}

// =========================================================================
// 9. PACKER CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv113_packer_credentials_normal_must_fire() {
    assert_detector_fires(
        "packer-credentials",
        "HCP_CLIENT_ID=2741f27f-279a-1657-afb4-30b08a3d35d0",
        "2741f27f-279a-1657-afb4-30b08a3d35d0",
    );
}

#[test]
fn adv113_packer_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "packer-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv113_packer_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "packer-credentials",
        "HCP_CLIENT_ID=2741f27f-279a-1657\u{200B}-afb4-30b08a3d35d0",
        "2741f27f-279a-1657-afb4-30b08a3d35d0",
    );
}

#[test]
fn adv113_packer_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "packer-credentials",
        "HCP_CLIENT_ID=2741f27f-279a-1657\u{00AD}-afb4-30b08a3d35d0",
        "2741f27f-279a-1657-afb4-30b08a3d35d0",
    );
}

#[test]
fn adv113_packer_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "packer-credentials",
        "HCP_CLIENT_ID=2741f27f-279a-1657\u{200C}-afb4-30b08a3d35d0",
        "2741f27f-279a-1657-afb4-30b08a3d35d0",
    );
}

#[test]
fn adv113_packer_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "packer-credentials",
        "HCP_CLIENT_ID=2741f27f-279a-1657\u{200D}-afb4-30b08a3d35d0",
        "2741f27f-279a-1657-afb4-30b08a3d35d0",
    );
}

#[test]
fn adv113_packer_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "packer-credentials",
        "HCP_CLIENT_ID=2741f27f-279a-1657\u{FEFF}-afb4-30b08a3d35d0",
        "2741f27f-279a-1657-afb4-30b08a3d35d0",
    );
}

#[test]
fn adv113_packer_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "packer-credentials",
        "HCP_CLIENT_ID=2741f27f-279a-1657\u{2060}-afb4-30b08a3d35d0",
        "2741f27f-279a-1657-afb4-30b08a3d35d0",
    );
}

#[test]
fn adv113_packer_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "packer-credentials",
        "HCP_CLIENT_ID=2741f27f-279a-1657\u{180E}-afb4-30b08a3d35d0",
        "2741f27f-279a-1657-afb4-30b08a3d35d0",
    );
}

#[test]
fn adv113_packer_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "packer-credentials",
        "HCP_CLIENT_ID=2741f27f-279a-1657\u{202E}-afb4-30b08a3d35d0",
        "2741f27f-279a-1657-afb4-30b08a3d35d0",
    );
}

#[test]
fn adv113_packer_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "packer-credentials",
        "HCP_CLIENT_ID=2741f27f-279a-1657\u{202C}-afb4-30b08a3d35d0",
        "2741f27f-279a-1657-afb4-30b08a3d35d0",
    );
}

#[test]
fn adv113_packer_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "packer-credentials",
        "HCP_CLIENT_ID=2741f27f-279a-1657\u{200E}-afb4-30b08a3d35d0",
        "2741f27f-279a-1657-afb4-30b08a3d35d0",
    );
}

// =========================================================================
// 10. PADDLE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv113_paddle_api_key_normal_must_fire() {
    assert_detector_fires(
        "paddle-api-key",
        "pdl_live_apikey_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pdl_live_apikey_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv113_paddle_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "paddle-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv113_paddle_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "paddle-api-key",
        "pdl_live_apikey_Kp4Qx7Rm\u{200B}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pdl_live_apikey_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv113_paddle_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "paddle-api-key",
        "pdl_live_apikey_Kp4Qx7Rm\u{00AD}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pdl_live_apikey_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv113_paddle_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "paddle-api-key",
        "pdl_live_apikey_Kp4Qx7Rm\u{200C}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pdl_live_apikey_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv113_paddle_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "paddle-api-key",
        "pdl_live_apikey_Kp4Qx7Rm\u{200D}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pdl_live_apikey_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv113_paddle_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "paddle-api-key",
        "pdl_live_apikey_Kp4Qx7Rm\u{FEFF}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pdl_live_apikey_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv113_paddle_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "paddle-api-key",
        "pdl_live_apikey_Kp4Qx7Rm\u{2060}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pdl_live_apikey_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv113_paddle_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "paddle-api-key",
        "pdl_live_apikey_Kp4Qx7Rm\u{180E}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pdl_live_apikey_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv113_paddle_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "paddle-api-key",
        "pdl_live_apikey_Kp4Qx7Rm\u{202E}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pdl_live_apikey_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv113_paddle_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "paddle-api-key",
        "pdl_live_apikey_Kp4Qx7Rm\u{202C}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pdl_live_apikey_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv113_paddle_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "paddle-api-key",
        "pdl_live_apikey_Kp4Qx7Rm\u{200E}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pdl_live_apikey_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}
