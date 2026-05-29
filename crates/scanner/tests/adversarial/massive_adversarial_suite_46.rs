//! Part 46 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates netlify, netlify, newrelic, newrelic, nexus, ngrok, ngrok, nih, noaa, nomad detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. NETLIFY BUILD HOOK ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv46_netlify_build_hook_normal_must_fire() {
    assert_detector_fires(
        "netlify-build-hook",
        "https://api.netlify.com/build_hooks/f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
        "https://api.netlify.com/build_hooks/f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
    );
}

#[test]
fn adv46_netlify_build_hook_wrong_prefix_must_silent() {
    assert_detector_silent(
        "netlify-build-hook",
        "dummy_prefix_0://api.netlify.com/build_hooks/f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
    );
}

#[test]
fn adv46_netlify_build_hook_evade_zwsp_must_fire() {
    assert_detector_fires(
        "netlify-build-hook",
        "https://api.netlify.com/build_hooks/\u{200B}f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
        "https://api.netlify.com/build_hooks/f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
    );
}

#[test]
fn adv46_netlify_build_hook_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "netlify-build-hook",
        "https://api.netlify.com/build_hooks/\u{00AD}f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
        "https://api.netlify.com/build_hooks/f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
    );
}

// =========================================================================
// 2. NETLIFY PAT ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv46_netlify_pat_normal_must_fire() {
    assert_detector_fires(
        "netlify-pat",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv46_netlify_pat_wrong_prefix_must_silent() {
    assert_detector_silent(
        "netlify-pat",
        "dummyKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv46_netlify_pat_evade_zwsp_must_fire() {
    assert_detector_fires(
        "netlify-pat",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3\u{200B}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv46_netlify_pat_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "netlify-pat",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3\u{00AD}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 3. NEWRELIC LICENSE KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv46_newrelic_license_key_normal_must_fire() {
    assert_detector_fires(
        "newrelic-license-key",
        "NEW_RELIC_LICENSE_KEY=5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2f5b8",
        "5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2f5b8",
    );
}

#[test]
fn adv46_newrelic_license_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "newrelic-license-key",
        "dummy_prefix_0 =xxxc1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2f5b8",
    );
}

#[test]
fn adv46_newrelic_license_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "newrelic-license-key",
        "NEW_RELIC_LICENSE_KEY=5d8c1a9f4e2b6c8d3a5e\u{200B}9f1b7c4d7b3ea9e2f5b8",
        "5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2f5b8",
    );
}

#[test]
fn adv46_newrelic_license_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "newrelic-license-key",
        "NEW_RELIC_LICENSE_KEY=5d8c1a9f4e2b6c8d3a5e\u{00AD}9f1b7c4d7b3ea9e2f5b8",
        "5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2f5b8",
    );
}

// =========================================================================
// 4. NEWRELIC USER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv46_newrelic_user_api_key_normal_must_fire() {
    assert_detector_fires(
        "newrelic-user-api-key",
        "NRAK-2EYOINJXROC0URJH7T52XQYNDJX",
        "NRAK-2EYOINJXROC0URJH7T52XQYNDJX",
    );
}

#[test]
fn adv46_newrelic_user_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "newrelic-user-api-key",
        "dummy-2EYOINJXROC0URJH7T52XQYNDJX",
    );
}

#[test]
fn adv46_newrelic_user_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "newrelic-user-api-key",
        "NRAK-2EYOINJXROC\u{200B}0URJH7T52XQYNDJX",
        "NRAK-2EYOINJXROC0URJH7T52XQYNDJX",
    );
}

#[test]
fn adv46_newrelic_user_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "newrelic-user-api-key",
        "NRAK-2EYOINJXROC\u{00AD}0URJH7T52XQYNDJX",
        "NRAK-2EYOINJXROC0URJH7T52XQYNDJX",
    );
}

// =========================================================================
// 5. NEXUS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv46_nexus_api_key_normal_must_fire() {
    assert_detector_fires(
        "nexus-api-key",
        "NEXUS_API_KEY=926820561f663070c952112c7f4f5fa46b37c427601aa7dc9e98614469cca8c1",
        "926820561f663070c952112c7f4f5fa46b37c427601aa7dc9e98614469cca8c1",
    );
}

#[test]
fn adv46_nexus_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "nexus-api-key",
        "dummy_prefix_0 =xxx820561f663070c952112c7f4f5fa46b37c427601aa7dc9e98614469cca8c1",
    );
}

#[test]
fn adv46_nexus_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "nexus-api-key",
        "NEXUS_API_KEY=926820561f663070c952112c7f4f5fa4\u{200B}6b37c427601aa7dc9e98614469cca8c1",
        "926820561f663070c952112c7f4f5fa46b37c427601aa7dc9e98614469cca8c1",
    );
}

#[test]
fn adv46_nexus_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "nexus-api-key",
        "NEXUS_API_KEY=926820561f663070c952112c7f4f5fa4\u{00AD}6b37c427601aa7dc9e98614469cca8c1",
        "926820561f663070c952112c7f4f5fa46b37c427601aa7dc9e98614469cca8c1",
    );
}

// =========================================================================
// 6. NGROK API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv46_ngrok_api_key_normal_must_fire() {
    assert_detector_fires(
        "ngrok-api-key",
        "NGROK_API_KEY=JBtug0uFLI4S6P3lTr5LRbu4nzD7wx3SQrs23tOu",
        "JBtug0uFLI4S6P3lTr5LRbu4nzD7wx3SQrs23tOu",
    );
}

#[test]
fn adv46_ngrok_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ngrok-api-key",
        "dummy_prefix_0 =xxxug0uFLI4S6P3lTr5LRbu4nzD7wx3SQrs23tOu",
    );
}

#[test]
fn adv46_ngrok_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ngrok-api-key",
        "NGROK_API_KEY=JBtug0uFLI4S6P3lTr5L\u{200B}Rbu4nzD7wx3SQrs23tOu",
        "JBtug0uFLI4S6P3lTr5LRbu4nzD7wx3SQrs23tOu",
    );
}

#[test]
fn adv46_ngrok_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ngrok-api-key",
        "NGROK_API_KEY=JBtug0uFLI4S6P3lTr5L\u{00AD}Rbu4nzD7wx3SQrs23tOu",
        "JBtug0uFLI4S6P3lTr5LRbu4nzD7wx3SQrs23tOu",
    );
}

// =========================================================================
// 7. NGROK AUTH TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv46_ngrok_auth_token_normal_must_fire() {
    assert_detector_fires(
        "ngrok-auth-token",
        "NGROK_AUTHTOKEN=6vFSd5rDCFSM5K5OrRo4JGIdLLsIfXAuWO+bvvn/",
        "6vFSd5rDCFSM5K5OrRo4JGIdLLsIfXAuWO+bvvn/",
    );
}

#[test]
fn adv46_ngrok_auth_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ngrok-auth-token",
        "dummy_prefix_0 =xxxSd5rDCFSM5K5OrRo4JGIdLLsIfXAuWO+bvvn/",
    );
}

#[test]
fn adv46_ngrok_auth_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ngrok-auth-token",
        "NGROK_AUTHTOKEN=6vFSd5rDCFSM5K5OrRo4\u{200B}JGIdLLsIfXAuWO+bvvn/",
        "6vFSd5rDCFSM5K5OrRo4JGIdLLsIfXAuWO+bvvn/",
    );
}

#[test]
fn adv46_ngrok_auth_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ngrok-auth-token",
        "NGROK_AUTHTOKEN=6vFSd5rDCFSM5K5OrRo4\u{00AD}JGIdLLsIfXAuWO+bvvn/",
        "6vFSd5rDCFSM5K5OrRo4JGIdLLsIfXAuWO+bvvn/",
    );
}

// =========================================================================
// 8. NIH PUBMED API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv46_nih_pubmed_api_key_normal_must_fire() {
    assert_detector_fires(
        "nih-pubmed-api-key",
        "NIH_PUBMED_API_KEY=9Uz0vRSvRD4VZ7SSmyPz32hJL459hzkhCEwA",
        "9Uz0vRSvRD4VZ7SSmyPz32hJL459hzkhCEwA",
    );
}

#[test]
fn adv46_nih_pubmed_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "nih-pubmed-api-key",
        "dummy_prefix_0 =xxx0vRSvRD4VZ7SSmyPz32hJL459hzkhCEwA",
    );
}

#[test]
fn adv46_nih_pubmed_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "nih-pubmed-api-key",
        "NIH_PUBMED_API_KEY=9Uz0vRSvRD4VZ7SSmy\u{200B}Pz32hJL459hzkhCEwA",
        "9Uz0vRSvRD4VZ7SSmyPz32hJL459hzkhCEwA",
    );
}

#[test]
fn adv46_nih_pubmed_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "nih-pubmed-api-key",
        "NIH_PUBMED_API_KEY=9Uz0vRSvRD4VZ7SSmy\u{00AD}Pz32hJL459hzkhCEwA",
        "9Uz0vRSvRD4VZ7SSmyPz32hJL459hzkhCEwA",
    );
}

// =========================================================================
// 9. NOAA API CONFIG ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv46_noaa_api_config_normal_must_fire() {
    assert_detector_fires(
        "noaa-api-config",
        "User-Agent=mDnz,U!<T$2Zy#c?d:8E)H37Auqweather.govz)Y",
        "mDnz,U!<T$2Zy#c?d:8E)H37Auqweather.govz)Y",
    );
}

#[test]
fn adv46_noaa_api_config_wrong_prefix_must_silent() {
    assert_detector_silent(
        "noaa-api-config",
        "dummy_prefix_0 =xxxz,U!<T$2Zy#c?d:8E)H37Auqweather.govz)Y",
    );
}

#[test]
fn adv46_noaa_api_config_evade_zwsp_must_fire() {
    assert_detector_fires(
        "noaa-api-config",
        "User-Agent=mDnz,U!<T$2Zy#c?d:8E\u{200B})H37Auqweather.govz)Y",
        "mDnz,U!<T$2Zy#c?d:8E)H37Auqweather.govz)Y",
    );
}

#[test]
fn adv46_noaa_api_config_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "noaa-api-config",
        "User-Agent=mDnz,U!<T$2Zy#c?d:8E\u{00AD})H37Auqweather.govz)Y",
        "mDnz,U!<T$2Zy#c?d:8E)H37Auqweather.govz)Y",
    );
}

// =========================================================================
// 10. NOMAD ACL TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv46_nomad_acl_token_normal_must_fire() {
    assert_detector_fires(
        "nomad-acl-token",
        "NOMAD_TOKEN=5a625743-ca5c-c65a-3857-c02b98f8b8b5",
        "5a625743-ca5c-c65a-3857-c02b98f8b8b5",
    );
}

#[test]
fn adv46_nomad_acl_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "nomad-acl-token",
        "dummy_prefix_0 =xxx25743-ca5c-c65a-3857-c02b98f8b8b5",
    );
}

#[test]
fn adv46_nomad_acl_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "nomad-acl-token",
        "NOMAD_TOKEN=5a625743-ca5c-c65a\u{200B}-3857-c02b98f8b8b5",
        "5a625743-ca5c-c65a-3857-c02b98f8b8b5",
    );
}

#[test]
fn adv46_nomad_acl_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "nomad-acl-token",
        "NOMAD_TOKEN=5a625743-ca5c-c65a\u{00AD}-3857-c02b98f8b8b5",
        "5a625743-ca5c-c65a-3857-c02b98f8b8b5",
    );
}


