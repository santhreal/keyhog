//! Part 98 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates intercom, internalio, invision, ip, ipinfo, istock, iterable, jaeger, japan, jetadmin detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. INTERCOM ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv98_intercom_access_token_normal_must_fire() {
    assert_detector_fires(
        "intercom-access-token",
        "dG9rKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpTr",
        "dG9rKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpTr",
    );
}

#[test]
fn adv98_intercom_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "intercom-access-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv98_intercom_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "intercom-access-token",
        "dG9rKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S\u{200B}n5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpTr",
        "dG9rKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpTr",
    );
}

#[test]
fn adv98_intercom_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "intercom-access-token",
        "dG9rKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S\u{00AD}n5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpTr",
        "dG9rKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpTr",
    );
}

#[test]
fn adv98_intercom_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "intercom-access-token",
        "dG9rKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S\u{200C}n5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpTr",
        "dG9rKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpTr",
    );
}

#[test]
fn adv98_intercom_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "intercom-access-token",
        "dG9rKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S\u{200D}n5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpTr",
        "dG9rKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpTr",
    );
}

#[test]
fn adv98_intercom_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "intercom-access-token",
        "dG9rKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S\u{FEFF}n5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpTr",
        "dG9rKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpTr",
    );
}

#[test]
fn adv98_intercom_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "intercom-access-token",
        "dG9rKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S\u{2060}n5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpTr",
        "dG9rKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpTr",
    );
}

#[test]
fn adv98_intercom_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "intercom-access-token",
        "dG9rKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S\u{180E}n5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpTr",
        "dG9rKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpTr",
    );
}

#[test]
fn adv98_intercom_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "intercom-access-token",
        "dG9rKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S\u{202E}n5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpTr",
        "dG9rKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpTr",
    );
}

#[test]
fn adv98_intercom_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "intercom-access-token",
        "dG9rKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S\u{202C}n5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpTr",
        "dG9rKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpTr",
    );
}

#[test]
fn adv98_intercom_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "intercom-access-token",
        "dG9rKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2S\u{200E}n5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpTr",
        "dG9rKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpTr",
    );
}

// =========================================================================
// 2. INTERNALIO CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv98_internalio_credentials_normal_must_fire() {
    assert_detector_fires(
        "internalio-credentials",
        "INTERNAL_API_KEY=Us3--opIWQZLTHv0vzgnO4VDodoNo44DYyi8zI6wJWxV",
        "Us3--opIWQZLTHv0vzgnO4VDodoNo44DYyi8zI6wJWxV",
    );
}

#[test]
fn adv98_internalio_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "internalio-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv98_internalio_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "internalio-credentials",
        "INTERNAL_API_KEY=Us3--opIWQZLTHv0vzgnO4\u{200B}VDodoNo44DYyi8zI6wJWxV",
        "Us3--opIWQZLTHv0vzgnO4VDodoNo44DYyi8zI6wJWxV",
    );
}

#[test]
fn adv98_internalio_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "internalio-credentials",
        "INTERNAL_API_KEY=Us3--opIWQZLTHv0vzgnO4\u{00AD}VDodoNo44DYyi8zI6wJWxV",
        "Us3--opIWQZLTHv0vzgnO4VDodoNo44DYyi8zI6wJWxV",
    );
}

#[test]
fn adv98_internalio_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "internalio-credentials",
        "INTERNAL_API_KEY=Us3--opIWQZLTHv0vzgnO4\u{200C}VDodoNo44DYyi8zI6wJWxV",
        "Us3--opIWQZLTHv0vzgnO4VDodoNo44DYyi8zI6wJWxV",
    );
}

#[test]
fn adv98_internalio_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "internalio-credentials",
        "INTERNAL_API_KEY=Us3--opIWQZLTHv0vzgnO4\u{200D}VDodoNo44DYyi8zI6wJWxV",
        "Us3--opIWQZLTHv0vzgnO4VDodoNo44DYyi8zI6wJWxV",
    );
}

#[test]
fn adv98_internalio_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "internalio-credentials",
        "INTERNAL_API_KEY=Us3--opIWQZLTHv0vzgnO4\u{FEFF}VDodoNo44DYyi8zI6wJWxV",
        "Us3--opIWQZLTHv0vzgnO4VDodoNo44DYyi8zI6wJWxV",
    );
}

#[test]
fn adv98_internalio_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "internalio-credentials",
        "INTERNAL_API_KEY=Us3--opIWQZLTHv0vzgnO4\u{2060}VDodoNo44DYyi8zI6wJWxV",
        "Us3--opIWQZLTHv0vzgnO4VDodoNo44DYyi8zI6wJWxV",
    );
}

#[test]
fn adv98_internalio_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "internalio-credentials",
        "INTERNAL_API_KEY=Us3--opIWQZLTHv0vzgnO4\u{180E}VDodoNo44DYyi8zI6wJWxV",
        "Us3--opIWQZLTHv0vzgnO4VDodoNo44DYyi8zI6wJWxV",
    );
}

#[test]
fn adv98_internalio_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "internalio-credentials",
        "INTERNAL_API_KEY=Us3--opIWQZLTHv0vzgnO4\u{202E}VDodoNo44DYyi8zI6wJWxV",
        "Us3--opIWQZLTHv0vzgnO4VDodoNo44DYyi8zI6wJWxV",
    );
}

#[test]
fn adv98_internalio_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "internalio-credentials",
        "INTERNAL_API_KEY=Us3--opIWQZLTHv0vzgnO4\u{202C}VDodoNo44DYyi8zI6wJWxV",
        "Us3--opIWQZLTHv0vzgnO4VDodoNo44DYyi8zI6wJWxV",
    );
}

#[test]
fn adv98_internalio_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "internalio-credentials",
        "INTERNAL_API_KEY=Us3--opIWQZLTHv0vzgnO4\u{200E}VDodoNo44DYyi8zI6wJWxV",
        "Us3--opIWQZLTHv0vzgnO4VDodoNo44DYyi8zI6wJWxV",
    );
}

// =========================================================================
// 3. INVISION API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv98_invision_api_key_normal_must_fire() {
    assert_detector_fires(
        "invision-api-key",
        "IPS4 api_key=2963950e3ed2e3dc49d5740982bac6a9",
        "2963950e3ed2e3dc49d5740982bac6a9",
    );
}

#[test]
fn adv98_invision_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "invision-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv98_invision_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "invision-api-key",
        "IPS4 api_key=2963950e3ed2e3dc\u{200B}49d5740982bac6a9",
        "2963950e3ed2e3dc49d5740982bac6a9",
    );
}

#[test]
fn adv98_invision_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "invision-api-key",
        "IPS4 api_key=2963950e3ed2e3dc\u{00AD}49d5740982bac6a9",
        "2963950e3ed2e3dc49d5740982bac6a9",
    );
}

#[test]
fn adv98_invision_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "invision-api-key",
        "IPS4 api_key=2963950e3ed2e3dc\u{200C}49d5740982bac6a9",
        "2963950e3ed2e3dc49d5740982bac6a9",
    );
}

#[test]
fn adv98_invision_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "invision-api-key",
        "IPS4 api_key=2963950e3ed2e3dc\u{200D}49d5740982bac6a9",
        "2963950e3ed2e3dc49d5740982bac6a9",
    );
}

#[test]
fn adv98_invision_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "invision-api-key",
        "IPS4 api_key=2963950e3ed2e3dc\u{FEFF}49d5740982bac6a9",
        "2963950e3ed2e3dc49d5740982bac6a9",
    );
}

#[test]
fn adv98_invision_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "invision-api-key",
        "IPS4 api_key=2963950e3ed2e3dc\u{2060}49d5740982bac6a9",
        "2963950e3ed2e3dc49d5740982bac6a9",
    );
}

#[test]
fn adv98_invision_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "invision-api-key",
        "IPS4 api_key=2963950e3ed2e3dc\u{180E}49d5740982bac6a9",
        "2963950e3ed2e3dc49d5740982bac6a9",
    );
}

#[test]
fn adv98_invision_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "invision-api-key",
        "IPS4 api_key=2963950e3ed2e3dc\u{202E}49d5740982bac6a9",
        "2963950e3ed2e3dc49d5740982bac6a9",
    );
}

#[test]
fn adv98_invision_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "invision-api-key",
        "IPS4 api_key=2963950e3ed2e3dc\u{202C}49d5740982bac6a9",
        "2963950e3ed2e3dc49d5740982bac6a9",
    );
}

#[test]
fn adv98_invision_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "invision-api-key",
        "IPS4 api_key=2963950e3ed2e3dc\u{200E}49d5740982bac6a9",
        "2963950e3ed2e3dc49d5740982bac6a9",
    );
}

// =========================================================================
// 4. IP API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv98_ip_api_credentials_normal_must_fire() {
    assert_detector_fires("ip-api-credentials", "IPAPI_KEY=WnGcEBigw6", "WnGcEBigw6");
}

#[test]
fn adv98_ip_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent("ip-api-credentials", "dummy_prefix_0 =xxxxxxxxxx");
}

#[test]
fn adv98_ip_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ip-api-credentials",
        "IPAPI_KEY=WnGcE\u{200B}Bigw6",
        "WnGcEBigw6",
    );
}

#[test]
fn adv98_ip_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ip-api-credentials",
        "IPAPI_KEY=WnGcE\u{00AD}Bigw6",
        "WnGcEBigw6",
    );
}

#[test]
fn adv98_ip_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "ip-api-credentials",
        "IPAPI_KEY=WnGcE\u{200C}Bigw6",
        "WnGcEBigw6",
    );
}

#[test]
fn adv98_ip_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "ip-api-credentials",
        "IPAPI_KEY=WnGcE\u{200D}Bigw6",
        "WnGcEBigw6",
    );
}

#[test]
fn adv98_ip_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "ip-api-credentials",
        "IPAPI_KEY=WnGcE\u{FEFF}Bigw6",
        "WnGcEBigw6",
    );
}

#[test]
fn adv98_ip_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "ip-api-credentials",
        "IPAPI_KEY=WnGcE\u{2060}Bigw6",
        "WnGcEBigw6",
    );
}

#[test]
fn adv98_ip_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "ip-api-credentials",
        "IPAPI_KEY=WnGcE\u{180E}Bigw6",
        "WnGcEBigw6",
    );
}

#[test]
fn adv98_ip_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "ip-api-credentials",
        "IPAPI_KEY=WnGcE\u{202E}Bigw6",
        "WnGcEBigw6",
    );
}

#[test]
fn adv98_ip_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "ip-api-credentials",
        "IPAPI_KEY=WnGcE\u{202C}Bigw6",
        "WnGcEBigw6",
    );
}

#[test]
fn adv98_ip_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "ip-api-credentials",
        "IPAPI_KEY=WnGcE\u{200E}Bigw6",
        "WnGcEBigw6",
    );
}

// =========================================================================
// 5. IPINFO API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv98_ipinfo_api_token_normal_must_fire() {
    assert_detector_fires("ipinfo-api-token", "IPINFO=ic1pO5L3hs", "ic1pO5L3hs");
}

#[test]
fn adv98_ipinfo_api_token_wrong_prefix_must_silent() {
    assert_detector_silent("ipinfo-api-token", "dummy_prefix_0 =xxxxxxxxxx");
}

#[test]
fn adv98_ipinfo_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ipinfo-api-token",
        "IPINFO=ic1pO\u{200B}5L3hs",
        "ic1pO5L3hs",
    );
}

#[test]
fn adv98_ipinfo_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ipinfo-api-token",
        "IPINFO=ic1pO\u{00AD}5L3hs",
        "ic1pO5L3hs",
    );
}

#[test]
fn adv98_ipinfo_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "ipinfo-api-token",
        "IPINFO=ic1pO\u{200C}5L3hs",
        "ic1pO5L3hs",
    );
}

#[test]
fn adv98_ipinfo_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "ipinfo-api-token",
        "IPINFO=ic1pO\u{200D}5L3hs",
        "ic1pO5L3hs",
    );
}

#[test]
fn adv98_ipinfo_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "ipinfo-api-token",
        "IPINFO=ic1pO\u{FEFF}5L3hs",
        "ic1pO5L3hs",
    );
}

#[test]
fn adv98_ipinfo_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "ipinfo-api-token",
        "IPINFO=ic1pO\u{2060}5L3hs",
        "ic1pO5L3hs",
    );
}

#[test]
fn adv98_ipinfo_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "ipinfo-api-token",
        "IPINFO=ic1pO\u{180E}5L3hs",
        "ic1pO5L3hs",
    );
}

#[test]
fn adv98_ipinfo_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "ipinfo-api-token",
        "IPINFO=ic1pO\u{202E}5L3hs",
        "ic1pO5L3hs",
    );
}

#[test]
fn adv98_ipinfo_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "ipinfo-api-token",
        "IPINFO=ic1pO\u{202C}5L3hs",
        "ic1pO5L3hs",
    );
}

#[test]
fn adv98_ipinfo_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "ipinfo-api-token",
        "IPINFO=ic1pO\u{200E}5L3hs",
        "ic1pO5L3hs",
    );
}

// =========================================================================
// 6. ISTOCK API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv98_istock_api_key_normal_must_fire() {
    assert_detector_fires(
        "istock-api-key",
        "ISTOCK_API_KEY=xqaL6boKvK9T28agUy-2UKclZ___ijuK",
        "xqaL6boKvK9T28agUy-2UKclZ___ijuK",
    );
}

#[test]
fn adv98_istock_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "istock-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv98_istock_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "istock-api-key",
        "ISTOCK_API_KEY=xqaL6boKvK9T28ag\u{200B}Uy-2UKclZ___ijuK",
        "xqaL6boKvK9T28agUy-2UKclZ___ijuK",
    );
}

#[test]
fn adv98_istock_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "istock-api-key",
        "ISTOCK_API_KEY=xqaL6boKvK9T28ag\u{00AD}Uy-2UKclZ___ijuK",
        "xqaL6boKvK9T28agUy-2UKclZ___ijuK",
    );
}

#[test]
fn adv98_istock_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "istock-api-key",
        "ISTOCK_API_KEY=xqaL6boKvK9T28ag\u{200C}Uy-2UKclZ___ijuK",
        "xqaL6boKvK9T28agUy-2UKclZ___ijuK",
    );
}

#[test]
fn adv98_istock_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "istock-api-key",
        "ISTOCK_API_KEY=xqaL6boKvK9T28ag\u{200D}Uy-2UKclZ___ijuK",
        "xqaL6boKvK9T28agUy-2UKclZ___ijuK",
    );
}

#[test]
fn adv98_istock_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "istock-api-key",
        "ISTOCK_API_KEY=xqaL6boKvK9T28ag\u{FEFF}Uy-2UKclZ___ijuK",
        "xqaL6boKvK9T28agUy-2UKclZ___ijuK",
    );
}

#[test]
fn adv98_istock_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "istock-api-key",
        "ISTOCK_API_KEY=xqaL6boKvK9T28ag\u{2060}Uy-2UKclZ___ijuK",
        "xqaL6boKvK9T28agUy-2UKclZ___ijuK",
    );
}

#[test]
fn adv98_istock_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "istock-api-key",
        "ISTOCK_API_KEY=xqaL6boKvK9T28ag\u{180E}Uy-2UKclZ___ijuK",
        "xqaL6boKvK9T28agUy-2UKclZ___ijuK",
    );
}

#[test]
fn adv98_istock_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "istock-api-key",
        "ISTOCK_API_KEY=xqaL6boKvK9T28ag\u{202E}Uy-2UKclZ___ijuK",
        "xqaL6boKvK9T28agUy-2UKclZ___ijuK",
    );
}

#[test]
fn adv98_istock_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "istock-api-key",
        "ISTOCK_API_KEY=xqaL6boKvK9T28ag\u{202C}Uy-2UKclZ___ijuK",
        "xqaL6boKvK9T28agUy-2UKclZ___ijuK",
    );
}

#[test]
fn adv98_istock_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "istock-api-key",
        "ISTOCK_API_KEY=xqaL6boKvK9T28ag\u{200E}Uy-2UKclZ___ijuK",
        "xqaL6boKvK9T28agUy-2UKclZ___ijuK",
    );
}

// =========================================================================
// 7. ITERABLE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv98_iterable_api_key_normal_must_fire() {
    assert_detector_fires(
        "iterable-api-key",
        "ITERABLE=425d50e126cedeee2e523de4e609df80",
        "425d50e126cedeee2e523de4e609df80",
    );
}

#[test]
fn adv98_iterable_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "iterable-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv98_iterable_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "iterable-api-key",
        "ITERABLE=425d50e126cedeee\u{200B}2e523de4e609df80",
        "425d50e126cedeee2e523de4e609df80",
    );
}

#[test]
fn adv98_iterable_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "iterable-api-key",
        "ITERABLE=425d50e126cedeee\u{00AD}2e523de4e609df80",
        "425d50e126cedeee2e523de4e609df80",
    );
}

#[test]
fn adv98_iterable_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "iterable-api-key",
        "ITERABLE=425d50e126cedeee\u{200C}2e523de4e609df80",
        "425d50e126cedeee2e523de4e609df80",
    );
}

#[test]
fn adv98_iterable_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "iterable-api-key",
        "ITERABLE=425d50e126cedeee\u{200D}2e523de4e609df80",
        "425d50e126cedeee2e523de4e609df80",
    );
}

#[test]
fn adv98_iterable_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "iterable-api-key",
        "ITERABLE=425d50e126cedeee\u{FEFF}2e523de4e609df80",
        "425d50e126cedeee2e523de4e609df80",
    );
}

#[test]
fn adv98_iterable_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "iterable-api-key",
        "ITERABLE=425d50e126cedeee\u{2060}2e523de4e609df80",
        "425d50e126cedeee2e523de4e609df80",
    );
}

#[test]
fn adv98_iterable_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "iterable-api-key",
        "ITERABLE=425d50e126cedeee\u{180E}2e523de4e609df80",
        "425d50e126cedeee2e523de4e609df80",
    );
}

#[test]
fn adv98_iterable_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "iterable-api-key",
        "ITERABLE=425d50e126cedeee\u{202E}2e523de4e609df80",
        "425d50e126cedeee2e523de4e609df80",
    );
}

#[test]
fn adv98_iterable_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "iterable-api-key",
        "ITERABLE=425d50e126cedeee\u{202C}2e523de4e609df80",
        "425d50e126cedeee2e523de4e609df80",
    );
}

#[test]
fn adv98_iterable_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "iterable-api-key",
        "ITERABLE=425d50e126cedeee\u{200E}2e523de4e609df80",
        "425d50e126cedeee2e523de4e609df80",
    );
}

// =========================================================================
// 8. JAEGER CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv98_jaeger_credentials_normal_must_fire() {
    assert_detector_fires(
        "jaeger-credentials",
        "JAEGER_USERNAME=JJgWiH4Sq8qCfjalCt9tVyDklNVKAdeZ",
        "JJgWiH4Sq8qCfjalCt9tVyDklNVKAdeZ",
    );
}

#[test]
fn adv98_jaeger_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "jaeger-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv98_jaeger_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "jaeger-credentials",
        "JAEGER_USERNAME=JJgWiH4Sq8qCfjal\u{200B}Ct9tVyDklNVKAdeZ",
        "JJgWiH4Sq8qCfjalCt9tVyDklNVKAdeZ",
    );
}

#[test]
fn adv98_jaeger_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "jaeger-credentials",
        "JAEGER_USERNAME=JJgWiH4Sq8qCfjal\u{00AD}Ct9tVyDklNVKAdeZ",
        "JJgWiH4Sq8qCfjalCt9tVyDklNVKAdeZ",
    );
}

#[test]
fn adv98_jaeger_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "jaeger-credentials",
        "JAEGER_USERNAME=JJgWiH4Sq8qCfjal\u{200C}Ct9tVyDklNVKAdeZ",
        "JJgWiH4Sq8qCfjalCt9tVyDklNVKAdeZ",
    );
}

#[test]
fn adv98_jaeger_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "jaeger-credentials",
        "JAEGER_USERNAME=JJgWiH4Sq8qCfjal\u{200D}Ct9tVyDklNVKAdeZ",
        "JJgWiH4Sq8qCfjalCt9tVyDklNVKAdeZ",
    );
}

#[test]
fn adv98_jaeger_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "jaeger-credentials",
        "JAEGER_USERNAME=JJgWiH4Sq8qCfjal\u{FEFF}Ct9tVyDklNVKAdeZ",
        "JJgWiH4Sq8qCfjalCt9tVyDklNVKAdeZ",
    );
}

#[test]
fn adv98_jaeger_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "jaeger-credentials",
        "JAEGER_USERNAME=JJgWiH4Sq8qCfjal\u{2060}Ct9tVyDklNVKAdeZ",
        "JJgWiH4Sq8qCfjalCt9tVyDklNVKAdeZ",
    );
}

#[test]
fn adv98_jaeger_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "jaeger-credentials",
        "JAEGER_USERNAME=JJgWiH4Sq8qCfjal\u{180E}Ct9tVyDklNVKAdeZ",
        "JJgWiH4Sq8qCfjalCt9tVyDklNVKAdeZ",
    );
}

#[test]
fn adv98_jaeger_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "jaeger-credentials",
        "JAEGER_USERNAME=JJgWiH4Sq8qCfjal\u{202E}Ct9tVyDklNVKAdeZ",
        "JJgWiH4Sq8qCfjalCt9tVyDklNVKAdeZ",
    );
}

#[test]
fn adv98_jaeger_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "jaeger-credentials",
        "JAEGER_USERNAME=JJgWiH4Sq8qCfjal\u{202C}Ct9tVyDklNVKAdeZ",
        "JJgWiH4Sq8qCfjalCt9tVyDklNVKAdeZ",
    );
}

#[test]
fn adv98_jaeger_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "jaeger-credentials",
        "JAEGER_USERNAME=JJgWiH4Sq8qCfjal\u{200E}Ct9tVyDklNVKAdeZ",
        "JJgWiH4Sq8qCfjalCt9tVyDklNVKAdeZ",
    );
}

// =========================================================================
// 9. JAPAN EGOV API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv98_japan_egov_api_key_normal_must_fire() {
    assert_detector_fires(
        "japan-egov-api-key",
        "e-Statapi_key=8K2IWCe8Ib6RIp7hlOzI",
        "8K2IWCe8Ib6RIp7hlOzI",
    );
}

#[test]
fn adv98_japan_egov_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("japan-egov-api-key", "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv98_japan_egov_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "japan-egov-api-key",
        "e-Statapi_key=8K2IWCe8Ib\u{200B}6RIp7hlOzI",
        "8K2IWCe8Ib6RIp7hlOzI",
    );
}

#[test]
fn adv98_japan_egov_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "japan-egov-api-key",
        "e-Statapi_key=8K2IWCe8Ib\u{00AD}6RIp7hlOzI",
        "8K2IWCe8Ib6RIp7hlOzI",
    );
}

#[test]
fn adv98_japan_egov_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "japan-egov-api-key",
        "e-Statapi_key=8K2IWCe8Ib\u{200C}6RIp7hlOzI",
        "8K2IWCe8Ib6RIp7hlOzI",
    );
}

#[test]
fn adv98_japan_egov_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "japan-egov-api-key",
        "e-Statapi_key=8K2IWCe8Ib\u{200D}6RIp7hlOzI",
        "8K2IWCe8Ib6RIp7hlOzI",
    );
}

#[test]
fn adv98_japan_egov_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "japan-egov-api-key",
        "e-Statapi_key=8K2IWCe8Ib\u{FEFF}6RIp7hlOzI",
        "8K2IWCe8Ib6RIp7hlOzI",
    );
}

#[test]
fn adv98_japan_egov_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "japan-egov-api-key",
        "e-Statapi_key=8K2IWCe8Ib\u{2060}6RIp7hlOzI",
        "8K2IWCe8Ib6RIp7hlOzI",
    );
}

#[test]
fn adv98_japan_egov_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "japan-egov-api-key",
        "e-Statapi_key=8K2IWCe8Ib\u{180E}6RIp7hlOzI",
        "8K2IWCe8Ib6RIp7hlOzI",
    );
}

#[test]
fn adv98_japan_egov_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "japan-egov-api-key",
        "e-Statapi_key=8K2IWCe8Ib\u{202E}6RIp7hlOzI",
        "8K2IWCe8Ib6RIp7hlOzI",
    );
}

#[test]
fn adv98_japan_egov_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "japan-egov-api-key",
        "e-Statapi_key=8K2IWCe8Ib\u{202C}6RIp7hlOzI",
        "8K2IWCe8Ib6RIp7hlOzI",
    );
}

#[test]
fn adv98_japan_egov_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "japan-egov-api-key",
        "e-Statapi_key=8K2IWCe8Ib\u{200E}6RIp7hlOzI",
        "8K2IWCe8Ib6RIp7hlOzI",
    );
}

// =========================================================================
// 10. JETADMIN CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv98_jetadmin_credentials_normal_must_fire() {
    assert_detector_fires(
        "jetadmin-credentials",
        "JETADMIN_API_KEY=n-vvhk24chLYNYgsYTCfMLag",
        "n-vvhk24chLYNYgsYTCfMLag",
    );
}

#[test]
fn adv98_jetadmin_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "jetadmin-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv98_jetadmin_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "jetadmin-credentials",
        "JETADMIN_API_KEY=n-vvhk24chLY\u{200B}NYgsYTCfMLag",
        "n-vvhk24chLYNYgsYTCfMLag",
    );
}

#[test]
fn adv98_jetadmin_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "jetadmin-credentials",
        "JETADMIN_API_KEY=n-vvhk24chLY\u{00AD}NYgsYTCfMLag",
        "n-vvhk24chLYNYgsYTCfMLag",
    );
}

#[test]
fn adv98_jetadmin_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "jetadmin-credentials",
        "JETADMIN_API_KEY=n-vvhk24chLY\u{200C}NYgsYTCfMLag",
        "n-vvhk24chLYNYgsYTCfMLag",
    );
}

#[test]
fn adv98_jetadmin_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "jetadmin-credentials",
        "JETADMIN_API_KEY=n-vvhk24chLY\u{200D}NYgsYTCfMLag",
        "n-vvhk24chLYNYgsYTCfMLag",
    );
}

#[test]
fn adv98_jetadmin_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "jetadmin-credentials",
        "JETADMIN_API_KEY=n-vvhk24chLY\u{FEFF}NYgsYTCfMLag",
        "n-vvhk24chLYNYgsYTCfMLag",
    );
}

#[test]
fn adv98_jetadmin_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "jetadmin-credentials",
        "JETADMIN_API_KEY=n-vvhk24chLY\u{2060}NYgsYTCfMLag",
        "n-vvhk24chLYNYgsYTCfMLag",
    );
}

#[test]
fn adv98_jetadmin_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "jetadmin-credentials",
        "JETADMIN_API_KEY=n-vvhk24chLY\u{180E}NYgsYTCfMLag",
        "n-vvhk24chLYNYgsYTCfMLag",
    );
}

#[test]
fn adv98_jetadmin_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "jetadmin-credentials",
        "JETADMIN_API_KEY=n-vvhk24chLY\u{202E}NYgsYTCfMLag",
        "n-vvhk24chLYNYgsYTCfMLag",
    );
}

#[test]
fn adv98_jetadmin_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "jetadmin-credentials",
        "JETADMIN_API_KEY=n-vvhk24chLY\u{202C}NYgsYTCfMLag",
        "n-vvhk24chLYNYgsYTCfMLag",
    );
}

#[test]
fn adv98_jetadmin_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "jetadmin-credentials",
        "JETADMIN_API_KEY=n-vvhk24chLY\u{200E}NYgsYTCfMLag",
        "n-vvhk24chLYNYgsYTCfMLag",
    );
}
