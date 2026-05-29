//! Part 51 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates passbase, paychex, payload, paylocity, payoneer, percy, perfecto, perplexity, pexels, phrase detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. PASSBASE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv51_passbase_api_key_normal_must_fire() {
    assert_detector_fires(
        "passbase-api-key",
        "X-API-KEY=7VVpvY_rJEc_G33gXrRw",
        "7VVpvY_rJEc_G33gXrRw",
    );
}

#[test]
fn adv51_passbase_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "passbase-api-key",
        "dummy_prefix_0 =xxxpvY_rJEc_G33gXrRw",
    );
}

#[test]
fn adv51_passbase_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "passbase-api-key",
        "X-API-KEY=7VVpvY_rJE\u{200B}c_G33gXrRw",
        "7VVpvY_rJEc_G33gXrRw",
    );
}

#[test]
fn adv51_passbase_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "passbase-api-key",
        "X-API-KEY=7VVpvY_rJE\u{00AD}c_G33gXrRw",
        "7VVpvY_rJEc_G33gXrRw",
    );
}

// =========================================================================
// 2. PAYCHEX API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv51_paychex_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "paychex-api-credentials",
        "PAYCHEX_CLIENT_ID=L979NZXDahGSlqozkR8h",
        "L979NZXDahGSlqozkR8h",
    );
}

#[test]
fn adv51_paychex_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "paychex-api-credentials",
        "dummy_prefix_0 =xxx9NZXDahGSlqozkR8h",
    );
}

#[test]
fn adv51_paychex_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "paychex-api-credentials",
        "PAYCHEX_CLIENT_ID=L979NZXDah\u{200B}GSlqozkR8h",
        "L979NZXDahGSlqozkR8h",
    );
}

#[test]
fn adv51_paychex_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "paychex-api-credentials",
        "PAYCHEX_CLIENT_ID=L979NZXDah\u{00AD}GSlqozkR8h",
        "L979NZXDahGSlqozkR8h",
    );
}

// =========================================================================
// 3. PAYLOAD CMS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv51_payload_cms_api_key_normal_must_fire() {
    assert_detector_fires(
        "payload-cms-api-key",
        "PAYLOAD_API_KEY=c191374f-c337-41b5-4a8b-64b48783d13f",
        "c191374f-c337-41b5-4a8b-64b48783d13f",
    );
}

#[test]
fn adv51_payload_cms_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "payload-cms-api-key",
        "dummy_prefix_0 =xxx1374f-c337-41b5-4a8b-64b48783d13f",
    );
}

#[test]
fn adv51_payload_cms_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "payload-cms-api-key",
        "PAYLOAD_API_KEY=c191374f-c337-41b5\u{200B}-4a8b-64b48783d13f",
        "c191374f-c337-41b5-4a8b-64b48783d13f",
    );
}

#[test]
fn adv51_payload_cms_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "payload-cms-api-key",
        "PAYLOAD_API_KEY=c191374f-c337-41b5\u{00AD}-4a8b-64b48783d13f",
        "c191374f-c337-41b5-4a8b-64b48783d13f",
    );
}

// =========================================================================
// 4. PAYLOCITY API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv51_paylocity_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "paylocity-api-credentials",
        "PAYLOCITY_CLIENT_ID=3e3a5f82f7d330d5fc3da4cefedc7a9c",
        "3e3a5f82f7d330d5fc3da4cefedc7a9c",
    );
}

#[test]
fn adv51_paylocity_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "paylocity-api-credentials",
        "dummy_prefix_0 =xxxa5f82f7d330d5fc3da4cefedc7a9c",
    );
}

#[test]
fn adv51_paylocity_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "paylocity-api-credentials",
        "PAYLOCITY_CLIENT_ID=3e3a5f82f7d330d5\u{200B}fc3da4cefedc7a9c",
        "3e3a5f82f7d330d5fc3da4cefedc7a9c",
    );
}

#[test]
fn adv51_paylocity_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "paylocity-api-credentials",
        "PAYLOCITY_CLIENT_ID=3e3a5f82f7d330d5\u{00AD}fc3da4cefedc7a9c",
        "3e3a5f82f7d330d5fc3da4cefedc7a9c",
    );
}

// =========================================================================
// 5. PAYONEER API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv51_payoneer_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "payoneer-api-credentials",
        "PAYONEERCLIENTID=0XDdFBQiYgzN6zGNHJk7ky3v1b89yfc1DIbzaRI_hy",
        "0XDdFBQiYgzN6zGNHJk7ky3v1b89yfc1DIbzaRI_hy",
    );
}

#[test]
fn adv51_payoneer_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "payoneer-api-credentials",
        "dummy_prefix_0 =xxxdFBQiYgzN6zGNHJk7ky3v1b89yfc1DIbzaRI_hy",
    );
}

#[test]
fn adv51_payoneer_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "payoneer-api-credentials",
        "PAYONEERCLIENTID=0XDdFBQiYgzN6zGNHJk7k\u{200B}y3v1b89yfc1DIbzaRI_hy",
        "0XDdFBQiYgzN6zGNHJk7ky3v1b89yfc1DIbzaRI_hy",
    );
}

#[test]
fn adv51_payoneer_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "payoneer-api-credentials",
        "PAYONEERCLIENTID=0XDdFBQiYgzN6zGNHJk7k\u{00AD}y3v1b89yfc1DIbzaRI_hy",
        "0XDdFBQiYgzN6zGNHJk7ky3v1b89yfc1DIbzaRI_hy",
    );
}

// =========================================================================
// 6. PERCY TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv51_percy_token_normal_must_fire() {
    assert_detector_fires(
        "percy-token",
        "percy_h3KLZpjNQVXQtYzZ36cCBZ9ab39wZdGc",
        "percy_h3KLZpjNQVXQtYzZ36cCBZ9ab39wZdGc",
    );
}

#[test]
fn adv51_percy_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "percy-token",
        "dummyy_h3KLZpjNQVXQtYzZ36cCBZ9ab39wZdGc",
    );
}

#[test]
fn adv51_percy_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "percy-token",
        "percy_h3KLZpjNQVXQt\u{200B}YzZ36cCBZ9ab39wZdGc",
        "percy_h3KLZpjNQVXQtYzZ36cCBZ9ab39wZdGc",
    );
}

#[test]
fn adv51_percy_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "percy-token",
        "percy_h3KLZpjNQVXQt\u{00AD}YzZ36cCBZ9ab39wZdGc",
        "percy_h3KLZpjNQVXQtYzZ36cCBZ9ab39wZdGc",
    );
}

// =========================================================================
// 7. PERFECTO API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv51_perfecto_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "perfecto-api-credentials",
        "PERFECTO_TOKEN=2MAVAz2q7AI1W9P17EB71Wdb9ge0nhEj",
        "2MAVAz2q7AI1W9P17EB71Wdb9ge0nhEj",
    );
}

#[test]
fn adv51_perfecto_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "perfecto-api-credentials",
        "dummy_prefix_0 =xxxVAz2q7AI1W9P17EB71Wdb9ge0nhEj",
    );
}

#[test]
fn adv51_perfecto_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "perfecto-api-credentials",
        "PERFECTO_TOKEN=2MAVAz2q7AI1W9P1\u{200B}7EB71Wdb9ge0nhEj",
        "2MAVAz2q7AI1W9P17EB71Wdb9ge0nhEj",
    );
}

#[test]
fn adv51_perfecto_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "perfecto-api-credentials",
        "PERFECTO_TOKEN=2MAVAz2q7AI1W9P1\u{00AD}7EB71Wdb9ge0nhEj",
        "2MAVAz2q7AI1W9P17EB71Wdb9ge0nhEj",
    );
}

// =========================================================================
// 8. PERPLEXITY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv51_perplexity_api_key_normal_must_fire() {
    assert_detector_fires(
        "perplexity-api-key",
        "pplx-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
        "pplx-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv51_perplexity_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "perplexity-api-key",
        "dummy-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv51_perplexity_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "perplexity-api-key",
        "pplx-Kp4Qx7Rm2Sn5Tb\u{200B}8Vw3YzKp4Qx7Rm2Sn5Tb",
        "pplx-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv51_perplexity_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "perplexity-api-key",
        "pplx-Kp4Qx7Rm2Sn5Tb\u{00AD}8Vw3YzKp4Qx7Rm2Sn5Tb",
        "pplx-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

// =========================================================================
// 9. PEXELS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv51_pexels_api_key_normal_must_fire() {
    assert_detector_fires(
        "pexels-api-key",
        "PEXELS_API_KEY=YpnKhuwG7qqvltzETAtrtrXlv9srwh4TUnFDoNwKfurzDV3emeNiRpx8",
        "YpnKhuwG7qqvltzETAtrtrXlv9srwh4TUnFDoNwKfurzDV3emeNiRpx8",
    );
}

#[test]
fn adv51_pexels_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pexels-api-key",
        "dummy_prefix_0 =xxxKhuwG7qqvltzETAtrtrXlv9srwh4TUnFDoNwKfurzDV3emeNiRpx8",
    );
}

#[test]
fn adv51_pexels_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pexels-api-key",
        "PEXELS_API_KEY=YpnKhuwG7qqvltzETAtrtrXlv9sr\u{200B}wh4TUnFDoNwKfurzDV3emeNiRpx8",
        "YpnKhuwG7qqvltzETAtrtrXlv9srwh4TUnFDoNwKfurzDV3emeNiRpx8",
    );
}

#[test]
fn adv51_pexels_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pexels-api-key",
        "PEXELS_API_KEY=YpnKhuwG7qqvltzETAtrtrXlv9sr\u{00AD}wh4TUnFDoNwKfurzDV3emeNiRpx8",
        "YpnKhuwG7qqvltzETAtrtrXlv9srwh4TUnFDoNwKfurzDV3emeNiRpx8",
    );
}

// =========================================================================
// 10. PHRASE API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv51_phrase_api_token_normal_must_fire() {
    assert_detector_fires(
        "phrase-api-token",
        "PHRASE=d33dcb033f52664212c34c0219033d3846ba3ce5c38efd17",
        "d33dcb033f52664212c34c0219033d3846ba3ce5c38efd17",
    );
}

#[test]
fn adv51_phrase_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "phrase-api-token",
        "dummy_prefix_0 =xxxdcb033f52664212c34c0219033d3846ba3ce5c38efd17",
    );
}

#[test]
fn adv51_phrase_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "phrase-api-token",
        "PHRASE=d33dcb033f52664212c34c02\u{200B}19033d3846ba3ce5c38efd17",
        "d33dcb033f52664212c34c0219033d3846ba3ce5c38efd17",
    );
}

#[test]
fn adv51_phrase_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "phrase-api-token",
        "PHRASE=d33dcb033f52664212c34c02\u{00AD}19033d3846ba3ce5c38efd17",
        "d33dcb033f52664212c34c0219033d3846ba3ce5c38efd17",
    );
}


