//! Part 115 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates paylocity, payoneer, percy, perfecto, perplexity, pexels, phrase, pinecone, pingdom, pinterest detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. PAYLOCITY API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv115_paylocity_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "paylocity-api-credentials",
        "PAYLOCITY_CLIENT_ID=3e3a5f82f7d330d5fc3da4cefedc7a9c",
        "3e3a5f82f7d330d5fc3da4cefedc7a9c",
    );
}

#[test]
fn adv115_paylocity_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "paylocity-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv115_paylocity_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "paylocity-api-credentials",
        "PAYLOCITY_CLIENT_ID=3e3a5f82f7d330d5\u{200B}fc3da4cefedc7a9c",
        "3e3a5f82f7d330d5fc3da4cefedc7a9c",
    );
}

#[test]
fn adv115_paylocity_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "paylocity-api-credentials",
        "PAYLOCITY_CLIENT_ID=3e3a5f82f7d330d5\u{00AD}fc3da4cefedc7a9c",
        "3e3a5f82f7d330d5fc3da4cefedc7a9c",
    );
}

#[test]
fn adv115_paylocity_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "paylocity-api-credentials",
        "PAYLOCITY_CLIENT_ID=3e3a5f82f7d330d5\u{200C}fc3da4cefedc7a9c",
        "3e3a5f82f7d330d5fc3da4cefedc7a9c",
    );
}

#[test]
fn adv115_paylocity_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "paylocity-api-credentials",
        "PAYLOCITY_CLIENT_ID=3e3a5f82f7d330d5\u{200D}fc3da4cefedc7a9c",
        "3e3a5f82f7d330d5fc3da4cefedc7a9c",
    );
}

#[test]
fn adv115_paylocity_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "paylocity-api-credentials",
        "PAYLOCITY_CLIENT_ID=3e3a5f82f7d330d5\u{FEFF}fc3da4cefedc7a9c",
        "3e3a5f82f7d330d5fc3da4cefedc7a9c",
    );
}

#[test]
fn adv115_paylocity_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "paylocity-api-credentials",
        "PAYLOCITY_CLIENT_ID=3e3a5f82f7d330d5\u{2060}fc3da4cefedc7a9c",
        "3e3a5f82f7d330d5fc3da4cefedc7a9c",
    );
}

#[test]
fn adv115_paylocity_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "paylocity-api-credentials",
        "PAYLOCITY_CLIENT_ID=3e3a5f82f7d330d5\u{180E}fc3da4cefedc7a9c",
        "3e3a5f82f7d330d5fc3da4cefedc7a9c",
    );
}

#[test]
fn adv115_paylocity_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "paylocity-api-credentials",
        "PAYLOCITY_CLIENT_ID=3e3a5f82f7d330d5\u{202E}fc3da4cefedc7a9c",
        "3e3a5f82f7d330d5fc3da4cefedc7a9c",
    );
}

#[test]
fn adv115_paylocity_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "paylocity-api-credentials",
        "PAYLOCITY_CLIENT_ID=3e3a5f82f7d330d5\u{202C}fc3da4cefedc7a9c",
        "3e3a5f82f7d330d5fc3da4cefedc7a9c",
    );
}

#[test]
fn adv115_paylocity_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "paylocity-api-credentials",
        "PAYLOCITY_CLIENT_ID=3e3a5f82f7d330d5\u{200E}fc3da4cefedc7a9c",
        "3e3a5f82f7d330d5fc3da4cefedc7a9c",
    );
}

// =========================================================================
// 2. PAYONEER API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv115_payoneer_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "payoneer-api-credentials",
        "PAYONEERCLIENTID=0XDdFBQiYgzN6zGNHJk7ky3v1b89yfc1DIbzaRI_hy",
        "0XDdFBQiYgzN6zGNHJk7ky3v1b89yfc1DIbzaRI_hy",
    );
}

#[test]
fn adv115_payoneer_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "payoneer-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv115_payoneer_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "payoneer-api-credentials",
        "PAYONEERCLIENTID=0XDdFBQiYgzN6zGNHJk7k\u{200B}y3v1b89yfc1DIbzaRI_hy",
        "0XDdFBQiYgzN6zGNHJk7ky3v1b89yfc1DIbzaRI_hy",
    );
}

#[test]
fn adv115_payoneer_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "payoneer-api-credentials",
        "PAYONEERCLIENTID=0XDdFBQiYgzN6zGNHJk7k\u{00AD}y3v1b89yfc1DIbzaRI_hy",
        "0XDdFBQiYgzN6zGNHJk7ky3v1b89yfc1DIbzaRI_hy",
    );
}

#[test]
fn adv115_payoneer_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "payoneer-api-credentials",
        "PAYONEERCLIENTID=0XDdFBQiYgzN6zGNHJk7k\u{200C}y3v1b89yfc1DIbzaRI_hy",
        "0XDdFBQiYgzN6zGNHJk7ky3v1b89yfc1DIbzaRI_hy",
    );
}

#[test]
fn adv115_payoneer_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "payoneer-api-credentials",
        "PAYONEERCLIENTID=0XDdFBQiYgzN6zGNHJk7k\u{200D}y3v1b89yfc1DIbzaRI_hy",
        "0XDdFBQiYgzN6zGNHJk7ky3v1b89yfc1DIbzaRI_hy",
    );
}

#[test]
fn adv115_payoneer_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "payoneer-api-credentials",
        "PAYONEERCLIENTID=0XDdFBQiYgzN6zGNHJk7k\u{FEFF}y3v1b89yfc1DIbzaRI_hy",
        "0XDdFBQiYgzN6zGNHJk7ky3v1b89yfc1DIbzaRI_hy",
    );
}

#[test]
fn adv115_payoneer_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "payoneer-api-credentials",
        "PAYONEERCLIENTID=0XDdFBQiYgzN6zGNHJk7k\u{2060}y3v1b89yfc1DIbzaRI_hy",
        "0XDdFBQiYgzN6zGNHJk7ky3v1b89yfc1DIbzaRI_hy",
    );
}

#[test]
fn adv115_payoneer_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "payoneer-api-credentials",
        "PAYONEERCLIENTID=0XDdFBQiYgzN6zGNHJk7k\u{180E}y3v1b89yfc1DIbzaRI_hy",
        "0XDdFBQiYgzN6zGNHJk7ky3v1b89yfc1DIbzaRI_hy",
    );
}

#[test]
fn adv115_payoneer_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "payoneer-api-credentials",
        "PAYONEERCLIENTID=0XDdFBQiYgzN6zGNHJk7k\u{202E}y3v1b89yfc1DIbzaRI_hy",
        "0XDdFBQiYgzN6zGNHJk7ky3v1b89yfc1DIbzaRI_hy",
    );
}

#[test]
fn adv115_payoneer_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "payoneer-api-credentials",
        "PAYONEERCLIENTID=0XDdFBQiYgzN6zGNHJk7k\u{202C}y3v1b89yfc1DIbzaRI_hy",
        "0XDdFBQiYgzN6zGNHJk7ky3v1b89yfc1DIbzaRI_hy",
    );
}

#[test]
fn adv115_payoneer_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "payoneer-api-credentials",
        "PAYONEERCLIENTID=0XDdFBQiYgzN6zGNHJk7k\u{200E}y3v1b89yfc1DIbzaRI_hy",
        "0XDdFBQiYgzN6zGNHJk7ky3v1b89yfc1DIbzaRI_hy",
    );
}

// =========================================================================
// 3. PERCY TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv115_percy_token_normal_must_fire() {
    assert_detector_fires(
        "percy-token",
        "percy_h3KLZpjNQVXQtYzZ36cCBZ9ab39wZdGc",
        "percy_h3KLZpjNQVXQtYzZ36cCBZ9ab39wZdGc",
    );
}

#[test]
fn adv115_percy_token_wrong_prefix_must_silent() {
    assert_detector_silent("percy-token", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv115_percy_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "percy-token",
        "percy_h3KLZpjNQVXQt\u{200B}YzZ36cCBZ9ab39wZdGc",
        "percy_h3KLZpjNQVXQtYzZ36cCBZ9ab39wZdGc",
    );
}

#[test]
fn adv115_percy_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "percy-token",
        "percy_h3KLZpjNQVXQt\u{00AD}YzZ36cCBZ9ab39wZdGc",
        "percy_h3KLZpjNQVXQtYzZ36cCBZ9ab39wZdGc",
    );
}

#[test]
fn adv115_percy_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "percy-token",
        "percy_h3KLZpjNQVXQt\u{200C}YzZ36cCBZ9ab39wZdGc",
        "percy_h3KLZpjNQVXQtYzZ36cCBZ9ab39wZdGc",
    );
}

#[test]
fn adv115_percy_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "percy-token",
        "percy_h3KLZpjNQVXQt\u{200D}YzZ36cCBZ9ab39wZdGc",
        "percy_h3KLZpjNQVXQtYzZ36cCBZ9ab39wZdGc",
    );
}

#[test]
fn adv115_percy_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "percy-token",
        "percy_h3KLZpjNQVXQt\u{FEFF}YzZ36cCBZ9ab39wZdGc",
        "percy_h3KLZpjNQVXQtYzZ36cCBZ9ab39wZdGc",
    );
}

#[test]
fn adv115_percy_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "percy-token",
        "percy_h3KLZpjNQVXQt\u{2060}YzZ36cCBZ9ab39wZdGc",
        "percy_h3KLZpjNQVXQtYzZ36cCBZ9ab39wZdGc",
    );
}

#[test]
fn adv115_percy_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "percy-token",
        "percy_h3KLZpjNQVXQt\u{180E}YzZ36cCBZ9ab39wZdGc",
        "percy_h3KLZpjNQVXQtYzZ36cCBZ9ab39wZdGc",
    );
}

#[test]
fn adv115_percy_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "percy-token",
        "percy_h3KLZpjNQVXQt\u{202E}YzZ36cCBZ9ab39wZdGc",
        "percy_h3KLZpjNQVXQtYzZ36cCBZ9ab39wZdGc",
    );
}

#[test]
fn adv115_percy_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "percy-token",
        "percy_h3KLZpjNQVXQt\u{202C}YzZ36cCBZ9ab39wZdGc",
        "percy_h3KLZpjNQVXQtYzZ36cCBZ9ab39wZdGc",
    );
}

#[test]
fn adv115_percy_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "percy-token",
        "percy_h3KLZpjNQVXQt\u{200E}YzZ36cCBZ9ab39wZdGc",
        "percy_h3KLZpjNQVXQtYzZ36cCBZ9ab39wZdGc",
    );
}

// =========================================================================
// 4. PERFECTO API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv115_perfecto_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "perfecto-api-credentials",
        "PERFECTO_TOKEN=2MAVAz2q7AI1W9P17EB71Wdb9ge0nhEj",
        "2MAVAz2q7AI1W9P17EB71Wdb9ge0nhEj",
    );
}

#[test]
fn adv115_perfecto_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "perfecto-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv115_perfecto_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "perfecto-api-credentials",
        "PERFECTO_TOKEN=2MAVAz2q7AI1W9P1\u{200B}7EB71Wdb9ge0nhEj",
        "2MAVAz2q7AI1W9P17EB71Wdb9ge0nhEj",
    );
}

#[test]
fn adv115_perfecto_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "perfecto-api-credentials",
        "PERFECTO_TOKEN=2MAVAz2q7AI1W9P1\u{00AD}7EB71Wdb9ge0nhEj",
        "2MAVAz2q7AI1W9P17EB71Wdb9ge0nhEj",
    );
}

#[test]
fn adv115_perfecto_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "perfecto-api-credentials",
        "PERFECTO_TOKEN=2MAVAz2q7AI1W9P1\u{200C}7EB71Wdb9ge0nhEj",
        "2MAVAz2q7AI1W9P17EB71Wdb9ge0nhEj",
    );
}

#[test]
fn adv115_perfecto_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "perfecto-api-credentials",
        "PERFECTO_TOKEN=2MAVAz2q7AI1W9P1\u{200D}7EB71Wdb9ge0nhEj",
        "2MAVAz2q7AI1W9P17EB71Wdb9ge0nhEj",
    );
}

#[test]
fn adv115_perfecto_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "perfecto-api-credentials",
        "PERFECTO_TOKEN=2MAVAz2q7AI1W9P1\u{FEFF}7EB71Wdb9ge0nhEj",
        "2MAVAz2q7AI1W9P17EB71Wdb9ge0nhEj",
    );
}

#[test]
fn adv115_perfecto_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "perfecto-api-credentials",
        "PERFECTO_TOKEN=2MAVAz2q7AI1W9P1\u{2060}7EB71Wdb9ge0nhEj",
        "2MAVAz2q7AI1W9P17EB71Wdb9ge0nhEj",
    );
}

#[test]
fn adv115_perfecto_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "perfecto-api-credentials",
        "PERFECTO_TOKEN=2MAVAz2q7AI1W9P1\u{180E}7EB71Wdb9ge0nhEj",
        "2MAVAz2q7AI1W9P17EB71Wdb9ge0nhEj",
    );
}

#[test]
fn adv115_perfecto_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "perfecto-api-credentials",
        "PERFECTO_TOKEN=2MAVAz2q7AI1W9P1\u{202E}7EB71Wdb9ge0nhEj",
        "2MAVAz2q7AI1W9P17EB71Wdb9ge0nhEj",
    );
}

#[test]
fn adv115_perfecto_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "perfecto-api-credentials",
        "PERFECTO_TOKEN=2MAVAz2q7AI1W9P1\u{202C}7EB71Wdb9ge0nhEj",
        "2MAVAz2q7AI1W9P17EB71Wdb9ge0nhEj",
    );
}

#[test]
fn adv115_perfecto_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "perfecto-api-credentials",
        "PERFECTO_TOKEN=2MAVAz2q7AI1W9P1\u{200E}7EB71Wdb9ge0nhEj",
        "2MAVAz2q7AI1W9P17EB71Wdb9ge0nhEj",
    );
}

// =========================================================================
// 5. PERPLEXITY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv115_perplexity_api_key_normal_must_fire() {
    assert_detector_fires(
        "perplexity-api-key",
        "pplx-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
        "pplx-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv115_perplexity_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "perplexity-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv115_perplexity_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "perplexity-api-key",
        "pplx-Kp4Qx7Rm2Sn5Tb\u{200B}8Vw3YzKp4Qx7Rm2Sn5Tb",
        "pplx-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv115_perplexity_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "perplexity-api-key",
        "pplx-Kp4Qx7Rm2Sn5Tb\u{00AD}8Vw3YzKp4Qx7Rm2Sn5Tb",
        "pplx-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv115_perplexity_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "perplexity-api-key",
        "pplx-Kp4Qx7Rm2Sn5Tb\u{200C}8Vw3YzKp4Qx7Rm2Sn5Tb",
        "pplx-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv115_perplexity_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "perplexity-api-key",
        "pplx-Kp4Qx7Rm2Sn5Tb\u{200D}8Vw3YzKp4Qx7Rm2Sn5Tb",
        "pplx-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv115_perplexity_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "perplexity-api-key",
        "pplx-Kp4Qx7Rm2Sn5Tb\u{FEFF}8Vw3YzKp4Qx7Rm2Sn5Tb",
        "pplx-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv115_perplexity_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "perplexity-api-key",
        "pplx-Kp4Qx7Rm2Sn5Tb\u{2060}8Vw3YzKp4Qx7Rm2Sn5Tb",
        "pplx-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv115_perplexity_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "perplexity-api-key",
        "pplx-Kp4Qx7Rm2Sn5Tb\u{180E}8Vw3YzKp4Qx7Rm2Sn5Tb",
        "pplx-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv115_perplexity_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "perplexity-api-key",
        "pplx-Kp4Qx7Rm2Sn5Tb\u{202E}8Vw3YzKp4Qx7Rm2Sn5Tb",
        "pplx-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv115_perplexity_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "perplexity-api-key",
        "pplx-Kp4Qx7Rm2Sn5Tb\u{202C}8Vw3YzKp4Qx7Rm2Sn5Tb",
        "pplx-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv115_perplexity_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "perplexity-api-key",
        "pplx-Kp4Qx7Rm2Sn5Tb\u{200E}8Vw3YzKp4Qx7Rm2Sn5Tb",
        "pplx-Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

// =========================================================================
// 6. PEXELS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv115_pexels_api_key_normal_must_fire() {
    assert_detector_fires(
        "pexels-api-key",
        "PEXELS_API_KEY=YpnKhuwG7qqvltzETAtrtrXlv9srwh4TUnFDoNwKfurzDV3emeNiRpx8",
        "YpnKhuwG7qqvltzETAtrtrXlv9srwh4TUnFDoNwKfurzDV3emeNiRpx8",
    );
}

#[test]
fn adv115_pexels_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pexels-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv115_pexels_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pexels-api-key",
        "PEXELS_API_KEY=YpnKhuwG7qqvltzETAtrtrXlv9sr\u{200B}wh4TUnFDoNwKfurzDV3emeNiRpx8",
        "YpnKhuwG7qqvltzETAtrtrXlv9srwh4TUnFDoNwKfurzDV3emeNiRpx8",
    );
}

#[test]
fn adv115_pexels_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pexels-api-key",
        "PEXELS_API_KEY=YpnKhuwG7qqvltzETAtrtrXlv9sr\u{00AD}wh4TUnFDoNwKfurzDV3emeNiRpx8",
        "YpnKhuwG7qqvltzETAtrtrXlv9srwh4TUnFDoNwKfurzDV3emeNiRpx8",
    );
}

#[test]
fn adv115_pexels_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "pexels-api-key",
        "PEXELS_API_KEY=YpnKhuwG7qqvltzETAtrtrXlv9sr\u{200C}wh4TUnFDoNwKfurzDV3emeNiRpx8",
        "YpnKhuwG7qqvltzETAtrtrXlv9srwh4TUnFDoNwKfurzDV3emeNiRpx8",
    );
}

#[test]
fn adv115_pexels_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "pexels-api-key",
        "PEXELS_API_KEY=YpnKhuwG7qqvltzETAtrtrXlv9sr\u{200D}wh4TUnFDoNwKfurzDV3emeNiRpx8",
        "YpnKhuwG7qqvltzETAtrtrXlv9srwh4TUnFDoNwKfurzDV3emeNiRpx8",
    );
}

#[test]
fn adv115_pexels_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "pexels-api-key",
        "PEXELS_API_KEY=YpnKhuwG7qqvltzETAtrtrXlv9sr\u{FEFF}wh4TUnFDoNwKfurzDV3emeNiRpx8",
        "YpnKhuwG7qqvltzETAtrtrXlv9srwh4TUnFDoNwKfurzDV3emeNiRpx8",
    );
}

#[test]
fn adv115_pexels_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "pexels-api-key",
        "PEXELS_API_KEY=YpnKhuwG7qqvltzETAtrtrXlv9sr\u{2060}wh4TUnFDoNwKfurzDV3emeNiRpx8",
        "YpnKhuwG7qqvltzETAtrtrXlv9srwh4TUnFDoNwKfurzDV3emeNiRpx8",
    );
}

#[test]
fn adv115_pexels_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "pexels-api-key",
        "PEXELS_API_KEY=YpnKhuwG7qqvltzETAtrtrXlv9sr\u{180E}wh4TUnFDoNwKfurzDV3emeNiRpx8",
        "YpnKhuwG7qqvltzETAtrtrXlv9srwh4TUnFDoNwKfurzDV3emeNiRpx8",
    );
}

#[test]
fn adv115_pexels_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "pexels-api-key",
        "PEXELS_API_KEY=YpnKhuwG7qqvltzETAtrtrXlv9sr\u{202E}wh4TUnFDoNwKfurzDV3emeNiRpx8",
        "YpnKhuwG7qqvltzETAtrtrXlv9srwh4TUnFDoNwKfurzDV3emeNiRpx8",
    );
}

#[test]
fn adv115_pexels_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "pexels-api-key",
        "PEXELS_API_KEY=YpnKhuwG7qqvltzETAtrtrXlv9sr\u{202C}wh4TUnFDoNwKfurzDV3emeNiRpx8",
        "YpnKhuwG7qqvltzETAtrtrXlv9srwh4TUnFDoNwKfurzDV3emeNiRpx8",
    );
}

#[test]
fn adv115_pexels_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "pexels-api-key",
        "PEXELS_API_KEY=YpnKhuwG7qqvltzETAtrtrXlv9sr\u{200E}wh4TUnFDoNwKfurzDV3emeNiRpx8",
        "YpnKhuwG7qqvltzETAtrtrXlv9srwh4TUnFDoNwKfurzDV3emeNiRpx8",
    );
}

// =========================================================================
// 7. PHRASE API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv115_phrase_api_token_normal_must_fire() {
    assert_detector_fires(
        "phrase-api-token",
        "PHRASE=d33dcb033f52664212c34c0219033d3846ba3ce5c38efd17",
        "d33dcb033f52664212c34c0219033d3846ba3ce5c38efd17",
    );
}

#[test]
fn adv115_phrase_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "phrase-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv115_phrase_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "phrase-api-token",
        "PHRASE=d33dcb033f52664212c34c02\u{200B}19033d3846ba3ce5c38efd17",
        "d33dcb033f52664212c34c0219033d3846ba3ce5c38efd17",
    );
}

#[test]
fn adv115_phrase_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "phrase-api-token",
        "PHRASE=d33dcb033f52664212c34c02\u{00AD}19033d3846ba3ce5c38efd17",
        "d33dcb033f52664212c34c0219033d3846ba3ce5c38efd17",
    );
}

#[test]
fn adv115_phrase_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "phrase-api-token",
        "PHRASE=d33dcb033f52664212c34c02\u{200C}19033d3846ba3ce5c38efd17",
        "d33dcb033f52664212c34c0219033d3846ba3ce5c38efd17",
    );
}

#[test]
fn adv115_phrase_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "phrase-api-token",
        "PHRASE=d33dcb033f52664212c34c02\u{200D}19033d3846ba3ce5c38efd17",
        "d33dcb033f52664212c34c0219033d3846ba3ce5c38efd17",
    );
}

#[test]
fn adv115_phrase_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "phrase-api-token",
        "PHRASE=d33dcb033f52664212c34c02\u{FEFF}19033d3846ba3ce5c38efd17",
        "d33dcb033f52664212c34c0219033d3846ba3ce5c38efd17",
    );
}

#[test]
fn adv115_phrase_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "phrase-api-token",
        "PHRASE=d33dcb033f52664212c34c02\u{2060}19033d3846ba3ce5c38efd17",
        "d33dcb033f52664212c34c0219033d3846ba3ce5c38efd17",
    );
}

#[test]
fn adv115_phrase_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "phrase-api-token",
        "PHRASE=d33dcb033f52664212c34c02\u{180E}19033d3846ba3ce5c38efd17",
        "d33dcb033f52664212c34c0219033d3846ba3ce5c38efd17",
    );
}

#[test]
fn adv115_phrase_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "phrase-api-token",
        "PHRASE=d33dcb033f52664212c34c02\u{202E}19033d3846ba3ce5c38efd17",
        "d33dcb033f52664212c34c0219033d3846ba3ce5c38efd17",
    );
}

#[test]
fn adv115_phrase_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "phrase-api-token",
        "PHRASE=d33dcb033f52664212c34c02\u{202C}19033d3846ba3ce5c38efd17",
        "d33dcb033f52664212c34c0219033d3846ba3ce5c38efd17",
    );
}

#[test]
fn adv115_phrase_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "phrase-api-token",
        "PHRASE=d33dcb033f52664212c34c02\u{200E}19033d3846ba3ce5c38efd17",
        "d33dcb033f52664212c34c0219033d3846ba3ce5c38efd17",
    );
}

// =========================================================================
// 8. PINECONE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv115_pinecone_api_key_normal_must_fire() {
    assert_detector_fires(
        "pinecone-api-key",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv115_pinecone_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pinecone-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv115_pinecone_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pinecone-api-key",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7R\u{200B}m2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv115_pinecone_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pinecone-api-key",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7R\u{00AD}m2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv115_pinecone_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "pinecone-api-key",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7R\u{200C}m2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv115_pinecone_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "pinecone-api-key",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7R\u{200D}m2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv115_pinecone_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "pinecone-api-key",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7R\u{FEFF}m2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv115_pinecone_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "pinecone-api-key",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7R\u{2060}m2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv115_pinecone_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "pinecone-api-key",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7R\u{180E}m2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv115_pinecone_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "pinecone-api-key",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7R\u{202E}m2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv115_pinecone_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "pinecone-api-key",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7R\u{202C}m2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv115_pinecone_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "pinecone-api-key",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7R\u{200E}m2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 9. PINGDOM API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv115_pingdom_api_key_normal_must_fire() {
    assert_detector_fires(
        "pingdom-api-key",
        "pingdom.api_key=Eqd6yBLcY71nZR9yY59FDFI5RQ8uvP3cB2wFLNdtabcd",
        "Eqd6yBLcY71nZR9yY59FDFI5RQ8uvP3cB2wFLNdtabcd",
    );
}

#[test]
fn adv115_pingdom_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pingdom-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv115_pingdom_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pingdom-api-key",
        "pingdom.api_key=Eqd6yBLcY71nZR9yY59FDF\u{200B}I5RQ8uvP3cB2wFLNdtabcd",
        "Eqd6yBLcY71nZR9yY59FDFI5RQ8uvP3cB2wFLNdtabcd",
    );
}

#[test]
fn adv115_pingdom_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pingdom-api-key",
        "pingdom.api_key=Eqd6yBLcY71nZR9yY59FDF\u{00AD}I5RQ8uvP3cB2wFLNdtabcd",
        "Eqd6yBLcY71nZR9yY59FDFI5RQ8uvP3cB2wFLNdtabcd",
    );
}

#[test]
fn adv115_pingdom_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "pingdom-api-key",
        "pingdom.api_key=Eqd6yBLcY71nZR9yY59FDF\u{200C}I5RQ8uvP3cB2wFLNdtabcd",
        "Eqd6yBLcY71nZR9yY59FDFI5RQ8uvP3cB2wFLNdtabcd",
    );
}

#[test]
fn adv115_pingdom_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "pingdom-api-key",
        "pingdom.api_key=Eqd6yBLcY71nZR9yY59FDF\u{200D}I5RQ8uvP3cB2wFLNdtabcd",
        "Eqd6yBLcY71nZR9yY59FDFI5RQ8uvP3cB2wFLNdtabcd",
    );
}

#[test]
fn adv115_pingdom_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "pingdom-api-key",
        "pingdom.api_key=Eqd6yBLcY71nZR9yY59FDF\u{FEFF}I5RQ8uvP3cB2wFLNdtabcd",
        "Eqd6yBLcY71nZR9yY59FDFI5RQ8uvP3cB2wFLNdtabcd",
    );
}

#[test]
fn adv115_pingdom_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "pingdom-api-key",
        "pingdom.api_key=Eqd6yBLcY71nZR9yY59FDF\u{2060}I5RQ8uvP3cB2wFLNdtabcd",
        "Eqd6yBLcY71nZR9yY59FDFI5RQ8uvP3cB2wFLNdtabcd",
    );
}

#[test]
fn adv115_pingdom_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "pingdom-api-key",
        "pingdom.api_key=Eqd6yBLcY71nZR9yY59FDF\u{180E}I5RQ8uvP3cB2wFLNdtabcd",
        "Eqd6yBLcY71nZR9yY59FDFI5RQ8uvP3cB2wFLNdtabcd",
    );
}

#[test]
fn adv115_pingdom_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "pingdom-api-key",
        "pingdom.api_key=Eqd6yBLcY71nZR9yY59FDF\u{202E}I5RQ8uvP3cB2wFLNdtabcd",
        "Eqd6yBLcY71nZR9yY59FDFI5RQ8uvP3cB2wFLNdtabcd",
    );
}

#[test]
fn adv115_pingdom_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "pingdom-api-key",
        "pingdom.api_key=Eqd6yBLcY71nZR9yY59FDF\u{202C}I5RQ8uvP3cB2wFLNdtabcd",
        "Eqd6yBLcY71nZR9yY59FDFI5RQ8uvP3cB2wFLNdtabcd",
    );
}

#[test]
fn adv115_pingdom_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "pingdom-api-key",
        "pingdom.api_key=Eqd6yBLcY71nZR9yY59FDF\u{200E}I5RQ8uvP3cB2wFLNdtabcd",
        "Eqd6yBLcY71nZR9yY59FDFI5RQ8uvP3cB2wFLNdtabcd",
    );
}

// =========================================================================
// 10. PINTEREST ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv115_pinterest_access_token_normal_must_fire() {
    assert_detector_fires(
        "pinterest-access-token",
        "PINTEREST=cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
        "cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
    );
}

#[test]
fn adv115_pinterest_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pinterest-access-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv115_pinterest_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pinterest-access-token",
        "PINTEREST=cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0\u{200B}nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
        "cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
    );
}

#[test]
fn adv115_pinterest_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pinterest-access-token",
        "PINTEREST=cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0\u{00AD}nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
        "cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
    );
}

#[test]
fn adv115_pinterest_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "pinterest-access-token",
        "PINTEREST=cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0\u{200C}nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
        "cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
    );
}

#[test]
fn adv115_pinterest_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "pinterest-access-token",
        "PINTEREST=cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0\u{200D}nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
        "cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
    );
}

#[test]
fn adv115_pinterest_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "pinterest-access-token",
        "PINTEREST=cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0\u{FEFF}nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
        "cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
    );
}

#[test]
fn adv115_pinterest_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "pinterest-access-token",
        "PINTEREST=cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0\u{2060}nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
        "cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
    );
}

#[test]
fn adv115_pinterest_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "pinterest-access-token",
        "PINTEREST=cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0\u{180E}nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
        "cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
    );
}

#[test]
fn adv115_pinterest_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "pinterest-access-token",
        "PINTEREST=cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0\u{202E}nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
        "cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
    );
}

#[test]
fn adv115_pinterest_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "pinterest-access-token",
        "PINTEREST=cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0\u{202C}nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
        "cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
    );
}

#[test]
fn adv115_pinterest_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "pinterest-access-token",
        "PINTEREST=cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0\u{200E}nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
        "cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
    );
}
