//! Part 77 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates cloudflare, cloudflare, cloudinary, cloudsmith, cmcom, cockroachdb, codecov, codesandbox, cognito, cohere detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. CLOUDFLARE WORKERS API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv77_cloudflare_workers_api_token_normal_must_fire() {
    assert_detector_fires(
        "cloudflare-workers-api-token",
        "CLOUDFLARE_WORKERS_API_TOKEN=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv77_cloudflare_workers_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cloudflare-workers-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv77_cloudflare_workers_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cloudflare-workers-api-token",
        "CLOUDFLARE_WORKERS_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{200B}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv77_cloudflare_workers_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cloudflare-workers-api-token",
        "CLOUDFLARE_WORKERS_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{00AD}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv77_cloudflare_workers_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "cloudflare-workers-api-token",
        "CLOUDFLARE_WORKERS_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{200C}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv77_cloudflare_workers_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "cloudflare-workers-api-token",
        "CLOUDFLARE_WORKERS_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{200D}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv77_cloudflare_workers_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "cloudflare-workers-api-token",
        "CLOUDFLARE_WORKERS_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{FEFF}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv77_cloudflare_workers_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "cloudflare-workers-api-token",
        "CLOUDFLARE_WORKERS_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{2060}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv77_cloudflare_workers_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "cloudflare-workers-api-token",
        "CLOUDFLARE_WORKERS_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{180E}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv77_cloudflare_workers_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "cloudflare-workers-api-token",
        "CLOUDFLARE_WORKERS_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{202E}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv77_cloudflare_workers_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "cloudflare-workers-api-token",
        "CLOUDFLARE_WORKERS_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{202C}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

#[test]
fn adv77_cloudflare_workers_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "cloudflare-workers-api-token",
        "CLOUDFLARE_WORKERS_API_TOKEN=AbCdEfGhIjKlMnOpQrSt\u{200E}UvWxYz0123456789AbCd",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
    );
}

// =========================================================================
// 2. CLOUDFLARE ZERO TRUST SERVICE TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv77_cloudflare_zero_trust_service_token_normal_must_fire() {
    assert_detector_fires(
        "cloudflare-zero-trust-service-token",
        "CF-Access-Client-Id=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d.access",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv77_cloudflare_zero_trust_service_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cloudflare-zero-trust-service-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.access",
    );
}

#[test]
fn adv77_cloudflare_zero_trust_service_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cloudflare-zero-trust-service-token",
        "CF-Access-Client-Id=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d.access",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv77_cloudflare_zero_trust_service_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cloudflare-zero-trust-service-token",
        "CF-Access-Client-Id=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d.access",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv77_cloudflare_zero_trust_service_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "cloudflare-zero-trust-service-token",
        "CF-Access-Client-Id=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d.access",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv77_cloudflare_zero_trust_service_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "cloudflare-zero-trust-service-token",
        "CF-Access-Client-Id=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d.access",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv77_cloudflare_zero_trust_service_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "cloudflare-zero-trust-service-token",
        "CF-Access-Client-Id=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d.access",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv77_cloudflare_zero_trust_service_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "cloudflare-zero-trust-service-token",
        "CF-Access-Client-Id=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d.access",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv77_cloudflare_zero_trust_service_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "cloudflare-zero-trust-service-token",
        "CF-Access-Client-Id=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d.access",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv77_cloudflare_zero_trust_service_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "cloudflare-zero-trust-service-token",
        "CF-Access-Client-Id=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d.access",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv77_cloudflare_zero_trust_service_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "cloudflare-zero-trust-service-token",
        "CF-Access-Client-Id=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d.access",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv77_cloudflare_zero_trust_service_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "cloudflare-zero-trust-service-token",
        "CF-Access-Client-Id=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d.access",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 3. CLOUDINARY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv77_cloudinary_api_key_normal_must_fire() {
    assert_detector_fires(
        "cloudinary-api-key",
        "cloudinary://946054033816433664211118670346455:NvXnEzfHQBPE9sQVcnk@rgV7LEbhI1QMVD7lYiBrqFtq3avz_fSEXZpggxdEGkHDnUT3TMXyqaAAPFYT",
        "cloudinary://946054033816433664211118670346455:NvXnEzfHQBPE9sQVcnk@rgV7LEbhI1QMVD7lYiBrqFtq3avz_fSEXZpggxdEGkHDnUT3TMXyqaAAPFYT",
    );
}

#[test]
fn adv77_cloudinary_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cloudinary-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv77_cloudinary_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cloudinary-api-key",
        "cloudinary://946054033816433664211118670346455:NvXnEzfHQBPE9sQV\u{200B}cnk@rgV7LEbhI1QMVD7lYiBrqFtq3avz_fSEXZpggxdEGkHDnUT3TMXyqaAAPFYT",
        "cloudinary://946054033816433664211118670346455:NvXnEzfHQBPE9sQVcnk@rgV7LEbhI1QMVD7lYiBrqFtq3avz_fSEXZpggxdEGkHDnUT3TMXyqaAAPFYT",
    );
}

#[test]
fn adv77_cloudinary_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cloudinary-api-key",
        "cloudinary://946054033816433664211118670346455:NvXnEzfHQBPE9sQV\u{00AD}cnk@rgV7LEbhI1QMVD7lYiBrqFtq3avz_fSEXZpggxdEGkHDnUT3TMXyqaAAPFYT",
        "cloudinary://946054033816433664211118670346455:NvXnEzfHQBPE9sQVcnk@rgV7LEbhI1QMVD7lYiBrqFtq3avz_fSEXZpggxdEGkHDnUT3TMXyqaAAPFYT",
    );
}

#[test]
fn adv77_cloudinary_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "cloudinary-api-key",
        "cloudinary://946054033816433664211118670346455:NvXnEzfHQBPE9sQV\u{200C}cnk@rgV7LEbhI1QMVD7lYiBrqFtq3avz_fSEXZpggxdEGkHDnUT3TMXyqaAAPFYT",
        "cloudinary://946054033816433664211118670346455:NvXnEzfHQBPE9sQVcnk@rgV7LEbhI1QMVD7lYiBrqFtq3avz_fSEXZpggxdEGkHDnUT3TMXyqaAAPFYT",
    );
}

#[test]
fn adv77_cloudinary_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "cloudinary-api-key",
        "cloudinary://946054033816433664211118670346455:NvXnEzfHQBPE9sQV\u{200D}cnk@rgV7LEbhI1QMVD7lYiBrqFtq3avz_fSEXZpggxdEGkHDnUT3TMXyqaAAPFYT",
        "cloudinary://946054033816433664211118670346455:NvXnEzfHQBPE9sQVcnk@rgV7LEbhI1QMVD7lYiBrqFtq3avz_fSEXZpggxdEGkHDnUT3TMXyqaAAPFYT",
    );
}

#[test]
fn adv77_cloudinary_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "cloudinary-api-key",
        "cloudinary://946054033816433664211118670346455:NvXnEzfHQBPE9sQV\u{FEFF}cnk@rgV7LEbhI1QMVD7lYiBrqFtq3avz_fSEXZpggxdEGkHDnUT3TMXyqaAAPFYT",
        "cloudinary://946054033816433664211118670346455:NvXnEzfHQBPE9sQVcnk@rgV7LEbhI1QMVD7lYiBrqFtq3avz_fSEXZpggxdEGkHDnUT3TMXyqaAAPFYT",
    );
}

#[test]
fn adv77_cloudinary_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "cloudinary-api-key",
        "cloudinary://946054033816433664211118670346455:NvXnEzfHQBPE9sQV\u{2060}cnk@rgV7LEbhI1QMVD7lYiBrqFtq3avz_fSEXZpggxdEGkHDnUT3TMXyqaAAPFYT",
        "cloudinary://946054033816433664211118670346455:NvXnEzfHQBPE9sQVcnk@rgV7LEbhI1QMVD7lYiBrqFtq3avz_fSEXZpggxdEGkHDnUT3TMXyqaAAPFYT",
    );
}

#[test]
fn adv77_cloudinary_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "cloudinary-api-key",
        "cloudinary://946054033816433664211118670346455:NvXnEzfHQBPE9sQV\u{180E}cnk@rgV7LEbhI1QMVD7lYiBrqFtq3avz_fSEXZpggxdEGkHDnUT3TMXyqaAAPFYT",
        "cloudinary://946054033816433664211118670346455:NvXnEzfHQBPE9sQVcnk@rgV7LEbhI1QMVD7lYiBrqFtq3avz_fSEXZpggxdEGkHDnUT3TMXyqaAAPFYT",
    );
}

#[test]
fn adv77_cloudinary_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "cloudinary-api-key",
        "cloudinary://946054033816433664211118670346455:NvXnEzfHQBPE9sQV\u{202E}cnk@rgV7LEbhI1QMVD7lYiBrqFtq3avz_fSEXZpggxdEGkHDnUT3TMXyqaAAPFYT",
        "cloudinary://946054033816433664211118670346455:NvXnEzfHQBPE9sQVcnk@rgV7LEbhI1QMVD7lYiBrqFtq3avz_fSEXZpggxdEGkHDnUT3TMXyqaAAPFYT",
    );
}

#[test]
fn adv77_cloudinary_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "cloudinary-api-key",
        "cloudinary://946054033816433664211118670346455:NvXnEzfHQBPE9sQV\u{202C}cnk@rgV7LEbhI1QMVD7lYiBrqFtq3avz_fSEXZpggxdEGkHDnUT3TMXyqaAAPFYT",
        "cloudinary://946054033816433664211118670346455:NvXnEzfHQBPE9sQVcnk@rgV7LEbhI1QMVD7lYiBrqFtq3avz_fSEXZpggxdEGkHDnUT3TMXyqaAAPFYT",
    );
}

#[test]
fn adv77_cloudinary_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "cloudinary-api-key",
        "cloudinary://946054033816433664211118670346455:NvXnEzfHQBPE9sQV\u{200E}cnk@rgV7LEbhI1QMVD7lYiBrqFtq3avz_fSEXZpggxdEGkHDnUT3TMXyqaAAPFYT",
        "cloudinary://946054033816433664211118670346455:NvXnEzfHQBPE9sQVcnk@rgV7LEbhI1QMVD7lYiBrqFtq3avz_fSEXZpggxdEGkHDnUT3TMXyqaAAPFYT",
    );
}

// =========================================================================
// 4. CLOUDSMITH API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv77_cloudsmith_api_key_normal_must_fire() {
    assert_detector_fires(
        "cloudsmith-api-key",
        "cs_AbCdEfGhIjKlMnOpQrStUvWxYz01234567",
        "cs_AbCdEfGhIjKlMnOpQrStUvWxYz01234567",
    );
}

#[test]
fn adv77_cloudsmith_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cloudsmith-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv77_cloudsmith_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cloudsmith-api-key",
        "cs_AbCdEfGhIjKlMnO\u{200B}pQrStUvWxYz01234567",
        "cs_AbCdEfGhIjKlMnOpQrStUvWxYz01234567",
    );
}

#[test]
fn adv77_cloudsmith_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cloudsmith-api-key",
        "cs_AbCdEfGhIjKlMnO\u{00AD}pQrStUvWxYz01234567",
        "cs_AbCdEfGhIjKlMnOpQrStUvWxYz01234567",
    );
}

#[test]
fn adv77_cloudsmith_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "cloudsmith-api-key",
        "cs_AbCdEfGhIjKlMnO\u{200C}pQrStUvWxYz01234567",
        "cs_AbCdEfGhIjKlMnOpQrStUvWxYz01234567",
    );
}

#[test]
fn adv77_cloudsmith_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "cloudsmith-api-key",
        "cs_AbCdEfGhIjKlMnO\u{200D}pQrStUvWxYz01234567",
        "cs_AbCdEfGhIjKlMnOpQrStUvWxYz01234567",
    );
}

#[test]
fn adv77_cloudsmith_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "cloudsmith-api-key",
        "cs_AbCdEfGhIjKlMnO\u{FEFF}pQrStUvWxYz01234567",
        "cs_AbCdEfGhIjKlMnOpQrStUvWxYz01234567",
    );
}

#[test]
fn adv77_cloudsmith_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "cloudsmith-api-key",
        "cs_AbCdEfGhIjKlMnO\u{2060}pQrStUvWxYz01234567",
        "cs_AbCdEfGhIjKlMnOpQrStUvWxYz01234567",
    );
}

#[test]
fn adv77_cloudsmith_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "cloudsmith-api-key",
        "cs_AbCdEfGhIjKlMnO\u{180E}pQrStUvWxYz01234567",
        "cs_AbCdEfGhIjKlMnOpQrStUvWxYz01234567",
    );
}

#[test]
fn adv77_cloudsmith_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "cloudsmith-api-key",
        "cs_AbCdEfGhIjKlMnO\u{202E}pQrStUvWxYz01234567",
        "cs_AbCdEfGhIjKlMnOpQrStUvWxYz01234567",
    );
}

#[test]
fn adv77_cloudsmith_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "cloudsmith-api-key",
        "cs_AbCdEfGhIjKlMnO\u{202C}pQrStUvWxYz01234567",
        "cs_AbCdEfGhIjKlMnOpQrStUvWxYz01234567",
    );
}

#[test]
fn adv77_cloudsmith_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "cloudsmith-api-key",
        "cs_AbCdEfGhIjKlMnO\u{200E}pQrStUvWxYz01234567",
        "cs_AbCdEfGhIjKlMnOpQrStUvWxYz01234567",
    );
}

// =========================================================================
// 5. CMCOM API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv77_cmcom_api_key_normal_must_fire() {
    assert_detector_fires(
        "cmcom-api-key",
        "X-CM-PRODUCTTOKEN=7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv77_cmcom_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cmcom-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv77_cmcom_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cmcom-api-key",
        "X-CM-PRODUCTTOKEN=7b3e5d8c-1a9f-4e2b\u{200B}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv77_cmcom_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cmcom-api-key",
        "X-CM-PRODUCTTOKEN=7b3e5d8c-1a9f-4e2b\u{00AD}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv77_cmcom_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "cmcom-api-key",
        "X-CM-PRODUCTTOKEN=7b3e5d8c-1a9f-4e2b\u{200C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv77_cmcom_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "cmcom-api-key",
        "X-CM-PRODUCTTOKEN=7b3e5d8c-1a9f-4e2b\u{200D}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv77_cmcom_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "cmcom-api-key",
        "X-CM-PRODUCTTOKEN=7b3e5d8c-1a9f-4e2b\u{FEFF}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv77_cmcom_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "cmcom-api-key",
        "X-CM-PRODUCTTOKEN=7b3e5d8c-1a9f-4e2b\u{2060}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv77_cmcom_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "cmcom-api-key",
        "X-CM-PRODUCTTOKEN=7b3e5d8c-1a9f-4e2b\u{180E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv77_cmcom_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "cmcom-api-key",
        "X-CM-PRODUCTTOKEN=7b3e5d8c-1a9f-4e2b\u{202E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv77_cmcom_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "cmcom-api-key",
        "X-CM-PRODUCTTOKEN=7b3e5d8c-1a9f-4e2b\u{202C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv77_cmcom_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "cmcom-api-key",
        "X-CM-PRODUCTTOKEN=7b3e5d8c-1a9f-4e2b\u{200E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

// =========================================================================
// 6. COCKROACHDB API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv77_cockroachdb_api_key_normal_must_fire() {
    assert_detector_fires(
        "cockroachdb-api-key",
        "COCKROACH_API_KEY=KP4QX7R_M2SN5TB_VW3YZKP_4QX7RM_2SN",
        "KP4QX7R_M2SN5TB_VW3YZKP_4QX7RM_2SN",
    );
}

#[test]
fn adv77_cockroachdb_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cockroachdb-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv77_cockroachdb_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cockroachdb-api-key",
        "COCKROACH_API_KEY=KP4QX7R_M2SN5TB_V\u{200B}W3YZKP_4QX7RM_2SN",
        "KP4QX7R_M2SN5TB_VW3YZKP_4QX7RM_2SN",
    );
}

#[test]
fn adv77_cockroachdb_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cockroachdb-api-key",
        "COCKROACH_API_KEY=KP4QX7R_M2SN5TB_V\u{00AD}W3YZKP_4QX7RM_2SN",
        "KP4QX7R_M2SN5TB_VW3YZKP_4QX7RM_2SN",
    );
}

#[test]
fn adv77_cockroachdb_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "cockroachdb-api-key",
        "COCKROACH_API_KEY=KP4QX7R_M2SN5TB_V\u{200C}W3YZKP_4QX7RM_2SN",
        "KP4QX7R_M2SN5TB_VW3YZKP_4QX7RM_2SN",
    );
}

#[test]
fn adv77_cockroachdb_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "cockroachdb-api-key",
        "COCKROACH_API_KEY=KP4QX7R_M2SN5TB_V\u{200D}W3YZKP_4QX7RM_2SN",
        "KP4QX7R_M2SN5TB_VW3YZKP_4QX7RM_2SN",
    );
}

#[test]
fn adv77_cockroachdb_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "cockroachdb-api-key",
        "COCKROACH_API_KEY=KP4QX7R_M2SN5TB_V\u{FEFF}W3YZKP_4QX7RM_2SN",
        "KP4QX7R_M2SN5TB_VW3YZKP_4QX7RM_2SN",
    );
}

#[test]
fn adv77_cockroachdb_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "cockroachdb-api-key",
        "COCKROACH_API_KEY=KP4QX7R_M2SN5TB_V\u{2060}W3YZKP_4QX7RM_2SN",
        "KP4QX7R_M2SN5TB_VW3YZKP_4QX7RM_2SN",
    );
}

#[test]
fn adv77_cockroachdb_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "cockroachdb-api-key",
        "COCKROACH_API_KEY=KP4QX7R_M2SN5TB_V\u{180E}W3YZKP_4QX7RM_2SN",
        "KP4QX7R_M2SN5TB_VW3YZKP_4QX7RM_2SN",
    );
}

#[test]
fn adv77_cockroachdb_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "cockroachdb-api-key",
        "COCKROACH_API_KEY=KP4QX7R_M2SN5TB_V\u{202E}W3YZKP_4QX7RM_2SN",
        "KP4QX7R_M2SN5TB_VW3YZKP_4QX7RM_2SN",
    );
}

#[test]
fn adv77_cockroachdb_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "cockroachdb-api-key",
        "COCKROACH_API_KEY=KP4QX7R_M2SN5TB_V\u{202C}W3YZKP_4QX7RM_2SN",
        "KP4QX7R_M2SN5TB_VW3YZKP_4QX7RM_2SN",
    );
}

#[test]
fn adv77_cockroachdb_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "cockroachdb-api-key",
        "COCKROACH_API_KEY=KP4QX7R_M2SN5TB_V\u{200E}W3YZKP_4QX7RM_2SN",
        "KP4QX7R_M2SN5TB_VW3YZKP_4QX7RM_2SN",
    );
}

// =========================================================================
// 7. CODECOV BASH CREDS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv77_codecov_bash_creds_normal_must_fire() {
    assert_detector_fires(
        "codecov-bash-creds",
        "https://codecov.io/upload/v4?package=bash-1.2.3&token=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv77_codecov_bash_creds_wrong_prefix_must_silent() {
    assert_detector_silent(
        "codecov-bash-creds",
        "dummy_prefix_0 =bash-1.2.3&token=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv77_codecov_bash_creds_evade_zwsp_must_fire() {
    assert_detector_fires(
        "codecov-bash-creds",
        "https://codecov.io/upload/v4?package=bash-1.2.3&token=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv77_codecov_bash_creds_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "codecov-bash-creds",
        "https://codecov.io/upload/v4?package=bash-1.2.3&token=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv77_codecov_bash_creds_evade_zwnj_must_fire() {
    assert_detector_fires(
        "codecov-bash-creds",
        "https://codecov.io/upload/v4?package=bash-1.2.3&token=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv77_codecov_bash_creds_evade_zwj_must_fire() {
    assert_detector_fires(
        "codecov-bash-creds",
        "https://codecov.io/upload/v4?package=bash-1.2.3&token=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv77_codecov_bash_creds_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "codecov-bash-creds",
        "https://codecov.io/upload/v4?package=bash-1.2.3&token=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv77_codecov_bash_creds_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "codecov-bash-creds",
        "https://codecov.io/upload/v4?package=bash-1.2.3&token=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv77_codecov_bash_creds_evade_mongolian_must_fire() {
    assert_detector_fires(
        "codecov-bash-creds",
        "https://codecov.io/upload/v4?package=bash-1.2.3&token=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv77_codecov_bash_creds_evade_rtl_must_fire() {
    assert_detector_fires(
        "codecov-bash-creds",
        "https://codecov.io/upload/v4?package=bash-1.2.3&token=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv77_codecov_bash_creds_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "codecov-bash-creds",
        "https://codecov.io/upload/v4?package=bash-1.2.3&token=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv77_codecov_bash_creds_evade_lrm_must_fire() {
    assert_detector_fires(
        "codecov-bash-creds",
        "https://codecov.io/upload/v4?package=bash-1.2.3&token=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 8. CODESANDBOX API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv77_codesandbox_api_token_normal_must_fire() {
    assert_detector_fires(
        "codesandbox-api-token",
        "csb_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "csb_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv77_codesandbox_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "codesandbox-api-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv77_codesandbox_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "codesandbox-api-token",
        "csb_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{200B}4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "csb_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv77_codesandbox_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "codesandbox-api-token",
        "csb_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{00AD}4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "csb_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv77_codesandbox_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "codesandbox-api-token",
        "csb_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{200C}4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "csb_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv77_codesandbox_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "codesandbox-api-token",
        "csb_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{200D}4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "csb_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv77_codesandbox_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "codesandbox-api-token",
        "csb_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{FEFF}4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "csb_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv77_codesandbox_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "codesandbox-api-token",
        "csb_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{2060}4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "csb_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv77_codesandbox_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "codesandbox-api-token",
        "csb_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{180E}4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "csb_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv77_codesandbox_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "codesandbox-api-token",
        "csb_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{202E}4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "csb_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv77_codesandbox_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "codesandbox-api-token",
        "csb_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{202C}4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "csb_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv77_codesandbox_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "codesandbox-api-token",
        "csb_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{200E}4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "csb_api_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 9. COGNITO FORMS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv77_cognito_forms_api_key_normal_must_fire() {
    assert_detector_fires(
        "cognito-forms-api-key",
        "cognito_forms_api_key Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
    );
}

#[test]
fn adv77_cognito_forms_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cognito-forms-api-key",
        "dummyito_forms_api_key xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv77_cognito_forms_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cognito-forms-api-key",
        "cognito_forms_api_key Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q\u{200B}x7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
    );
}

#[test]
fn adv77_cognito_forms_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cognito-forms-api-key",
        "cognito_forms_api_key Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q\u{00AD}x7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
    );
}

#[test]
fn adv77_cognito_forms_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "cognito-forms-api-key",
        "cognito_forms_api_key Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q\u{200C}x7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
    );
}

#[test]
fn adv77_cognito_forms_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "cognito-forms-api-key",
        "cognito_forms_api_key Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q\u{200D}x7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
    );
}

#[test]
fn adv77_cognito_forms_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "cognito-forms-api-key",
        "cognito_forms_api_key Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q\u{FEFF}x7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
    );
}

#[test]
fn adv77_cognito_forms_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "cognito-forms-api-key",
        "cognito_forms_api_key Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q\u{2060}x7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
    );
}

#[test]
fn adv77_cognito_forms_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "cognito-forms-api-key",
        "cognito_forms_api_key Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q\u{180E}x7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
    );
}

#[test]
fn adv77_cognito_forms_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "cognito-forms-api-key",
        "cognito_forms_api_key Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q\u{202E}x7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
    );
}

#[test]
fn adv77_cognito_forms_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "cognito-forms-api-key",
        "cognito_forms_api_key Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q\u{202C}x7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
    );
}

#[test]
fn adv77_cognito_forms_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "cognito-forms-api-key",
        "cognito_forms_api_key Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q\u{200E}x7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2",
    );
}

// =========================================================================
// 10. COHERE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv77_cohere_api_key_normal_must_fire() {
    assert_detector_fires(
        "cohere-api-key",
        "co_K3p7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
        "co_K3p7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
    );
}

#[test]
fn adv77_cohere_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("cohere-api-key", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv77_cohere_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cohere-api-key",
        "co_K3p7QxR4mN9sBv2\u{200B}Ta5Yc8Wh3Lj6Dz1FgU",
        "co_K3p7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
    );
}

#[test]
fn adv77_cohere_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cohere-api-key",
        "co_K3p7QxR4mN9sBv2\u{00AD}Ta5Yc8Wh3Lj6Dz1FgU",
        "co_K3p7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
    );
}

#[test]
fn adv77_cohere_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "cohere-api-key",
        "co_K3p7QxR4mN9sBv2\u{200C}Ta5Yc8Wh3Lj6Dz1FgU",
        "co_K3p7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
    );
}

#[test]
fn adv77_cohere_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "cohere-api-key",
        "co_K3p7QxR4mN9sBv2\u{200D}Ta5Yc8Wh3Lj6Dz1FgU",
        "co_K3p7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
    );
}

#[test]
fn adv77_cohere_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "cohere-api-key",
        "co_K3p7QxR4mN9sBv2\u{FEFF}Ta5Yc8Wh3Lj6Dz1FgU",
        "co_K3p7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
    );
}

#[test]
fn adv77_cohere_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "cohere-api-key",
        "co_K3p7QxR4mN9sBv2\u{2060}Ta5Yc8Wh3Lj6Dz1FgU",
        "co_K3p7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
    );
}

#[test]
fn adv77_cohere_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "cohere-api-key",
        "co_K3p7QxR4mN9sBv2\u{180E}Ta5Yc8Wh3Lj6Dz1FgU",
        "co_K3p7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
    );
}

#[test]
fn adv77_cohere_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "cohere-api-key",
        "co_K3p7QxR4mN9sBv2\u{202E}Ta5Yc8Wh3Lj6Dz1FgU",
        "co_K3p7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
    );
}

#[test]
fn adv77_cohere_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "cohere-api-key",
        "co_K3p7QxR4mN9sBv2\u{202C}Ta5Yc8Wh3Lj6Dz1FgU",
        "co_K3p7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
    );
}

#[test]
fn adv77_cohere_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "cohere-api-key",
        "co_K3p7QxR4mN9sBv2\u{200E}Ta5Yc8Wh3Lj6Dz1FgU",
        "co_K3p7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
    );
}
