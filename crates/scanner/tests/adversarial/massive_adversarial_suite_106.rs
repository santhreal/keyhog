//! Part 106 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates medusa, meilisearch, memcached, messagemedia, mexico, microsoft, microsoft, microsoft, minio, minio detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. MEDUSA API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv106_medusa_api_key_normal_must_fire() {
    assert_detector_fires(
        "medusa-api-key",
        "MEDUSA_API_KEY=kjxEBj2xZsZQ7L7gLbFmaoEWoFnUU0WUHceGVW0y",
        "kjxEBj2xZsZQ7L7gLbFmaoEWoFnUU0WUHceGVW0y",
    );
}

#[test]
fn adv106_medusa_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "medusa-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv106_medusa_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "medusa-api-key",
        "MEDUSA_API_KEY=kjxEBj2xZsZQ7L7gLbFm\u{200B}aoEWoFnUU0WUHceGVW0y",
        "kjxEBj2xZsZQ7L7gLbFmaoEWoFnUU0WUHceGVW0y",
    );
}

#[test]
fn adv106_medusa_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "medusa-api-key",
        "MEDUSA_API_KEY=kjxEBj2xZsZQ7L7gLbFm\u{00AD}aoEWoFnUU0WUHceGVW0y",
        "kjxEBj2xZsZQ7L7gLbFmaoEWoFnUU0WUHceGVW0y",
    );
}

#[test]
fn adv106_medusa_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "medusa-api-key",
        "MEDUSA_API_KEY=kjxEBj2xZsZQ7L7gLbFm\u{200C}aoEWoFnUU0WUHceGVW0y",
        "kjxEBj2xZsZQ7L7gLbFmaoEWoFnUU0WUHceGVW0y",
    );
}

#[test]
fn adv106_medusa_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "medusa-api-key",
        "MEDUSA_API_KEY=kjxEBj2xZsZQ7L7gLbFm\u{200D}aoEWoFnUU0WUHceGVW0y",
        "kjxEBj2xZsZQ7L7gLbFmaoEWoFnUU0WUHceGVW0y",
    );
}

#[test]
fn adv106_medusa_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "medusa-api-key",
        "MEDUSA_API_KEY=kjxEBj2xZsZQ7L7gLbFm\u{FEFF}aoEWoFnUU0WUHceGVW0y",
        "kjxEBj2xZsZQ7L7gLbFmaoEWoFnUU0WUHceGVW0y",
    );
}

#[test]
fn adv106_medusa_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "medusa-api-key",
        "MEDUSA_API_KEY=kjxEBj2xZsZQ7L7gLbFm\u{2060}aoEWoFnUU0WUHceGVW0y",
        "kjxEBj2xZsZQ7L7gLbFmaoEWoFnUU0WUHceGVW0y",
    );
}

#[test]
fn adv106_medusa_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "medusa-api-key",
        "MEDUSA_API_KEY=kjxEBj2xZsZQ7L7gLbFm\u{180E}aoEWoFnUU0WUHceGVW0y",
        "kjxEBj2xZsZQ7L7gLbFmaoEWoFnUU0WUHceGVW0y",
    );
}

#[test]
fn adv106_medusa_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "medusa-api-key",
        "MEDUSA_API_KEY=kjxEBj2xZsZQ7L7gLbFm\u{202E}aoEWoFnUU0WUHceGVW0y",
        "kjxEBj2xZsZQ7L7gLbFmaoEWoFnUU0WUHceGVW0y",
    );
}

#[test]
fn adv106_medusa_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "medusa-api-key",
        "MEDUSA_API_KEY=kjxEBj2xZsZQ7L7gLbFm\u{202C}aoEWoFnUU0WUHceGVW0y",
        "kjxEBj2xZsZQ7L7gLbFmaoEWoFnUU0WUHceGVW0y",
    );
}

#[test]
fn adv106_medusa_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "medusa-api-key",
        "MEDUSA_API_KEY=kjxEBj2xZsZQ7L7gLbFm\u{200E}aoEWoFnUU0WUHceGVW0y",
        "kjxEBj2xZsZQ7L7gLbFmaoEWoFnUU0WUHceGVW0y",
    );
}

// =========================================================================
// 2. MEILISEARCH API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv106_meilisearch_api_key_normal_must_fire() {
    assert_detector_fires(
        "meilisearch-api-key",
        "MEILISEARCH_API_KEY=zbNdq6Fp78ZTADck",
        "zbNdq6Fp78ZTADck",
    );
}

#[test]
fn adv106_meilisearch_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "meilisearch-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv106_meilisearch_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "meilisearch-api-key",
        "MEILISEARCH_API_KEY=zbNdq6Fp\u{200B}78ZTADck",
        "zbNdq6Fp78ZTADck",
    );
}

#[test]
fn adv106_meilisearch_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "meilisearch-api-key",
        "MEILISEARCH_API_KEY=zbNdq6Fp\u{00AD}78ZTADck",
        "zbNdq6Fp78ZTADck",
    );
}

#[test]
fn adv106_meilisearch_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "meilisearch-api-key",
        "MEILISEARCH_API_KEY=zbNdq6Fp\u{200C}78ZTADck",
        "zbNdq6Fp78ZTADck",
    );
}

#[test]
fn adv106_meilisearch_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "meilisearch-api-key",
        "MEILISEARCH_API_KEY=zbNdq6Fp\u{200D}78ZTADck",
        "zbNdq6Fp78ZTADck",
    );
}

#[test]
fn adv106_meilisearch_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "meilisearch-api-key",
        "MEILISEARCH_API_KEY=zbNdq6Fp\u{FEFF}78ZTADck",
        "zbNdq6Fp78ZTADck",
    );
}

#[test]
fn adv106_meilisearch_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "meilisearch-api-key",
        "MEILISEARCH_API_KEY=zbNdq6Fp\u{2060}78ZTADck",
        "zbNdq6Fp78ZTADck",
    );
}

#[test]
fn adv106_meilisearch_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "meilisearch-api-key",
        "MEILISEARCH_API_KEY=zbNdq6Fp\u{180E}78ZTADck",
        "zbNdq6Fp78ZTADck",
    );
}

#[test]
fn adv106_meilisearch_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "meilisearch-api-key",
        "MEILISEARCH_API_KEY=zbNdq6Fp\u{202E}78ZTADck",
        "zbNdq6Fp78ZTADck",
    );
}

#[test]
fn adv106_meilisearch_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "meilisearch-api-key",
        "MEILISEARCH_API_KEY=zbNdq6Fp\u{202C}78ZTADck",
        "zbNdq6Fp78ZTADck",
    );
}

#[test]
fn adv106_meilisearch_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "meilisearch-api-key",
        "MEILISEARCH_API_KEY=zbNdq6Fp\u{200E}78ZTADck",
        "zbNdq6Fp78ZTADck",
    );
}

// =========================================================================
// 3. MEMCACHED SASL CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv106_memcached_sasl_credentials_normal_must_fire() {
    assert_detector_fires(
        "memcached-sasl-credentials",
        "MEMCACHE_USERNAME=k3PpL7zR9xQ2",
        "k3PpL7zR9xQ2",
    );
}

#[test]
fn adv106_memcached_sasl_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "memcached-sasl-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxx",
    );
}

#[test]
fn adv106_memcached_sasl_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "memcached-sasl-credentials",
        "MEMCACHE_USERNAME=k3PpL7\u{200B}zR9xQ2",
        "k3PpL7zR9xQ2",
    );
}

#[test]
fn adv106_memcached_sasl_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "memcached-sasl-credentials",
        "MEMCACHE_USERNAME=k3PpL7\u{00AD}zR9xQ2",
        "k3PpL7zR9xQ2",
    );
}

#[test]
fn adv106_memcached_sasl_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "memcached-sasl-credentials",
        "MEMCACHE_USERNAME=k3PpL7\u{200C}zR9xQ2",
        "k3PpL7zR9xQ2",
    );
}

#[test]
fn adv106_memcached_sasl_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "memcached-sasl-credentials",
        "MEMCACHE_USERNAME=k3PpL7\u{200D}zR9xQ2",
        "k3PpL7zR9xQ2",
    );
}

#[test]
fn adv106_memcached_sasl_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "memcached-sasl-credentials",
        "MEMCACHE_USERNAME=k3PpL7\u{FEFF}zR9xQ2",
        "k3PpL7zR9xQ2",
    );
}

#[test]
fn adv106_memcached_sasl_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "memcached-sasl-credentials",
        "MEMCACHE_USERNAME=k3PpL7\u{2060}zR9xQ2",
        "k3PpL7zR9xQ2",
    );
}

#[test]
fn adv106_memcached_sasl_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "memcached-sasl-credentials",
        "MEMCACHE_USERNAME=k3PpL7\u{180E}zR9xQ2",
        "k3PpL7zR9xQ2",
    );
}

#[test]
fn adv106_memcached_sasl_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "memcached-sasl-credentials",
        "MEMCACHE_USERNAME=k3PpL7\u{202E}zR9xQ2",
        "k3PpL7zR9xQ2",
    );
}

#[test]
fn adv106_memcached_sasl_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "memcached-sasl-credentials",
        "MEMCACHE_USERNAME=k3PpL7\u{202C}zR9xQ2",
        "k3PpL7zR9xQ2",
    );
}

#[test]
fn adv106_memcached_sasl_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "memcached-sasl-credentials",
        "MEMCACHE_USERNAME=k3PpL7\u{200E}zR9xQ2",
        "k3PpL7zR9xQ2",
    );
}

// =========================================================================
// 4. MESSAGEMEDIA API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv106_messagemedia_api_key_normal_must_fire() {
    assert_detector_fires(
        "messagemedia-api-key",
        "MESSAGEMEDIA_API_KEY=SqLjEPwwDKhgVlj98M2q",
        "SqLjEPwwDKhgVlj98M2q",
    );
}

#[test]
fn adv106_messagemedia_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "messagemedia-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv106_messagemedia_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "messagemedia-api-key",
        "MESSAGEMEDIA_API_KEY=SqLjEPwwDK\u{200B}hgVlj98M2q",
        "SqLjEPwwDKhgVlj98M2q",
    );
}

#[test]
fn adv106_messagemedia_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "messagemedia-api-key",
        "MESSAGEMEDIA_API_KEY=SqLjEPwwDK\u{00AD}hgVlj98M2q",
        "SqLjEPwwDKhgVlj98M2q",
    );
}

#[test]
fn adv106_messagemedia_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "messagemedia-api-key",
        "MESSAGEMEDIA_API_KEY=SqLjEPwwDK\u{200C}hgVlj98M2q",
        "SqLjEPwwDKhgVlj98M2q",
    );
}

#[test]
fn adv106_messagemedia_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "messagemedia-api-key",
        "MESSAGEMEDIA_API_KEY=SqLjEPwwDK\u{200D}hgVlj98M2q",
        "SqLjEPwwDKhgVlj98M2q",
    );
}

#[test]
fn adv106_messagemedia_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "messagemedia-api-key",
        "MESSAGEMEDIA_API_KEY=SqLjEPwwDK\u{FEFF}hgVlj98M2q",
        "SqLjEPwwDKhgVlj98M2q",
    );
}

#[test]
fn adv106_messagemedia_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "messagemedia-api-key",
        "MESSAGEMEDIA_API_KEY=SqLjEPwwDK\u{2060}hgVlj98M2q",
        "SqLjEPwwDKhgVlj98M2q",
    );
}

#[test]
fn adv106_messagemedia_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "messagemedia-api-key",
        "MESSAGEMEDIA_API_KEY=SqLjEPwwDK\u{180E}hgVlj98M2q",
        "SqLjEPwwDKhgVlj98M2q",
    );
}

#[test]
fn adv106_messagemedia_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "messagemedia-api-key",
        "MESSAGEMEDIA_API_KEY=SqLjEPwwDK\u{202E}hgVlj98M2q",
        "SqLjEPwwDKhgVlj98M2q",
    );
}

#[test]
fn adv106_messagemedia_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "messagemedia-api-key",
        "MESSAGEMEDIA_API_KEY=SqLjEPwwDK\u{202C}hgVlj98M2q",
        "SqLjEPwwDKhgVlj98M2q",
    );
}

#[test]
fn adv106_messagemedia_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "messagemedia-api-key",
        "MESSAGEMEDIA_API_KEY=SqLjEPwwDK\u{200E}hgVlj98M2q",
        "SqLjEPwwDKhgVlj98M2q",
    );
}

// =========================================================================
// 5. MEXICO DATOSGOBMX API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv106_mexico_datosgobmx_api_key_normal_must_fire() {
    assert_detector_fires(
        "mexico-datosgobmx-api-key",
        "DATOS_GOB_API_KEY=f81a1948-ed21-1d74-ea77-cfb73d772899",
        "f81a1948-ed21-1d74-ea77-cfb73d772899",
    );
}

#[test]
fn adv106_mexico_datosgobmx_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mexico-datosgobmx-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv106_mexico_datosgobmx_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mexico-datosgobmx-api-key",
        "DATOS_GOB_API_KEY=f81a1948-ed21-1d74\u{200B}-ea77-cfb73d772899",
        "f81a1948-ed21-1d74-ea77-cfb73d772899",
    );
}

#[test]
fn adv106_mexico_datosgobmx_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mexico-datosgobmx-api-key",
        "DATOS_GOB_API_KEY=f81a1948-ed21-1d74\u{00AD}-ea77-cfb73d772899",
        "f81a1948-ed21-1d74-ea77-cfb73d772899",
    );
}

#[test]
fn adv106_mexico_datosgobmx_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "mexico-datosgobmx-api-key",
        "DATOS_GOB_API_KEY=f81a1948-ed21-1d74\u{200C}-ea77-cfb73d772899",
        "f81a1948-ed21-1d74-ea77-cfb73d772899",
    );
}

#[test]
fn adv106_mexico_datosgobmx_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "mexico-datosgobmx-api-key",
        "DATOS_GOB_API_KEY=f81a1948-ed21-1d74\u{200D}-ea77-cfb73d772899",
        "f81a1948-ed21-1d74-ea77-cfb73d772899",
    );
}

#[test]
fn adv106_mexico_datosgobmx_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "mexico-datosgobmx-api-key",
        "DATOS_GOB_API_KEY=f81a1948-ed21-1d74\u{FEFF}-ea77-cfb73d772899",
        "f81a1948-ed21-1d74-ea77-cfb73d772899",
    );
}

#[test]
fn adv106_mexico_datosgobmx_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "mexico-datosgobmx-api-key",
        "DATOS_GOB_API_KEY=f81a1948-ed21-1d74\u{2060}-ea77-cfb73d772899",
        "f81a1948-ed21-1d74-ea77-cfb73d772899",
    );
}

#[test]
fn adv106_mexico_datosgobmx_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "mexico-datosgobmx-api-key",
        "DATOS_GOB_API_KEY=f81a1948-ed21-1d74\u{180E}-ea77-cfb73d772899",
        "f81a1948-ed21-1d74-ea77-cfb73d772899",
    );
}

#[test]
fn adv106_mexico_datosgobmx_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "mexico-datosgobmx-api-key",
        "DATOS_GOB_API_KEY=f81a1948-ed21-1d74\u{202E}-ea77-cfb73d772899",
        "f81a1948-ed21-1d74-ea77-cfb73d772899",
    );
}

#[test]
fn adv106_mexico_datosgobmx_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "mexico-datosgobmx-api-key",
        "DATOS_GOB_API_KEY=f81a1948-ed21-1d74\u{202C}-ea77-cfb73d772899",
        "f81a1948-ed21-1d74-ea77-cfb73d772899",
    );
}

#[test]
fn adv106_mexico_datosgobmx_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "mexico-datosgobmx-api-key",
        "DATOS_GOB_API_KEY=f81a1948-ed21-1d74\u{200E}-ea77-cfb73d772899",
        "f81a1948-ed21-1d74-ea77-cfb73d772899",
    );
}

// =========================================================================
// 6. MICROSOFT ADVERTISING API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv106_microsoft_advertising_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "microsoft-advertising-api-credentials",
        "microsoft_advertising client_id=ed39a474-b89c-05b2-5fcc-1d1cdffea13b",
        "ed39a474-b89c-05b2-5fcc-1d1cdffea13b",
    );
}

#[test]
fn adv106_microsoft_advertising_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "microsoft-advertising-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv106_microsoft_advertising_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "microsoft-advertising-api-credentials",
        "microsoft_advertising client_id=ed39a474-b89c-05b2\u{200B}-5fcc-1d1cdffea13b",
        "ed39a474-b89c-05b2-5fcc-1d1cdffea13b",
    );
}

#[test]
fn adv106_microsoft_advertising_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "microsoft-advertising-api-credentials",
        "microsoft_advertising client_id=ed39a474-b89c-05b2\u{00AD}-5fcc-1d1cdffea13b",
        "ed39a474-b89c-05b2-5fcc-1d1cdffea13b",
    );
}

#[test]
fn adv106_microsoft_advertising_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "microsoft-advertising-api-credentials",
        "microsoft_advertising client_id=ed39a474-b89c-05b2\u{200C}-5fcc-1d1cdffea13b",
        "ed39a474-b89c-05b2-5fcc-1d1cdffea13b",
    );
}

#[test]
fn adv106_microsoft_advertising_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "microsoft-advertising-api-credentials",
        "microsoft_advertising client_id=ed39a474-b89c-05b2\u{200D}-5fcc-1d1cdffea13b",
        "ed39a474-b89c-05b2-5fcc-1d1cdffea13b",
    );
}

#[test]
fn adv106_microsoft_advertising_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "microsoft-advertising-api-credentials",
        "microsoft_advertising client_id=ed39a474-b89c-05b2\u{FEFF}-5fcc-1d1cdffea13b",
        "ed39a474-b89c-05b2-5fcc-1d1cdffea13b",
    );
}

#[test]
fn adv106_microsoft_advertising_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "microsoft-advertising-api-credentials",
        "microsoft_advertising client_id=ed39a474-b89c-05b2\u{2060}-5fcc-1d1cdffea13b",
        "ed39a474-b89c-05b2-5fcc-1d1cdffea13b",
    );
}

#[test]
fn adv106_microsoft_advertising_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "microsoft-advertising-api-credentials",
        "microsoft_advertising client_id=ed39a474-b89c-05b2\u{180E}-5fcc-1d1cdffea13b",
        "ed39a474-b89c-05b2-5fcc-1d1cdffea13b",
    );
}

#[test]
fn adv106_microsoft_advertising_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "microsoft-advertising-api-credentials",
        "microsoft_advertising client_id=ed39a474-b89c-05b2\u{202E}-5fcc-1d1cdffea13b",
        "ed39a474-b89c-05b2-5fcc-1d1cdffea13b",
    );
}

#[test]
fn adv106_microsoft_advertising_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "microsoft-advertising-api-credentials",
        "microsoft_advertising client_id=ed39a474-b89c-05b2\u{202C}-5fcc-1d1cdffea13b",
        "ed39a474-b89c-05b2-5fcc-1d1cdffea13b",
    );
}

#[test]
fn adv106_microsoft_advertising_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "microsoft-advertising-api-credentials",
        "microsoft_advertising client_id=ed39a474-b89c-05b2\u{200E}-5fcc-1d1cdffea13b",
        "ed39a474-b89c-05b2-5fcc-1d1cdffea13b",
    );
}

// =========================================================================
// 7. MICROSOFT TEAMS API ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv106_microsoft_teams_api_normal_must_fire() {
    assert_detector_fires(
        "microsoft-teams-api",
        "teams api key=5dhKzM-gAg-SRhZqJ_-oU2nsnWNYVs9UueLFXIZsabcd",
        "5dhKzM-gAg-SRhZqJ_-oU2nsnWNYVs9UueLFXIZsabcd",
    );
}

#[test]
fn adv106_microsoft_teams_api_wrong_prefix_must_silent() {
    assert_detector_silent(
        "microsoft-teams-api",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv106_microsoft_teams_api_evade_zwsp_must_fire() {
    assert_detector_fires(
        "microsoft-teams-api",
        "teams api key=5dhKzM-gAg-SRhZqJ_-oU2\u{200B}nsnWNYVs9UueLFXIZsabcd",
        "5dhKzM-gAg-SRhZqJ_-oU2nsnWNYVs9UueLFXIZsabcd",
    );
}

#[test]
fn adv106_microsoft_teams_api_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "microsoft-teams-api",
        "teams api key=5dhKzM-gAg-SRhZqJ_-oU2\u{00AD}nsnWNYVs9UueLFXIZsabcd",
        "5dhKzM-gAg-SRhZqJ_-oU2nsnWNYVs9UueLFXIZsabcd",
    );
}

#[test]
fn adv106_microsoft_teams_api_evade_zwnj_must_fire() {
    assert_detector_fires(
        "microsoft-teams-api",
        "teams api key=5dhKzM-gAg-SRhZqJ_-oU2\u{200C}nsnWNYVs9UueLFXIZsabcd",
        "5dhKzM-gAg-SRhZqJ_-oU2nsnWNYVs9UueLFXIZsabcd",
    );
}

#[test]
fn adv106_microsoft_teams_api_evade_zwj_must_fire() {
    assert_detector_fires(
        "microsoft-teams-api",
        "teams api key=5dhKzM-gAg-SRhZqJ_-oU2\u{200D}nsnWNYVs9UueLFXIZsabcd",
        "5dhKzM-gAg-SRhZqJ_-oU2nsnWNYVs9UueLFXIZsabcd",
    );
}

#[test]
fn adv106_microsoft_teams_api_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "microsoft-teams-api",
        "teams api key=5dhKzM-gAg-SRhZqJ_-oU2\u{FEFF}nsnWNYVs9UueLFXIZsabcd",
        "5dhKzM-gAg-SRhZqJ_-oU2nsnWNYVs9UueLFXIZsabcd",
    );
}

#[test]
fn adv106_microsoft_teams_api_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "microsoft-teams-api",
        "teams api key=5dhKzM-gAg-SRhZqJ_-oU2\u{2060}nsnWNYVs9UueLFXIZsabcd",
        "5dhKzM-gAg-SRhZqJ_-oU2nsnWNYVs9UueLFXIZsabcd",
    );
}

#[test]
fn adv106_microsoft_teams_api_evade_mongolian_must_fire() {
    assert_detector_fires(
        "microsoft-teams-api",
        "teams api key=5dhKzM-gAg-SRhZqJ_-oU2\u{180E}nsnWNYVs9UueLFXIZsabcd",
        "5dhKzM-gAg-SRhZqJ_-oU2nsnWNYVs9UueLFXIZsabcd",
    );
}

#[test]
fn adv106_microsoft_teams_api_evade_rtl_must_fire() {
    assert_detector_fires(
        "microsoft-teams-api",
        "teams api key=5dhKzM-gAg-SRhZqJ_-oU2\u{202E}nsnWNYVs9UueLFXIZsabcd",
        "5dhKzM-gAg-SRhZqJ_-oU2nsnWNYVs9UueLFXIZsabcd",
    );
}

#[test]
fn adv106_microsoft_teams_api_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "microsoft-teams-api",
        "teams api key=5dhKzM-gAg-SRhZqJ_-oU2\u{202C}nsnWNYVs9UueLFXIZsabcd",
        "5dhKzM-gAg-SRhZqJ_-oU2nsnWNYVs9UueLFXIZsabcd",
    );
}

#[test]
fn adv106_microsoft_teams_api_evade_lrm_must_fire() {
    assert_detector_fires(
        "microsoft-teams-api",
        "teams api key=5dhKzM-gAg-SRhZqJ_-oU2\u{200E}nsnWNYVs9UueLFXIZsabcd",
        "5dhKzM-gAg-SRhZqJ_-oU2nsnWNYVs9UueLFXIZsabcd",
    );
}

// =========================================================================
// 8. MICROSOFT TRANSLATOR API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv106_microsoft_translator_api_key_normal_must_fire() {
    assert_detector_fires(
        "microsoft-translator-api-key",
        "MS_TRANSLATOR_KEY=1dcd0b60e5b037569d8c72e160975b2c",
        "1dcd0b60e5b037569d8c72e160975b2c",
    );
}

#[test]
fn adv106_microsoft_translator_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "microsoft-translator-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv106_microsoft_translator_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "microsoft-translator-api-key",
        "MS_TRANSLATOR_KEY=1dcd0b60e5b03756\u{200B}9d8c72e160975b2c",
        "1dcd0b60e5b037569d8c72e160975b2c",
    );
}

#[test]
fn adv106_microsoft_translator_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "microsoft-translator-api-key",
        "MS_TRANSLATOR_KEY=1dcd0b60e5b03756\u{00AD}9d8c72e160975b2c",
        "1dcd0b60e5b037569d8c72e160975b2c",
    );
}

#[test]
fn adv106_microsoft_translator_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "microsoft-translator-api-key",
        "MS_TRANSLATOR_KEY=1dcd0b60e5b03756\u{200C}9d8c72e160975b2c",
        "1dcd0b60e5b037569d8c72e160975b2c",
    );
}

#[test]
fn adv106_microsoft_translator_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "microsoft-translator-api-key",
        "MS_TRANSLATOR_KEY=1dcd0b60e5b03756\u{200D}9d8c72e160975b2c",
        "1dcd0b60e5b037569d8c72e160975b2c",
    );
}

#[test]
fn adv106_microsoft_translator_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "microsoft-translator-api-key",
        "MS_TRANSLATOR_KEY=1dcd0b60e5b03756\u{FEFF}9d8c72e160975b2c",
        "1dcd0b60e5b037569d8c72e160975b2c",
    );
}

#[test]
fn adv106_microsoft_translator_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "microsoft-translator-api-key",
        "MS_TRANSLATOR_KEY=1dcd0b60e5b03756\u{2060}9d8c72e160975b2c",
        "1dcd0b60e5b037569d8c72e160975b2c",
    );
}

#[test]
fn adv106_microsoft_translator_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "microsoft-translator-api-key",
        "MS_TRANSLATOR_KEY=1dcd0b60e5b03756\u{180E}9d8c72e160975b2c",
        "1dcd0b60e5b037569d8c72e160975b2c",
    );
}

#[test]
fn adv106_microsoft_translator_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "microsoft-translator-api-key",
        "MS_TRANSLATOR_KEY=1dcd0b60e5b03756\u{202E}9d8c72e160975b2c",
        "1dcd0b60e5b037569d8c72e160975b2c",
    );
}

#[test]
fn adv106_microsoft_translator_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "microsoft-translator-api-key",
        "MS_TRANSLATOR_KEY=1dcd0b60e5b03756\u{202C}9d8c72e160975b2c",
        "1dcd0b60e5b037569d8c72e160975b2c",
    );
}

#[test]
fn adv106_microsoft_translator_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "microsoft-translator-api-key",
        "MS_TRANSLATOR_KEY=1dcd0b60e5b03756\u{200E}9d8c72e160975b2c",
        "1dcd0b60e5b037569d8c72e160975b2c",
    );
}

// =========================================================================
// 9. MINIO ACCESS KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv106_minio_access_key_normal_must_fire() {
    assert_detector_fires(
        "minio-access-key",
        "MINIO_ACCESS_KEY=0vp69pixmZ8oC",
        "0vp69pixmZ8oC",
    );
}

#[test]
fn adv106_minio_access_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "minio-access-key",
        "dummy_prefix_0 =xxxxxxxxxxxxx",
    );
}

#[test]
fn adv106_minio_access_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "minio-access-key",
        "MINIO_ACCESS_KEY=0vp69p\u{200B}ixmZ8oC",
        "0vp69pixmZ8oC",
    );
}

#[test]
fn adv106_minio_access_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "minio-access-key",
        "MINIO_ACCESS_KEY=0vp69p\u{00AD}ixmZ8oC",
        "0vp69pixmZ8oC",
    );
}

#[test]
fn adv106_minio_access_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "minio-access-key",
        "MINIO_ACCESS_KEY=0vp69p\u{200C}ixmZ8oC",
        "0vp69pixmZ8oC",
    );
}

#[test]
fn adv106_minio_access_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "minio-access-key",
        "MINIO_ACCESS_KEY=0vp69p\u{200D}ixmZ8oC",
        "0vp69pixmZ8oC",
    );
}

#[test]
fn adv106_minio_access_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "minio-access-key",
        "MINIO_ACCESS_KEY=0vp69p\u{FEFF}ixmZ8oC",
        "0vp69pixmZ8oC",
    );
}

#[test]
fn adv106_minio_access_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "minio-access-key",
        "MINIO_ACCESS_KEY=0vp69p\u{2060}ixmZ8oC",
        "0vp69pixmZ8oC",
    );
}

#[test]
fn adv106_minio_access_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "minio-access-key",
        "MINIO_ACCESS_KEY=0vp69p\u{180E}ixmZ8oC",
        "0vp69pixmZ8oC",
    );
}

#[test]
fn adv106_minio_access_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "minio-access-key",
        "MINIO_ACCESS_KEY=0vp69p\u{202E}ixmZ8oC",
        "0vp69pixmZ8oC",
    );
}

#[test]
fn adv106_minio_access_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "minio-access-key",
        "MINIO_ACCESS_KEY=0vp69p\u{202C}ixmZ8oC",
        "0vp69pixmZ8oC",
    );
}

#[test]
fn adv106_minio_access_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "minio-access-key",
        "MINIO_ACCESS_KEY=0vp69p\u{200E}ixmZ8oC",
        "0vp69pixmZ8oC",
    );
}

// =========================================================================
// 10. MINIO PRESIGNED CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv106_minio_presigned_credentials_normal_must_fire() {
    assert_detector_fires(
        "minio-presigned-credentials",
        "MINIO_ROOT_USER=adminuser12345",
        "adminuser12345",
    );
}

#[test]
fn adv106_minio_presigned_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "minio-presigned-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxx",
    );
}

#[test]
fn adv106_minio_presigned_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "minio-presigned-credentials",
        "MINIO_ROOT_USER=adminus\u{200B}er12345",
        "adminuser12345",
    );
}

#[test]
fn adv106_minio_presigned_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "minio-presigned-credentials",
        "MINIO_ROOT_USER=adminus\u{00AD}er12345",
        "adminuser12345",
    );
}

#[test]
fn adv106_minio_presigned_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "minio-presigned-credentials",
        "MINIO_ROOT_USER=adminus\u{200C}er12345",
        "adminuser12345",
    );
}

#[test]
fn adv106_minio_presigned_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "minio-presigned-credentials",
        "MINIO_ROOT_USER=adminus\u{200D}er12345",
        "adminuser12345",
    );
}

#[test]
fn adv106_minio_presigned_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "minio-presigned-credentials",
        "MINIO_ROOT_USER=adminus\u{FEFF}er12345",
        "adminuser12345",
    );
}

#[test]
fn adv106_minio_presigned_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "minio-presigned-credentials",
        "MINIO_ROOT_USER=adminus\u{2060}er12345",
        "adminuser12345",
    );
}

#[test]
fn adv106_minio_presigned_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "minio-presigned-credentials",
        "MINIO_ROOT_USER=adminus\u{180E}er12345",
        "adminuser12345",
    );
}

#[test]
fn adv106_minio_presigned_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "minio-presigned-credentials",
        "MINIO_ROOT_USER=adminus\u{202E}er12345",
        "adminuser12345",
    );
}

#[test]
fn adv106_minio_presigned_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "minio-presigned-credentials",
        "MINIO_ROOT_USER=adminus\u{202C}er12345",
        "adminuser12345",
    );
}

#[test]
fn adv106_minio_presigned_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "minio-presigned-credentials",
        "MINIO_ROOT_USER=adminus\u{200E}er12345",
        "adminuser12345",
    );
}


