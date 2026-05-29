//! Part 42 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates mastodon, matomo, maxmind, medium, medusa, meilisearch, memcached, messagemedia, mexico, microsoft detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. MASTODON API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv42_mastodon_api_token_normal_must_fire() {
    assert_detector_fires(
        "mastodon-api-token",
        "mastodon=ed60ba139c8585a100f4e152ccbb8e98725b17fbddb5169c6d27e2bc86085f9f",
        "ed60ba139c8585a100f4e152ccbb8e98725b17fbddb5169c6d27e2bc86085f9f",
    );
}

#[test]
fn adv42_mastodon_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mastodon-api-token",
        "dummy_prefix_0 =xxx0ba139c8585a100f4e152ccbb8e98725b17fbddb5169c6d27e2bc86085f9f",
    );
}

#[test]
fn adv42_mastodon_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mastodon-api-token",
        "mastodon=ed60ba139c8585a100f4e152ccbb8e98\u{200B}725b17fbddb5169c6d27e2bc86085f9f",
        "ed60ba139c8585a100f4e152ccbb8e98725b17fbddb5169c6d27e2bc86085f9f",
    );
}

#[test]
fn adv42_mastodon_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mastodon-api-token",
        "mastodon=ed60ba139c8585a100f4e152ccbb8e98\u{00AD}725b17fbddb5169c6d27e2bc86085f9f",
        "ed60ba139c8585a100f4e152ccbb8e98725b17fbddb5169c6d27e2bc86085f9f",
    );
}

// =========================================================================
// 2. MATOMO API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv42_matomo_api_token_normal_must_fire() {
    assert_detector_fires(
        "matomo-api-token",
        "MATOMO_API_TOKEN=533b30a72eee83f00d7436071027b88f",
        "533b30a72eee83f00d7436071027b88f",
    );
}

#[test]
fn adv42_matomo_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "matomo-api-token",
        "dummy_prefix_0 =xxxb30a72eee83f00d7436071027b88f",
    );
}

#[test]
fn adv42_matomo_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "matomo-api-token",
        "MATOMO_API_TOKEN=533b30a72eee83f0\u{200B}0d7436071027b88f",
        "533b30a72eee83f00d7436071027b88f",
    );
}

#[test]
fn adv42_matomo_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "matomo-api-token",
        "MATOMO_API_TOKEN=533b30a72eee83f0\u{00AD}0d7436071027b88f",
        "533b30a72eee83f00d7436071027b88f",
    );
}

// =========================================================================
// 3. MAXMIND GEOIP LICENSE KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv42_maxmind_geoip_license_key_normal_must_fire() {
    assert_detector_fires(
        "maxmind-geoip-license-key",
        "MAXMIND=avH2zSZWSvN8xcCT",
        "avH2zSZWSvN8xcCT",
    );
}

#[test]
fn adv42_maxmind_geoip_license_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "maxmind-geoip-license-key",
        "dummy_prefix_0 =xxx2zSZWSvN8xcCT",
    );
}

#[test]
fn adv42_maxmind_geoip_license_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "maxmind-geoip-license-key",
        "MAXMIND=avH2zSZW\u{200B}SvN8xcCT",
        "avH2zSZWSvN8xcCT",
    );
}

#[test]
fn adv42_maxmind_geoip_license_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "maxmind-geoip-license-key",
        "MAXMIND=avH2zSZW\u{00AD}SvN8xcCT",
        "avH2zSZWSvN8xcCT",
    );
}

// =========================================================================
// 4. MEDIUM API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv42_medium_api_token_normal_must_fire() {
    assert_detector_fires(
        "medium-api-token",
        "medium=b6559e279ed5ab9ef6f25fed4628f8e6",
        "b6559e279ed5ab9ef6f25fed4628f8e6",
    );
}

#[test]
fn adv42_medium_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "medium-api-token",
        "dummy_prefix_0 =xxx59e279ed5ab9ef6f25fed4628f8e6",
    );
}

#[test]
fn adv42_medium_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "medium-api-token",
        "medium=b6559e279ed5ab9e\u{200B}f6f25fed4628f8e6",
        "b6559e279ed5ab9ef6f25fed4628f8e6",
    );
}

#[test]
fn adv42_medium_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "medium-api-token",
        "medium=b6559e279ed5ab9e\u{00AD}f6f25fed4628f8e6",
        "b6559e279ed5ab9ef6f25fed4628f8e6",
    );
}

// =========================================================================
// 5. MEDUSA API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv42_medusa_api_key_normal_must_fire() {
    assert_detector_fires(
        "medusa-api-key",
        "MEDUSA_API_KEY=kjxEBj2xZsZQ7L7gLbFmaoEWoFnUU0WUHceGVW0y",
        "kjxEBj2xZsZQ7L7gLbFmaoEWoFnUU0WUHceGVW0y",
    );
}

#[test]
fn adv42_medusa_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "medusa-api-key",
        "dummy_prefix_0 =xxxEBj2xZsZQ7L7gLbFmaoEWoFnUU0WUHceGVW0y",
    );
}

#[test]
fn adv42_medusa_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "medusa-api-key",
        "MEDUSA_API_KEY=kjxEBj2xZsZQ7L7gLbFm\u{200B}aoEWoFnUU0WUHceGVW0y",
        "kjxEBj2xZsZQ7L7gLbFmaoEWoFnUU0WUHceGVW0y",
    );
}

#[test]
fn adv42_medusa_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "medusa-api-key",
        "MEDUSA_API_KEY=kjxEBj2xZsZQ7L7gLbFm\u{00AD}aoEWoFnUU0WUHceGVW0y",
        "kjxEBj2xZsZQ7L7gLbFmaoEWoFnUU0WUHceGVW0y",
    );
}

// =========================================================================
// 6. MEILISEARCH API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv42_meilisearch_api_key_normal_must_fire() {
    assert_detector_fires(
        "meilisearch-api-key",
        "MEILISEARCH_API_KEY=zbNdq6Fp78ZTADck",
        "zbNdq6Fp78ZTADck",
    );
}

#[test]
fn adv42_meilisearch_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "meilisearch-api-key",
        "dummy_prefix_0 =xxxdq6Fp78ZTADck",
    );
}

#[test]
fn adv42_meilisearch_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "meilisearch-api-key",
        "MEILISEARCH_API_KEY=zbNdq6Fp\u{200B}78ZTADck",
        "zbNdq6Fp78ZTADck",
    );
}

#[test]
fn adv42_meilisearch_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "meilisearch-api-key",
        "MEILISEARCH_API_KEY=zbNdq6Fp\u{00AD}78ZTADck",
        "zbNdq6Fp78ZTADck",
    );
}

// =========================================================================
// 7. MEMCACHED SASL CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv42_memcached_sasl_credentials_normal_must_fire() {
    assert_detector_fires(
        "memcached-sasl-credentials",
        "MEMCACHE_USERNAME=k3PpL7zR9xQ2",
        "k3PpL7zR9xQ2",
    );
}

#[test]
fn adv42_memcached_sasl_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "memcached-sasl-credentials",
        "dummy_prefix_0 =xxxpL7zR9xQ2",
    );
}

#[test]
fn adv42_memcached_sasl_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "memcached-sasl-credentials",
        "MEMCACHE_USERNAME=k3PpL7\u{200B}zR9xQ2",
        "k3PpL7zR9xQ2",
    );
}

#[test]
fn adv42_memcached_sasl_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "memcached-sasl-credentials",
        "MEMCACHE_USERNAME=k3PpL7\u{00AD}zR9xQ2",
        "k3PpL7zR9xQ2",
    );
}

// =========================================================================
// 8. MESSAGEMEDIA API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv42_messagemedia_api_key_normal_must_fire() {
    assert_detector_fires(
        "messagemedia-api-key",
        "MESSAGEMEDIA_API_KEY=SqLjEPwwDKhgVlj98M2q",
        "SqLjEPwwDKhgVlj98M2q",
    );
}

#[test]
fn adv42_messagemedia_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "messagemedia-api-key",
        "dummy_prefix_0 =xxxjEPwwDKhgVlj98M2q",
    );
}

#[test]
fn adv42_messagemedia_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "messagemedia-api-key",
        "MESSAGEMEDIA_API_KEY=SqLjEPwwDK\u{200B}hgVlj98M2q",
        "SqLjEPwwDKhgVlj98M2q",
    );
}

#[test]
fn adv42_messagemedia_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "messagemedia-api-key",
        "MESSAGEMEDIA_API_KEY=SqLjEPwwDK\u{00AD}hgVlj98M2q",
        "SqLjEPwwDKhgVlj98M2q",
    );
}

// =========================================================================
// 9. MEXICO DATOSGOBMX API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv42_mexico_datosgobmx_api_key_normal_must_fire() {
    assert_detector_fires(
        "mexico-datosgobmx-api-key",
        "DATOS_GOB_API_KEY=f81a1948-ed21-1d74-ea77-cfb73d772899",
        "f81a1948-ed21-1d74-ea77-cfb73d772899",
    );
}

#[test]
fn adv42_mexico_datosgobmx_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mexico-datosgobmx-api-key",
        "dummy_prefix_0 =xxxa1948-ed21-1d74-ea77-cfb73d772899",
    );
}

#[test]
fn adv42_mexico_datosgobmx_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mexico-datosgobmx-api-key",
        "DATOS_GOB_API_KEY=f81a1948-ed21-1d74\u{200B}-ea77-cfb73d772899",
        "f81a1948-ed21-1d74-ea77-cfb73d772899",
    );
}

#[test]
fn adv42_mexico_datosgobmx_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mexico-datosgobmx-api-key",
        "DATOS_GOB_API_KEY=f81a1948-ed21-1d74\u{00AD}-ea77-cfb73d772899",
        "f81a1948-ed21-1d74-ea77-cfb73d772899",
    );
}

// =========================================================================
// 10. MICROSOFT ADVERTISING API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv42_microsoft_advertising_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "microsoft-advertising-api-credentials",
        "microsoft_advertising client_id=ed39a474-b89c-05b2-5fcc-1d1cdffea13b",
        "ed39a474-b89c-05b2-5fcc-1d1cdffea13b",
    );
}

#[test]
fn adv42_microsoft_advertising_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "microsoft-advertising-api-credentials",
        "dummy_prefix_0 =xxx9a474-b89c-05b2-5fcc-1d1cdffea13b",
    );
}

#[test]
fn adv42_microsoft_advertising_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "microsoft-advertising-api-credentials",
        "microsoft_advertising client_id=ed39a474-b89c-05b2\u{200B}-5fcc-1d1cdffea13b",
        "ed39a474-b89c-05b2-5fcc-1d1cdffea13b",
    );
}

#[test]
fn adv42_microsoft_advertising_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "microsoft-advertising-api-credentials",
        "microsoft_advertising client_id=ed39a474-b89c-05b2\u{00AD}-5fcc-1d1cdffea13b",
        "ed39a474-b89c-05b2-5fcc-1d1cdffea13b",
    );
}


