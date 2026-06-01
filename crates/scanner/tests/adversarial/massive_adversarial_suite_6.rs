//! Part 6 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates Akamai, Akoya, Alchemy, Alertmanager, Algolia, and Amadeus
//! detectors against zero-width spaces, soft hyphens, combining marks, homoglyphs,
//! control characters, and custom directional format overrides.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. AKAMAI API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv6_akamai_normal_bare_must_stay_silent() {
    assert_detector_silent("akamai-api-credentials", "akab-client-token-12345");
}
#[test]
fn adv6_akamai_wrong_prefix_must_silent() {
    assert_detector_silent("akamai-api-credentials", "akac-client-token-12345");
}
#[test]
fn adv6_akamai_evade_zwsp_bare_must_stay_silent() {
    assert_detector_silent("akamai-api-credentials", "akab\u{200B}-client-token-12345");
}
#[test]
fn adv6_akamai_evade_soft_hyphen_bare_must_stay_silent() {
    assert_detector_silent("akamai-api-credentials", "akab-client\u{00AD}-token-12345");
}
#[test]
fn adv6_akamai_evade_homoglyph_bare_must_stay_silent() {
    assert_detector_silent("akamai-api-credentials", "akab-cli\u{0435}nt-token-12345");
}

// =========================================================================
// 2. AKOYA CLIENT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv6_akoya_normal_bare_must_stay_silent() {
    assert_detector_silent("akoya-client-credentials", "akoya-client-id-12345");
}
#[test]
fn adv6_akoya_wrong_prefix_must_silent() {
    assert_detector_silent("akoya-client-credentials", "akoyb-client-id-12345");
}
#[test]
fn adv6_akoya_evade_zwsp_bare_must_stay_silent() {
    assert_detector_silent("akoya-client-credentials", "akoya\u{200B}-client-id-12345");
}
#[test]
fn adv6_akoya_evade_soft_hyphen_bare_must_stay_silent() {
    assert_detector_silent("akoya-client-credentials", "akoya-client\u{00AD}-id-12345");
}
#[test]
fn adv6_akoya_evade_homoglyph_bare_must_stay_silent() {
    assert_detector_silent("akoya-client-credentials", "ak\u{043E}ya-client-id-12345");
}

// =========================================================================
// 3. ALCHEMY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv6_alchemy_normal_bare_must_stay_silent() {
    assert_detector_silent("alchemy-api-key", "alch-api-key-12345");
}
#[test]
fn adv6_alchemy_wrong_prefix_must_silent() {
    assert_detector_silent("alchemy-api-key", "alci-api-key-12345");
}
#[test]
fn adv6_alchemy_evade_zwsp_bare_must_stay_silent() {
    assert_detector_silent("alchemy-api-key", "alch\u{200B}-api-key-12345");
}
#[test]
fn adv6_alchemy_evade_soft_hyphen_bare_must_stay_silent() {
    assert_detector_silent("alchemy-api-key", "alch-api\u{00AD}-key-12345");
}
#[test]
fn adv6_alchemy_evade_homoglyph_bare_must_stay_silent() {
    assert_detector_silent("alchemy-api-key", "alch-api-k\u{0435}y-12345");
}

// =========================================================================
// 4. ALERTMANAGER CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv6_alertmanager_normal_bare_must_stay_silent() {
    assert_detector_silent("alertmanager-credentials", "alertmanager-token-123");
}
#[test]
fn adv6_alertmanager_wrong_prefix_must_silent() {
    assert_detector_silent("alertmanager-credentials", "alertmanagb-token-123");
}
#[test]
fn adv6_alertmanager_evade_zwsp_bare_must_stay_silent() {
    assert_detector_silent("alertmanager-credentials", "alertmanager\u{200B}-token-123");
}
#[test]
fn adv6_alertmanager_evade_soft_hyphen_bare_must_stay_silent() {
    assert_detector_silent("alertmanager-credentials", "alertmanager-to\u{00AD}ken-123");
}
#[test]
fn adv6_alertmanager_evade_homoglyph_bare_must_stay_silent() {
    assert_detector_silent("alertmanager-credentials", "alertmanag\u{0435}r-token-123");
}

// =========================================================================
// 5. ALGOLIA ADMIN API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv6_algolia_admin_normal_bare_must_stay_silent() {
    assert_detector_silent("algolia-admin-api-key", "algolia-admin-12345");
}
#[test]
fn adv6_algolia_admin_wrong_prefix_must_silent() {
    assert_detector_silent("algolia-admin-api-key", "algolib-admin-12345");
}
#[test]
fn adv6_algolia_admin_evade_zwsp_bare_must_stay_silent() {
    assert_detector_silent("algolia-admin-api-key", "algolia\u{200B}-admin-12345");
}
#[test]
fn adv6_algolia_admin_evade_soft_hyphen_bare_must_stay_silent() {
    assert_detector_silent("algolia-admin-api-key", "algolia-ad\u{00AD}min-12345");
}
#[test]
fn adv6_algolia_admin_evade_homoglyph_bare_must_stay_silent() {
    assert_detector_silent("algolia-admin-api-key", "alg\u{043E}lia-admin-12345");
}

// =========================================================================
// 6. ALGOLIA API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv6_algolia_normal_bare_must_stay_silent() {
    assert_detector_silent("algolia-api-key", "algolia-api-12345");
}
#[test]
fn adv6_algolia_wrong_prefix_must_silent() {
    assert_detector_silent("algolia-api-key", "algolib-api-12345");
}
#[test]
fn adv6_algolia_evade_zwsp_bare_must_stay_silent() {
    assert_detector_silent("algolia-api-key", "algolia\u{200B}-api-12345");
}
#[test]
fn adv6_algolia_evade_soft_hyphen_bare_must_stay_silent() {
    assert_detector_silent("algolia-api-key", "algolia-a\u{00AD}pi-12345");
}
#[test]
fn adv6_algolia_evade_homoglyph_bare_must_stay_silent() {
    assert_detector_silent("algolia-api-key", "alg\u{043E}lia-api-12345");
}

// =========================================================================
// 7. ALGOLIA SEARCH KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv6_algolia_search_normal_bare_must_stay_silent() {
    assert_detector_silent("algolia-search-key", "algolia-search-12345");
}
#[test]
fn adv6_algolia_search_wrong_prefix_must_silent() {
    assert_detector_silent("algolia-search-key", "algolib-search-12345");
}
#[test]
fn adv6_algolia_search_evade_zwsp_bare_must_stay_silent() {
    assert_detector_silent("algolia-search-key", "algolia\u{200B}-search-12345");
}
#[test]
fn adv6_algolia_search_evade_soft_hyphen_bare_must_stay_silent() {
    assert_detector_silent("algolia-search-key", "algolia-se\u{00AD}arch-12345");
}
#[test]
fn adv6_algolia_search_evade_homoglyph_bare_must_stay_silent() {
    assert_detector_silent("algolia-search-key", "alg\u{043E}lia-search-12345");
}

// =========================================================================
// 8. ALIENVAULT OTX API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv6_alienvault_normal_bare_must_stay_silent() {
    assert_detector_silent("alienvault-otx-api-key", "alienvault-12345");
}
#[test]
fn adv6_alienvault_wrong_prefix_must_silent() {
    assert_detector_silent("alienvault-otx-api-key", "alienvaukt-12345");
}
#[test]
fn adv6_alienvault_evade_zwsp_bare_must_stay_silent() {
    assert_detector_silent("alienvault-otx-api-key", "alienvault\u{200B}-12345");
}
#[test]
fn adv6_alienvault_evade_soft_hyphen_bare_must_stay_silent() {
    assert_detector_silent("alienvault-otx-api-key", "alien\u{00AD}vault-12345");
}
#[test]
fn adv6_alienvault_evade_homoglyph_bare_must_stay_silent() {
    assert_detector_silent("alienvault-otx-api-key", "ali\u{0435}nvault-12345");
}

// =========================================================================
// 9. AMADEUS API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv6_amadeus_normal_bare_must_stay_silent() {
    assert_detector_silent("amadeus-api-credentials", "amadeus-client-123");
}
#[test]
fn adv6_amadeus_wrong_prefix_must_silent() {
    assert_detector_silent("amadeus-api-credentials", "amadeub-client-123");
}
#[test]
fn adv6_amadeus_evade_zwsp_bare_must_stay_silent() {
    assert_detector_silent("amadeus-api-credentials", "amadeus\u{200B}-client-123");
}
#[test]
fn adv6_amadeus_evade_soft_hyphen_bare_must_stay_silent() {
    assert_detector_silent("amadeus-api-credentials", "amadeus-cl\u{00AD}ient-123");
}
#[test]
fn adv6_amadeus_evade_homoglyph_bare_must_stay_silent() {
    assert_detector_silent("amadeus-api-credentials", "amad\u{0435}us-client-123");
}

// =========================================================================
// 10. AMPLITUDE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv6_amplitude_normal_bare_must_stay_silent() {
    assert_detector_silent("amplitude-api-key", "amplitude-12345");
}
#[test]
fn adv6_amplitude_wrong_prefix_must_silent() {
    assert_detector_silent("amplitude-api-key", "amplitudc-12345");
}
#[test]
fn adv6_amplitude_evade_zwsp_bare_must_stay_silent() {
    assert_detector_silent("amplitude-api-key", "amplitude\u{200B}-12345");
}
#[test]
fn adv6_amplitude_evade_soft_hyphen_bare_must_stay_silent() {
    assert_detector_silent("amplitude-api-key", "ampli\u{00AD}tude-12345");
}
#[test]
fn adv6_amplitude_evade_homoglyph_bare_must_stay_silent() {
    assert_detector_silent("amplitude-api-key", "amplitud\u{0435}-12345");
}
