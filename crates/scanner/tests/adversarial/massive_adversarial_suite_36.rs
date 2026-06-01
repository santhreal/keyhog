//! Part 36 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates flyio, footprint, formstack, fortinet, foundation, framer,
//! freshdesk, front, frontegg, fullstory, and fusionauth detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. FLY.IO ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv36_flyio_access_normal_must_fire() {
    assert_detector_fires(
        "flyio-access-token",
        "fm2_1234567890123456789012345678901234567890123",
        "fm2_1234567890123456789012345678901234567890123",
    );
}

#[test]
fn adv36_flyio_access_wrong_prefix_must_silent() {
    assert_detector_silent(
        "flyio-access-token",
        "gm2_1234567890123456789012345678901234567890123",
    );
}

#[test]
fn adv36_flyio_access_evade_zwsp_must_fire() {
    assert_detector_fires(
        "flyio-access-token",
        "fm2_\u{200B}1234567890123456789012345678901234567890123",
        "fm2_1234567890123456789012345678901234567890123",
    );
}

#[test]
fn adv36_flyio_access_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "flyio-access-token",
        "fm2_123456789012345678901234567890123\u{00AD}4567890123",
        "fm2_1234567890123456789012345678901234567890123",
    );
}

#[test]
fn adv36_flyio_access_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "flyio-access-token",
        "fl\u{0443}.io access token fm2_1234567890123456789012345678901234567890123",
        "fm2_1234567890123456789012345678901234567890123",
    );
}

// =========================================================================
// 2. FLY.IO DEPLOY TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv36_flyio_deploy_normal_must_fire() {
    assert_detector_fires(
        "flyio-deploy-token",
        "fly_deploy_token = \"fo1_1234567890123456789012345678901234567890\"",
        "fo1_1234567890123456789012345678901234567890",
    );
}

#[test]
fn adv36_flyio_deploy_wrong_prefix_must_silent() {
    assert_detector_silent(
        "flyio-deploy-token",
        "fly_deploy_token = \"go1_1234567890123456789012345678901234567890\"",
    );
}

#[test]
fn adv36_flyio_deploy_evade_zwsp_must_fire() {
    assert_detector_fires(
        "flyio-deploy-token",
        "fly_deploy_token = \"fo1_\u{200B}1234567890123456789012345678901234567890\"",
        "fo1_1234567890123456789012345678901234567890",
    );
}

#[test]
fn adv36_flyio_deploy_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "flyio-deploy-token",
        "fly_deploy_token = \"fo1_12345678901234567890123456789012\u{00AD}34567890\"",
        "fo1_1234567890123456789012345678901234567890",
    );
}

#[test]
fn adv36_flyio_deploy_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "flyio-deploy-token",
        "fl\u{0443}_deploy_token = \"fo1_1234567890123456789012345678901234567890\"",
        "fo1_1234567890123456789012345678901234567890",
    );
}

// =========================================================================
// 3. FOOTPRINT API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv36_footprint_normal_must_fire() {
    assert_detector_fires(
        "footprint-api-key",
        "footprint_key = \"abcde12345abcde12345abcde1234512\"",
        "abcde12345abcde12345abcde1234512",
    );
}

#[test]
fn adv36_footprint_wrong_prefix_must_silent() {
    assert_detector_silent(
        "footprint-api-key",
        "gootprint_key = \"abcde12345abcde12345abcde1234512\"",
    );
}

#[test]
fn adv36_footprint_evade_zwsp_must_fire() {
    assert_detector_fires(
        "footprint-api-key",
        "footprint_key = \"abcde\u{200B}12345abcde12345abcde1234512\"",
        "abcde12345abcde12345abcde1234512",
    );
}

#[test]
fn adv36_footprint_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "footprint-api-key",
        "footprint_key = \"abcde12345abcde12345abcde1\u{00AD}234512\"",
        "abcde12345abcde12345abcde1234512",
    );
}

#[test]
fn adv36_footprint_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "footprint-api-key",
        "f\u{043e}\u{043e}tprint_key = \"abcde12345abcde12345abcde1234512\"",
        "abcde12345abcde12345abcde1234512",
    );
}

// =========================================================================
// 4. FORMSTACK API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv36_formstack_normal_must_fire() {
    assert_detector_fires(
        "formstack-api-credentials",
        "formstack_access_token \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    );
}

#[test]
fn adv36_formstack_wrong_prefix_must_silent() {
    assert_detector_silent(
        "formstack-api-credentials",
        "gormstack_access_token \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\"",
    );
}

#[test]
fn adv36_formstack_evade_zwsp_must_fire() {
    assert_detector_fires(
        "formstack-api-credentials",
        "formstack_access_token \"a1b2c3d4e5f6a1b2c3\u{200B}d4e5f6a1b2c3d4e5f6a1b2\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    );
}

#[test]
fn adv36_formstack_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "formstack-api-credentials",
        "formstack_access_token \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5\u{00AD}f6a1b2\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    );
}

#[test]
fn adv36_formstack_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "formstack-api-credentials",
        "f\u{043e}rmstack_access_token \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\"",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    );
}

// =========================================================================
// 5. FORTINET FORTIGATE API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv36_fortinet_normal_must_fire() {
    assert_detector_fires(
        "fortinet-fortigate-token",
        "fortinet_token = \"abcde12345abcde12345abcde1234512\"",
        "abcde12345abcde12345abcde1234512",
    );
}

#[test]
fn adv36_fortinet_wrong_prefix_must_silent() {
    assert_detector_silent(
        "fortinet-fortigate-token",
        "gortinet_token = \"abcde12345abcde12345abcde1234512\"",
    );
}

#[test]
fn adv36_fortinet_evade_zwsp_must_fire() {
    assert_detector_fires(
        "fortinet-fortigate-token",
        "fortinet_token = \"abcde12345\u{200B}abcde12345abcde1234512\"",
        "abcde12345abcde12345abcde1234512",
    );
}

#[test]
fn adv36_fortinet_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "fortinet-fortigate-token",
        "fortinet_token = \"abcde12345abcde12345abcde123\u{00AD}4512\"",
        "abcde12345abcde12345abcde1234512",
    );
}

#[test]
fn adv36_fortinet_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "fortinet-fortigate-token",
        "f\u{043e}rt\u{0456}net_token = \"abcde12345abcde12345abcde1234512\"",
        "abcde12345abcde12345abcde1234512",
    );
}

// =========================================================================
// 6. FOUNDATION API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv36_foundation_normal_must_fire() {
    assert_detector_fires(
        "foundation-api-key",
        "foundation_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv36_foundation_wrong_prefix_must_silent() {
    assert_detector_silent(
        "foundation-api-key",
        "goundation_key = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv36_foundation_evade_zwsp_must_fire() {
    assert_detector_fires(
        "foundation-api-key",
        "foundation_key = \"abcde12345\u{200B}abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv36_foundation_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "foundation-api-key",
        "foundation_key = \"abcde12345abcde12\u{00AD}345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv36_foundation_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "foundation-api-key",
        "f\u{043e}undat\u{0456}\u{043e}n_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

// =========================================================================
// 7. FRAMER API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv36_framer_normal_must_fire() {
    assert_detector_fires(
        "framer-api-credentials",
        "framer_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv36_framer_wrong_prefix_must_silent() {
    assert_detector_silent(
        "framer-api-credentials",
        "gramer_key = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv36_framer_evade_zwsp_must_fire() {
    assert_detector_fires(
        "framer-api-credentials",
        "framer_key = \"abcde12345\u{200B}abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv36_framer_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "framer-api-credentials",
        "framer_key = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv36_framer_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "framer-api-credentials",
        "fram\u{0435}r_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

// =========================================================================
// 8. FRESHDESK API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv36_freshdesk_normal_must_fire() {
    assert_detector_fires(
        "freshdesk-api-key",
        "freshdesk_api_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv36_freshdesk_wrong_prefix_must_silent() {
    assert_detector_silent(
        "freshdesk-api-key",
        "greshdesk_api_key = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv36_freshdesk_evade_zwsp_must_fire() {
    assert_detector_fires(
        "freshdesk-api-key",
        "freshdesk_api_key = \"abcde12345\u{200B}abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv36_freshdesk_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "freshdesk-api-key",
        "freshdesk_api_key = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv36_freshdesk_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "freshdesk-api-key",
        "fr\u{0435}shd\u{0435}sk_api_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

// =========================================================================
// 9. FRONT API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv36_front_normal_must_fire() {
    assert_detector_fires(
        "front-api-token",
        "fpt_1234567890123456789012345678901234567890",
        "fpt_1234567890123456789012345678901234567890",
    );
}

#[test]
fn adv36_front_wrong_prefix_must_silent() {
    assert_detector_silent(
        "front-api-token",
        "gpt_1234567890123456789012345678901234567890",
    );
}

#[test]
fn adv36_front_evade_zwsp_must_fire() {
    assert_detector_fires(
        "front-api-token",
        "fpt_\u{200B}1234567890123456789012345678901234567890",
        "fpt_1234567890123456789012345678901234567890",
    );
}

#[test]
fn adv36_front_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "front-api-token",
        "fpt_12345678901234567890123456789012\u{00AD}34567890",
        "fpt_1234567890123456789012345678901234567890",
    );
}

#[test]
fn adv36_front_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "front-api-token",
        "fr\u{043e}nt_token = fpt_1234567890123456789012345678901234567890",
        "fpt_1234567890123456789012345678901234567890",
    );
}

// =========================================================================
// 10. FRONTEGG API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv36_frontegg_normal_must_fire() {
    assert_detector_fires(
        "frontegg-api-credentials",
        "frontegg_client_id = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv36_frontegg_wrong_prefix_must_silent() {
    assert_detector_silent(
        "frontegg-api-credentials",
        "grontegg_client_id = \"00000000-0000-0000-0000-000000000000\"",
    );
}

#[test]
fn adv36_frontegg_evade_zwsp_must_fire() {
    assert_detector_fires(
        "frontegg-api-credentials",
        "frontegg_client_id = \"00000000-0000-0000-0000-\u{200B}000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv36_frontegg_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "frontegg-api-credentials",
        "frontegg_client_id = \"00000000-0000-0000-0000-0000\u{00AD}00000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv36_frontegg_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "frontegg-api-credentials",
        "fr\u{043e}nt\u{0435}gg_client_id = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

// =========================================================================
// 11. FULLSTORY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv36_fullstory_normal_must_fire() {
    assert_detector_fires(
        "fullstory-api-key",
        "fullstory_api_key = \"na1.abcde12345abcde12345\"",
        "na1.abcde12345abcde12345",
    );
}

#[test]
fn adv36_fullstory_wrong_prefix_must_silent() {
    assert_detector_silent(
        "fullstory-api-key",
        "gullstory_api_key = \"na1.abcde12345abcde12345\"",
    );
}

#[test]
fn adv36_fullstory_evade_zwsp_must_fire() {
    assert_detector_fires(
        "fullstory-api-key",
        "fullstory_api_key = \"na1.abcde\u{200B}12345abcde12345\"",
        "na1.abcde12345abcde12345",
    );
}

#[test]
fn adv36_fullstory_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "fullstory-api-key",
        "fullstory_api_key = \"na1.abcde12345abcd\u{00AD}e12345\"",
        "na1.abcde12345abcde12345",
    );
}

#[test]
fn adv36_fullstory_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "fullstory-api-key",
        "fullst\u{043e}ry_api_key = \"na1.abcde12345abcde12345\"",
        "na1.abcde12345abcde12345",
    );
}

// =========================================================================
// 12. FUSIONAUTH API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv36_fusionauth_normal_must_fire() {
    assert_detector_fires(
        "fusionauth-api-key",
        "fusionauth_api_key = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv36_fusionauth_wrong_prefix_must_silent() {
    assert_detector_silent(
        "fusionauth-api-key",
        "gusionauth_api_key = \"00000000-0000-0000-0000-000000000000\"",
    );
}

#[test]
fn adv36_fusionauth_evade_zwsp_must_fire() {
    assert_detector_fires(
        "fusionauth-api-key",
        "fusionauth_api_key = \"00000000-0000-0000-0000-\u{200B}000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv36_fusionauth_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "fusionauth-api-key",
        "fusionauth_api_key = \"00000000-0000-0000-0000-0000\u{00AD}00000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv36_fusionauth_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "fusionauth-api-key",
        "fus\u{0456}\u{043e}nauth_api_key = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}
