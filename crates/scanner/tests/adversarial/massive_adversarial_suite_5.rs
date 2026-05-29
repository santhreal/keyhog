//! Part 5 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates Anthropic, Asana, Axiom, Adobe, Apify, Alchemy, Amplitude, and Anyscale
//! detectors against zero-width spaces, soft hyphens, combining marks, homoglyphs,
//! control characters, and custom directional format overrides.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. ANTHROPIC API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv5_anthropic_key_normal_must_fire() {
    assert_detector_fires(
        "anthropic-api-key",
        "sk-ant-sid01-1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7a1b2c3d4e5f-1A2B3C4",
        "sk-ant-sid01-1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7a1b2c3d4e5f-1A2B3C4",
    );
}

#[test]
fn adv5_anthropic_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "anthropic-api-key",
        "sk-ant-sid02-1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7a1b2c3d4e5f-1A2B3C4",
    );
}

#[test]
fn adv5_anthropic_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "anthropic-api-key",
        "sk-ant\u{200B}-sid01-1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7a1b2c3d4e5f-1A2B3C4",
        "sk-ant-sid01-1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7a1b2c3d4e5f-1A2B3C4",
    );
}

#[test]
fn adv5_anthropic_key_evade_homoglyph_o_must_fire() {
    // Cyrillic 'о' visual replacement
    assert_detector_fires(
        "anthropic-api-key",
        "sk-ant-sid\u{043E}1-1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7a1b2c3d4e5f-1A2B3C4",
        "sk-ant-sid01-1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7a1b2c3d4e5f-1A2B3C4",
    );
}

#[test]
fn adv5_anthropic_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "anthropic-api-key",
        "sk-ant-sid01-1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7a1b\u{00AD}2c3d4e5f-1A2B3C4",
        "sk-ant-sid01-1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7a1b2c3d4e5f-1A2B3C4",
    );
}

// =========================================================================
// 2. ASANA PERSONAL ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv5_asana_pat_normal_must_fire() {
    assert_detector_fires(
        "asana-pat",
        "0/1234567890123456/a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
        "0/1234567890123456/a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
    );
}

#[test]
fn adv5_asana_pat_wrong_prefix_must_silent() {
    assert_detector_silent(
        "asana-pat",
        "1/1234567890123456/a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
    );
}

#[test]
fn adv5_asana_pat_evade_zwsp_slash_must_fire() {
    assert_detector_fires(
        "asana-pat",
        "0/\u{200B}1234567890123456/a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
        "0/1234567890123456/a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
    );
}

#[test]
fn adv5_asana_pat_evade_combining_tilde_must_fire() {
    // Combining tilde over slash or numbers
    assert_detector_fires(
        "asana-pat",
        "0/12345\u{0303}67890123456/a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
        "0/1234567890123456/a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
    );
}

// =========================================================================
// 3. AXIOM API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv5_axiom_token_normal_must_fire() {
    assert_detector_fires(
        "axiom-api-token",
        "xaat-01234567-89ab-cdef-0123-456789abcdef",
        "xaat-01234567-89ab-cdef-0123-456789abcdef",
    );
}

#[test]
fn adv5_axiom_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "axiom-api-token",
        "xabt-01234567-89ab-cdef-0123-456789abcdef",
    );
}

#[test]
fn adv5_axiom_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "axiom-api-token",
        "xaat\u{FEFF}-01234567-89ab-cdef-0123-456789abcdef",
        "xaat-01234567-89ab-cdef-0123-456789abcdef",
    );
}

#[test]
fn adv5_axiom_token_evade_bidi_must_fire() {
    assert_detector_fires(
        "axiom-api-token",
        "xaat-\u{202E}01234567-89ab-cdef-0123-456789abcdef",
        "xaat-01234567-89ab-cdef-0123-456789abcdef",
    );
}

// =========================================================================
// 4. ADOBE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv5_adobe_key_normal_must_fire() {
    assert_detector_fires(
        "adobe-api-key",
        "p8a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
        "p8a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
    );
}

#[test]
fn adv5_adobe_key_wrong_length_must_silent() {
    assert_detector_silent("adobe-api-key", "p8a1b2c3d4e5f6a1b2c3d4e5f6a1b2");
}

#[test]
fn adv5_adobe_key_evade_homoglyph_a_must_fire() {
    // Cyrillic 'а' visual replacement
    assert_detector_fires(
        "adobe-api-key",
        "p8\u{0430}1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
        "p8a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
    );
}

// =========================================================================
// 5. APIFY API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv5_apify_token_normal_must_fire() {
    assert_detector_fires(
        "apify-api-token",
        "apify_api_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8",
        "apify_api_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8",
    );
}

#[test]
fn adv5_apify_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "apify-api-token",
        "apifz_api_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8",
    );
}

#[test]
fn adv5_apify_token_evade_tab_must_fire() {
    assert_detector_fires(
        "apify-api-token",
        "apify_api\u{0009}_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8",
        "apify_api_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8",
    );
}

// =========================================================================
// 6. ALCHEMY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv5_alchemy_key_normal_must_fire() {
    assert_detector_fires(
        "alchemy-api-key",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv5_alchemy_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "alchemy-api-key",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1\u{200D}b2c3d4",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

// =========================================================================
// 7. AMPLITUDE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv5_amplitude_key_normal_must_fire() {
    assert_detector_fires(
        "amplitude-api-key",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

#[test]
fn adv5_amplitude_key_evade_backspace_must_fire() {
    assert_detector_fires(
        "amplitude-api-key",
        "a1b2c3d4e5f6a1b2c3d4\u{0008}e5f6a1b2c3d4",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );
}

// =========================================================================
// 8. ANYSCALE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv5_anyscale_key_normal_must_fire() {
    assert_detector_fires(
        "anyscale-api-key",
        "secret_a1b2c3d4e5f6g7h8i9j0k1l2m3",
        "secret_a1b2c3d4e5f6g7h8i9j0k1l2m3",
    );
}

#[test]
fn adv5_anyscale_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "anyscale-api-key",
        "secrez_a1b2c3d4e5f6g7h8i9j0k1l2m3",
    );
}

#[test]
fn adv5_anyscale_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "anyscale-api-key",
        "secret\u{180E}_a1b2c3d4e5f6g7h8i9j0k1l2m3",
        "secret_a1b2c3d4e5f6g7h8i9j0k1l2m3",
    );
}
