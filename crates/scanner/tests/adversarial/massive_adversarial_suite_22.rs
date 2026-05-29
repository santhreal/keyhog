//! Part 22 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates Consul and Contentful detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. CONSUL ACL TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv22_consul_normal_must_fire() {
    assert_detector_fires(
        "consul-acl-token",
        "CONSUL_TOKEN = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv22_consul_wrong_prefix_must_silent() {
    assert_detector_silent(
        "consul-acl-token",
        "DONSUL_TOKEN = \"00000000-0000-0000-0000-000000000000\"",
    );
}

#[test]
fn adv22_consul_evade_zwsp_must_fire() {
    assert_detector_fires(
        "consul-acl-token",
        "CONSUL\u{200B}_TOKEN = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv22_consul_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "consul-acl-token",
        "CONSUL_TOKEN = \"00000000-0000-0000-0000-000000\u{00AD}000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv22_consul_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "consul-acl-token",
        "C\u{041E}NSUL_TOKEN = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

// =========================================================================
// 2. CONTENTFUL DELIVERY TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv22_contentful_normal_must_fire() {
    assert_detector_fires(
        "contentful-delivery-token",
        "CONTENTFUL_DELIVERY_TOKEN = \"abcde12345abcde12345abcde12345abcde12345abc\"",
        "abcde12345abcde12345abcde12345abcde12345abc",
    );
}

#[test]
fn adv22_contentful_wrong_prefix_must_silent() {
    assert_detector_silent(
        "contentful-delivery-token",
        "BONTENTFUL_DELIVERY_TOKEN = \"abcde12345abcde12345abcde12345abcde12345abc\"",
    );
}

#[test]
fn adv22_contentful_evade_zwsp_must_fire() {
    assert_detector_fires(
        "contentful-delivery-token",
        "CONTENTFUL\u{200B}_DELIVERY_TOKEN = \"abcde12345abcde12345abcde12345abcde12345abc\"",
        "abcde12345abcde12345abcde12345abcde12345abc",
    );
}

#[test]
fn adv22_contentful_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "contentful-delivery-token",
        "CONTENTFUL_DELIVERY_TOKEN = \"abcde12345abcde12345abcde\u{00AD}12345abcde12345abc\"",
        "abcde12345abcde12345abcde12345abcde12345abc",
    );
}

#[test]
fn adv22_contentful_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "contentful-delivery-token",
        "C\u{041E}NTENTFUL_DELIVERY_TOKEN = \"abcde12345abcde12345abcde12345abcde12345abc\"",
        "abcde12345abcde12345abcde12345abcde12345abc",
    );
}
