//! Part 25 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates discord, dnsimple, and dockerhub detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. DISCORD BOT TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv25_discord_bot_normal_must_fire() {
    assert_detector_fires(
        "discord-bot-token",
        "discord_token = \"MTIzNDU2Nzg5MDEyMzQ1Njc4.A1B2C3.D4E5F6G7H8I9J0K1L2M3N4O5P6Q\"",
        "MTIzNDU2Nzg5MDEyMzQ1Njc4.A1B2C3.D4E5F6G7H8I9J0K1L2M3N4O5P6Q",
    );
}

#[test]
fn adv25_discord_bot_wrong_prefix_must_silent() {
    assert_detector_silent(
        "discord-bot-token",
        "wiscord_token = \"MTIzNDU2Nzg5MDEyMzQ1Njc4.A1B2C3.D4E5F6G7H8I9J0K1L2M3N4O5P6Q\"",
    );
}

#[test]
fn adv25_discord_bot_evade_zwsp_must_fire() {
    assert_detector_fires(
        "discord-bot-token",
        "discord\u{200B}_token = \"MTIzNDU2Nzg5MDEyMzQ1Njc4.A1B2C3.D4E5F6G7H8I9J0K1L2M3N4O5P6Q\"",
        "MTIzNDU2Nzg5MDEyMzQ1Njc4.A1B2C3.D4E5F6G7H8I9J0K1L2M3N4O5P6Q",
    );
}

#[test]
fn adv25_discord_bot_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "discord-bot-token",
        "discord_token = \"MTIzNDU2Nzg5MDEyMzQ1Njc4.A1B2C3.D4E5F6G7\u{00AD}H8I9J0K1L2M3N4O5P6Q\"",
        "MTIzNDU2Nzg5MDEyMzQ1Njc4.A1B2C3.D4E5F6G7H8I9J0K1L2M3N4O5P6Q",
    );
}

#[test]
fn adv25_discord_bot_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "discord-bot-token",
        "d\u{0456}scord_token = \"MTIzNDU2Nzg5MDEyMzQ1Njc4.A1B2C3.D4E5F6G7H8I9J0K1L2M3N4O5P6Q\"",
        "MTIzNDU2Nzg5MDEyMzQ1Njc4.A1B2C3.D4E5F6G7H8I9J0K1L2M3N4O5P6Q",
    );
}

// =========================================================================
// 2. DNSIMPLE API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv25_dnsimple_normal_must_fire() {
    assert_detector_fires(
        "dnsimple-api-token",
        "dnsimple_token = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv25_dnsimple_wrong_prefix_must_silent() {
    assert_detector_silent(
        "dnsimple-api-token",
        "fnsimple_token = \"0000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv25_dnsimple_evade_zwsp_must_fire() {
    assert_detector_fires(
        "dnsimple-api-token",
        "dnsimple\u{200B}_token = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv25_dnsimple_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "dnsimple-api-token",
        "dnsimple_token = \"00000000000000000000\u{00AD}00000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv25_dnsimple_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "dnsimple-api-token",
        "dns\u{0456}mple_token = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

// =========================================================================
// 3. DOCKER HUB PAT ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv25_dockerhub_normal_must_fire() {
    assert_detector_fires(
        "dockerhub-pat",
        "dodo_pat_00000000-0000-0000-0000-000000000000",
        "dodo_pat_00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv25_dockerhub_wrong_prefix_must_silent() {
    assert_detector_silent(
        "dockerhub-pat",
        "fodo_pat_00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv25_dockerhub_evade_zwsp_must_fire() {
    assert_detector_fires(
        "dockerhub-pat",
        "dodo_pat\u{200B}_00000000-0000-0000-0000-000000000000",
        "dodo_pat_00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv25_dockerhub_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "dockerhub-pat",
        "dodo_pat_00000000-0000-0000-0000-000000\u{00AD}000000",
        "dodo_pat_00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv25_dockerhub_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "dockerhub-pat",
        "d\u{043E}d\u{043E}_pat_00000000-0000-0000-0000-000000000000",
        "dodo_pat_00000000-0000-0000-0000-000000000000",
    );
}
