//! Regression (dogfood, CredData FP): a service-anchored (named) detector match
//! whose body is a long run of one repeated character — e.g. the
//! `AKIAXXXXXXXXXXXXXXXX` AWS-access-key placeholder CredData embeds — must be
//! crushed by the degenerate-repeat penalty.
//!
//! The bug: the `AKIA` (4-char) prefix dilutes the longest-run RATIO to exactly
//! `16/20 = 0.8`, which is NOT `> 0.8`, so it slipped under the named-branch
//! ratio gate; `char_diversity` is `4/20 = 0.2`, NOT `< 0.1`, so that gate
//! missed it too. keyhog reported it as a CRITICAL 80% finding (and even
//! base32-decoded a bogus AWS account_id from the all-`X` body). The absolute
//! run-length guard (`>= 10` identical chars — synthetic for any real
//! base32/hex/base64 secret, whose longest natural run is ~2-3) closes the hole
//! without touching low-diversity-but-legit named keys (64-hex PATs, UUIDs).

use keyhog_scanner::confidence::apply_post_ml_penalties;

#[test]
fn named_detector_all_x_placeholder_is_crushed() {
    // 4-char anchor + 16 'X': longest run 16, ratio 0.8 exactly (not > 0.8),
    // diversity 0.2 (not < 0.1). Only the absolute >= 10 run guard catches it.
    let adjusted = apply_post_ml_penalties(0.8, "AKIAXXXXXXXXXXXXXXXX", true);
    assert!(
        adjusted <= 0.1,
        "AKIA + 16-X placeholder must be crushed by the degenerate-run guard: got {adjusted}"
    );
}

#[test]
fn named_detector_real_low_diversity_hex_key_survives() {
    // A real 64-hex named-detector PAT (Linode-style): small alphabet → low
    // char_diversity (0.25), but the longest single-character run is 1. It must
    // NOT be penalized — the service anchor already proved it is the credential.
    let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let adjusted = apply_post_ml_penalties(0.9, hex, true);
    assert!(
        (adjusted - 0.9).abs() < 1e-9,
        "a real 64-hex named key (no long run) must survive unpenalized: got {adjusted}"
    );
}

#[test]
fn named_detector_short_run_under_threshold_survives() {
    // A legitimate-looking named token with a modest 4-char run (e.g. doubled
    // segments) is below the >= 10 absolute guard and the > 0.8 ratio, so it
    // stays unpenalized.
    let tok = "AKIAAAAA1B2C3D4E5F6G"; // run of 4 'A' then varied
    let adjusted = apply_post_ml_penalties(0.85, tok, true);
    assert!(
        (adjusted - 0.85).abs() < 1e-9,
        "a 4-char run named token must not be penalized: got {adjusted}"
    );
}
