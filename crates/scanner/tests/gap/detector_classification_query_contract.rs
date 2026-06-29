//! Behavioral contract for the Tier-B detector-classification query API
//! (crates/scanner/src/detector_classification.rs), against the LIVE bundled
//! `rules/detector-classification.toml`.
//!
//! The four query functions (`is_residual_weak_anchor`,
//! `is_private_key_block_detector`, `stripe_hot_confirmed_prefixes`, `validate`)
//! drive real suppression/resolution behaviour, yet the module's own
//! `#[cfg(test)]` tests only cover `parse_classification_rules` directly — the
//! cached operator-facing query path has zero behavioral coverage. These pin it
//! through the public facades with EXACT values, including cross-classification
//! negatives (an id in one bucket must report `false` for the other).

use keyhog_scanner::testing::{
    detector_classification_validate_for_test as validate,
    detector_is_private_key_block_for_test as is_pk_block,
    detector_is_residual_weak_anchor_for_test as is_weak_anchor,
    detector_stripe_hot_confirmed_prefixes_for_test as stripe_prefixes,
};

#[test]
fn live_rules_validate_clean() {
    assert_eq!(
        validate(),
        Ok(()),
        "the bundled detector-classification.toml must parse + validate clean"
    );
}

#[test]
fn weak_anchor_membership_is_exact() {
    // A real weak-anchor entry from the live TOML.
    assert_eq!(is_weak_anchor("flickr-api-key"), Ok(true));
    assert_eq!(is_weak_anchor("datadog-api-key"), Ok(true));
    // `ssh-private-key` is a valid detector id but lives in private_key_block,
    // NOT weak_anchor -> the weak-anchor query must report false for it.
    assert_eq!(
        is_weak_anchor("ssh-private-key"),
        Ok(false),
        "an id classified as private-key-block is not a weak anchor"
    );
    // A string that is not a classified id at all.
    assert_eq!(is_weak_anchor("definitely-not-a-classified-id"), Ok(false));
}

#[test]
fn private_key_block_membership_is_exact() {
    assert_eq!(is_pk_block("private-key"), Ok(true));
    assert_eq!(is_pk_block("ssh-private-key"), Ok(true));
    assert_eq!(is_pk_block("github-app-private-key"), Ok(true));
    // `flickr-api-key` is a weak anchor, NOT a private-key-block detector.
    assert_eq!(
        is_pk_block("flickr-api-key"),
        Ok(false),
        "a weak-anchor id is not a private-key-block detector"
    );
}

#[test]
fn stripe_hot_confirmed_prefixes_are_the_exact_ordered_list() {
    // The Vec preserves TOML order; pin the full slice, not just membership.
    assert_eq!(
        stripe_prefixes(),
        Ok(vec![
            "sk_live_".to_string(),
            "sk_test_".to_string(),
            "rk_live_".to_string(),
            "rk_test_".to_string(),
        ]),
        "the Stripe hot-path confirmed prefixes must match the live TOML exactly and in order"
    );
}
