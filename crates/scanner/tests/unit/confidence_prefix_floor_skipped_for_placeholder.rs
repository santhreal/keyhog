//! The 0.8 confidence floor for well-known credential prefixes is skipped
//! when the credential carries a placeholder word (EXAMPLE / PLACEHOLDER /
//! DUMMY / FAKE / SAMPLE / CHANGEME). Without this, a `ghp_EXAMPLE_…` /
//! `sk_live_PLACEHOLDER_…` doc sample whose post-ML score had already been
//! slammed to ~0.05 by `apply_post_ml_penalties` would be lifted straight
//! back to 0.8 by `final_score.max(0.8)` in `scan_postprocess`, surfacing
//! every README/docs example as a finding.
//!
//! SecretBench mirror 2026-05-29: 154 docs-example-marker FPs (ghp_EXAMPLE,
//! AKIAEXAMPLEEXAMPLE12, sk_live_PLACEHOLDER, xoxb-…-EXAMPLE-TOKEN)
//! collapsed to single digits with this gate in place.

use keyhog_scanner::confidence::known_prefix_confidence_floor;

#[test]
fn placeholder_words_skip_the_floor() {
    // GitHub PAT prefix wrapping an EXAMPLE body.
    assert_eq!(
        known_prefix_confidence_floor("ghp_EXAMPLE_TOKEN_FROM_DOCS"),
        None,
        "ghp_EXAMPLE_… is a docs sample - the placeholder penalty must NOT be reversed by the prefix floor"
    );

    // AKIA prefix wrapping an EXAMPLE body.
    assert_eq!(
        known_prefix_confidence_floor("AKIAEXAMPLEEXAMPLE12"),
        None,
        "AKIA…EXAMPLE… is a docs sample"
    );

    // Stripe live prefix wrapping a PLACEHOLDER body.
    assert_eq!(
        known_prefix_confidence_floor("sk_live_PLACEHOLDER_NOT_A_REAL_KEY"),
        None,
        "sk_live_PLACEHOLDER_… is a docs sample"
    );

    // Slack bot token wrapping an EXAMPLE marker.
    assert_eq!(
        known_prefix_confidence_floor("xoxb-1234567890-1234567890-EXAMPLE-TOKEN"),
        None,
        "xoxb-…-EXAMPLE-TOKEN is a docs sample"
    );

    // Other placeholder words: DUMMY, FAKE, SAMPLE, CHANGEME (case-insensitive).
    assert_eq!(
        known_prefix_confidence_floor("ghp_DUMMYabcdef0123456"),
        None
    );
    assert_eq!(known_prefix_confidence_floor("ghp_fakeabcdef0123456"), None);
    assert_eq!(
        known_prefix_confidence_floor("ghp_SAMPLEabcdef012345"),
        None
    );
    assert_eq!(known_prefix_confidence_floor("AKIACHANGEME12345678"), None);
}

#[test]
fn real_prefix_bodies_still_get_the_floor() {
    // Random-looking bodies (real-credential-shaped) must keep the floor.
    assert_eq!(
        known_prefix_confidence_floor("ghp_AbCdEf1234567890ZyXwVu9876543210Qq"),
        Some(0.8),
        "ghp_ with a random body is a real credential - floor must apply"
    );
    // Real AWS access key shape - 20 chars, no placeholder substring.
    assert_eq!(
        known_prefix_confidence_floor("AKIAJP3GG7XYRIBQXOLA"),
        Some(0.8),
        "AKIA with a real-shape body keeps the floor"
    );
    assert_eq!(
        known_prefix_confidence_floor("sk_live_4eC39HqLyjWDarjtT1zdp7dc"),
        Some(0.8),
        "sk_live_ with a random body keeps the floor"
    );
}

#[test]
fn degenerate_repeat_run_skips_the_floor() {
    // CredData dogfood 2026-06-03: a known-prefix placeholder whose body is a
    // long run of one character (no placeholder WORD, so the word-skip misses
    // it) was crushed to ~0.08 by `apply_post_ml_penalties` and then floored
    // back to 0.8 by `final_score.max(0.8)`. The degenerate-run skip closes it.
    assert_eq!(
        known_prefix_confidence_floor("AKIAXXXXXXXXXXXXXXXX"),
        None,
        "AKIA + 16-X placeholder must NOT be lifted back to the 0.8 floor"
    );
    assert_eq!(
        known_prefix_confidence_floor("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        None,
        "ghp_ + all-'a' body is a placeholder, not a real PAT"
    );
    // A real AKIA body with no long run keeps the floor (recall guard, mirrors
    // the case above so the two heuristics are visibly distinct).
    assert_eq!(
        known_prefix_confidence_floor("AKIAJP3GG7XYRIBQXOLA"),
        Some(0.8),
        "a real-shape AKIA body (no 10+ run) keeps the floor"
    );
}
