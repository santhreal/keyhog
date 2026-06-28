//! Characterization truth-table for the entropy-plausibility placeholder/decoy
//! marker gate (`bytes_contain_entropy_placeholder_marker`, consumed by
//! `entropy/plausibility.rs`).
//!
//! This gate is a SECOND, hardcoded marker vocabulary distinct from the Tier-B
//! `placeholder_words()` set, and it carries FIVE different match semantics:
//!   1. case-insensitive substring  (`your_`, `replace_me`, `change_me`,
//!      `insert_here`, `fake_`, `dummy_`, `mock_`)
//!   2. length-gated substring      (`secret_key` only when the value is < 20 bytes)
//!   3. compound prefix+suffix      (`AKIA…` that ends `EXAMPLE` or contains
//!      `1234567890`)
//!   4. angle-bracket presence      (`<` or `>` anywhere)
//!   5. whole-value EXACT, case-sensitive (`null`, `none`, `undefined`, `empty`,
//!      `default`, `secret`, `password`)
//!
//! Until now this recall-affecting suppression path had no behavioral test — only
//! a source-ownership gate. Every assertion below is an exact boolean for a
//! concrete input (Law 6). The point is twofold: (a) lock the current decision so
//! a future move of these markers into Tier-B data cannot silently change recall,
//! and (b) make the heterogeneous semantics (length gate, exact-vs-substring,
//! case sensitivity) explicit so the refactor must preserve or consciously change
//! each one. Pure decision logic — deterministic and host-independent.

use keyhog_scanner::testing::confidence::entropy_placeholder_marker as marker;

#[test]
fn category1_case_insensitive_substring_markers_suppress() {
    assert!(
        marker(b"YOUR_API_TOKEN"),
        "`your_` substring (upper) suppresses"
    );
    assert!(marker(b"yOuR_stuff"), "`your_` is case-insensitive");
    assert!(marker(b"please_replace_me_now"), "`replace_me` substring");
    assert!(marker(b"xxCHANGE_MExx"), "`change_me` substring (upper)");
    assert!(marker(b"insert_here_value"), "`insert_here` substring");
    assert!(marker(b"fake_key_123"), "`fake_` substring");
    assert!(marker(b"DUMMY_credential"), "`dummy_` substring");
    assert!(marker(b"mock_token_val"), "`mock_` substring");
}

#[test]
fn category1_negative_requires_the_underscore_form() {
    // `your-` / `your ` are NOT the `your_` marker, and no other clause fires, so
    // a hyphenated placeholder-ish word alone does not trip this gate.
    assert!(
        !marker(b"yourtokenvalue"),
        "`your` without the trailing underscore is not the marker"
    );
}

#[test]
fn category2_secret_key_is_gated_on_length_under_twenty() {
    // Exactly the `secret_key` clause: short values are decoys, long ones are not.
    assert!(
        marker(b"secret_key"),
        "`secret_key` (10 bytes < 20) is a decoy marker"
    );
    assert!(
        marker(b"my_secret_key"), // 13 bytes < 20
        "`secret_key` substring under 20 bytes suppresses"
    );
    // 24 bytes >= 20: the length gate closes and NOTHING else here matches, so a
    // longer `secret_key`-bearing value must NOT be suppressed by this gate — the
    // recall-load-bearing boundary.
    assert!(
        !marker(b"my_secret_key_padding_xx"),
        "`secret_key` at >= 20 bytes is past the length gate and not suppressed"
    );
}

#[test]
fn category3_akia_compound_only_for_example_or_sequential() {
    assert!(
        marker(b"AKIAIOSFODNN7EXAMPLE"),
        "AKIA…EXAMPLE is the canonical AWS docs decoy"
    );
    assert!(
        marker(b"akia0000001234567890"),
        "AKIA…1234567890 sequential filler is a decoy (prefix is case-insensitive)"
    );
    // AKIA prefix WITHOUT the EXAMPLE suffix or 1234567890 run is a real-looking
    // key shape and must NOT be suppressed by this marker.
    assert!(
        !marker(b"AKIAREALLOOKINGKEY99"),
        "a plain AKIA-prefixed key is not a decoy here (recall boundary)"
    );
}

#[test]
fn category4_angle_brackets_anywhere_suppress() {
    assert!(
        marker(b"<your-token-here>"),
        "leading `<` placeholder suppresses"
    );
    assert!(marker(b"value>tail"), "a bare `>` anywhere suppresses");
}

#[test]
fn category5_whole_value_exact_matches_suppress() {
    let exacts: [&[u8]; 7] = [
        b"null",
        b"none",
        b"undefined",
        b"empty",
        b"default",
        b"secret",
        b"password",
    ];
    for exact in exacts {
        assert!(
            marker(exact),
            "exact whole-value placeholder {exact:?} suppresses"
        );
    }
}

#[test]
fn category5_is_exact_not_substring() {
    // `null` as a SUBSTRING of a longer value is NOT the exact whole-value match,
    // and no other clause fires, so it is not suppressed — proving these seven are
    // whole-value-exact, not substring, markers.
    assert!(
        !marker(b"null_value"),
        "`null` as a substring is not the exact marker"
    );
    assert!(
        !marker(b"secretive"),
        "`secret` as a prefix is not the exact marker"
    );
    assert!(
        !marker(b"passwordless"),
        "`password` as a prefix is not the exact marker"
    );
}

#[test]
fn category5_exact_arm_is_case_sensitive() {
    // CURRENT behavior pinned (not endorsed): the whole-value arm compares raw
    // bytes, so the uppercase form is NOT suppressed by it. A future move to a
    // case-insensitive Tier-B list would flip this to `true` — and this assertion
    // makes that change visible rather than silent.
    assert!(
        !marker(b"NULL"),
        "uppercase NULL is not caught by the case-sensitive exact arm"
    );
}

#[test]
fn real_high_entropy_secrets_are_not_suppressed() {
    // The recall direction: random vendor-shaped bodies carry no marker.
    assert!(
        !marker(b"aB3xK9mQ2pL7vR4nT8wZ"),
        "random mixed-case body is not a decoy"
    );
    assert!(
        !marker(b"sk_live_4eC39HqLyjWDarjtT1zXyZ0u"),
        "a Stripe-shaped body is not a decoy"
    );
    assert!(!marker(b""), "empty input carries no marker");
}
