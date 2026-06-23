//! Migrated from src/simdsieve_prefilter.rs.
//!
//! The three metadata arrays + HOT_PATTERNS are index-parallel and must stay
//! consistent: hot_patterns.rs indexes all four by the same `pattern_idx`.
//! As of 2026-05-29 the arrays carry the CANONICAL detector identity (id /
//! name / service) the fast-path stands in for - not an internal `hot-*` /
//! `*_key` label - so the same secret surfaces with the same identity on
//! every platform. This pins that mapping so a table edit that desyncs the
//! arrays (or regresses an id back to a `hot-*` form) fails CI.
//!
//! The arrays are only exported under the `simdsieve` feature, so the
//! lean ci build (which drops simdsieve to kill its prefilter footprint)
//! skips this regression too.
#![cfg(feature = "simdsieve")]

use keyhog_scanner::testing::{
    hot_pattern_index_at, validate_hot_pattern_runtime_table_lengths, HOT_PATTERNS,
    HOT_PATTERN_DETECTOR_IDS, HOT_PATTERN_DISPLAY_NAMES, HOT_PATTERN_MIN_LENGTHS,
    HOT_PATTERN_NAMES,
};

#[test]
fn hot_pattern_arrays_are_index_parallel() {
    let n = HOT_PATTERNS.len();
    assert_eq!(HOT_PATTERN_NAMES.len(), n, "service array length");
    assert_eq!(HOT_PATTERN_DETECTOR_IDS.len(), n, "id array length");
    assert_eq!(
        HOT_PATTERN_DISPLAY_NAMES.len(),
        n,
        "display-name array length"
    );
    assert_eq!(HOT_PATTERN_MIN_LENGTHS.len(), n, "min-length array length");
}

#[test]
fn hot_patterns_map_to_canonical_detector_identity() {
    // (prefix, min_len, detector_id, display_name, service). The id/name/service must
    // match the corresponding detectors/*.toml so scan output is identical
    // whether the named detector or the fast-path made the find.
    let expected: &[(&[u8], usize, &str, &str, &str)] = &[
        (
            b"ghp_",
            40,
            "github-classic-pat",
            "GitHub Classic PAT",
            "github",
        ),
        (
            b"sk-proj-",
            20,
            "openai-api-key",
            "OpenAI API Key",
            "openai",
        ),
        (b"AKIA", 20, "aws-access-key", "AWS Access Key", "aws"),
        // ASIA is a temporary STS *access key ID* (same `[0-9A-Z]{16}` shape
        // as AKIA, both owned by the aws-access-key detector + the verifier's
        // AWS_VALID_ACCESS_KEY_PREFIXES). It is NOT the session token (the
        // long base64 blob aws-session-token matches), so it maps to
        // aws-access-key, not aws-session-token.
        (b"ASIA", 20, "aws-access-key", "AWS Access Key", "aws"),
        (
            b"SG.",
            26,
            "sendgrid-api-key",
            "SendGrid API Key",
            "sendgrid",
        ),
        (b"xoxb-", 16, "slack-bot-token", "Slack Bot Token", "slack"),
        (
            b"xoxp-",
            16,
            "slack-user-token",
            "Slack User Token",
            "slack",
        ),
        (
            b"sq0csp-",
            16,
            "square-access-token",
            "Square Access Token",
            "square",
        ),
        (
            b"sk_live_",
            32,
            "stripe-secret-key",
            "Stripe Secret Key",
            "stripe",
        ),
        (
            b"sk_test_",
            32,
            "stripe-secret-key",
            "Stripe Secret Key",
            "stripe",
        ),
        (
            b"rk_live_",
            32,
            "stripe-secret-key",
            "Stripe Secret Key",
            "stripe",
        ),
        (
            b"rk_test_",
            32,
            "stripe-secret-key",
            "Stripe Secret Key",
            "stripe",
        ),
    ];
    assert_eq!(HOT_PATTERNS.len(), expected.len());
    for (i, (prefix, min_len, id, name, service)) in expected.iter().enumerate() {
        assert_eq!(HOT_PATTERNS[i], *prefix, "prefix at {i}");
        assert_eq!(HOT_PATTERN_MIN_LENGTHS[i], *min_len, "min_len at {i}");
        assert_eq!(HOT_PATTERN_DETECTOR_IDS[i], *id, "detector_id at {i}");
        assert_eq!(HOT_PATTERN_DISPLAY_NAMES[i], *name, "display_name at {i}");
        assert_eq!(HOT_PATTERN_NAMES[i], *service, "service at {i}");
    }

    // No id may regress to a leaky internal `hot-*` form.
    for id in HOT_PATTERN_DETECTOR_IDS {
        assert!(
            !id.starts_with("hot-"),
            "{id} leaks an internal hot-* id into scan output"
        );
    }
}

#[test]
fn hot_pattern_index_resolves_every_prefix_from_the_shared_table() {
    for (idx, prefix) in HOT_PATTERNS.iter().enumerate() {
        assert_eq!(
            hot_pattern_index_at(prefix, 0),
            Some(idx),
            "prefix at slot {idx} resolves to its own slot"
        );

        let mut haystack = b"xx".to_vec();
        let offset = haystack.len();
        haystack.extend_from_slice(prefix);
        haystack.extend_from_slice(b"TAIL");
        assert_eq!(
            hot_pattern_index_at(&haystack, offset),
            Some(idx),
            "prefix at slot {idx} resolves at non-zero offset"
        );

        let mut near_miss = (*prefix).to_vec();
        let last = near_miss.len() - 1;
        near_miss[last] = if near_miss[last] == b'Z' { b'Y' } else { b'Z' };
        assert_eq!(
            hot_pattern_index_at(&near_miss, 0),
            None,
            "near miss for slot {idx} must not resolve"
        );
    }

    assert_eq!(hot_pattern_index_at(b"", 0), None, "empty haystack");
    assert_eq!(
        hot_pattern_index_at(b"prefix", b"prefix".len()),
        None,
        "offset at end of haystack"
    );
}

#[test]
fn hot_pattern_runtime_tables_fail_loud_on_length_drift() {
    let expected = HOT_PATTERNS.len();
    validate_hot_pattern_runtime_table_lengths(expected, expected, expected)
        .expect("matching runtime hot-pattern table lengths are valid");

    let err = validate_hot_pattern_runtime_table_lengths(expected - 1, expected, expected)
        .expect_err("validator length drift must fail scanner construction");
    let msg = err.to_string();
    assert!(
        msg.contains("hot_pattern_validators")
            && msg.contains("HOT_PATTERNS")
            && msg.contains("fix: rebuild all hot-pattern runtime tables"),
        "error must name the drifted table and remediation; got {msg}"
    );
}
