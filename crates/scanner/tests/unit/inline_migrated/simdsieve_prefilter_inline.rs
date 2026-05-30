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
    HOT_PATTERNS, HOT_PATTERN_DETECTOR_IDS, HOT_PATTERN_DISPLAY_NAMES, HOT_PATTERN_NAMES,
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
}

#[test]
fn hot_patterns_map_to_canonical_detector_identity() {
    // (prefix, detector_id, display_name, service). The id/name/service must
    // match the corresponding detectors/*.toml so scan output is identical
    // whether the named detector or the fast-path made the find. `sq0csp-`
    // has no canonical detector and stays fast-path-only (`hot-square_secret`).
    let expected: &[(&[u8], &str, &str, &str)] = &[
        (
            b"ghp_",
            "github-classic-pat",
            "GitHub Classic PAT",
            "github",
        ),
        (b"sk-proj-", "openai-api-key", "OpenAI API Key", "openai"),
        (b"AKIA", "aws-access-key", "AWS Access Key", "aws"),
        // ASIA is a temporary STS *access key ID* (same `[0-9A-Z]{16}` shape
        // as AKIA, both owned by the aws-access-key detector + the verifier's
        // AWS_VALID_ACCESS_KEY_PREFIXES). It is NOT the session token (the
        // long base64 blob aws-session-token matches), so it maps to
        // aws-access-key, not aws-session-token.
        (b"ASIA", "aws-access-key", "AWS Access Key", "aws"),
        (b"SG.", "sendgrid-api-key", "SendGrid API Key", "sendgrid"),
        (b"xoxb-", "slack-bot-token", "Slack Bot Token", "slack"),
        (b"xoxp-", "slack-user-token", "Slack User Token", "slack"),
        (b"sq0csp-", "hot-square_secret", "Square Secret", "square"),
    ];
    assert_eq!(HOT_PATTERNS.len(), expected.len());
    for (i, (prefix, id, name, service)) in expected.iter().enumerate() {
        assert_eq!(HOT_PATTERNS[i], *prefix, "prefix at {i}");
        assert_eq!(HOT_PATTERN_DETECTOR_IDS[i], *id, "detector_id at {i}");
        assert_eq!(HOT_PATTERN_DISPLAY_NAMES[i], *name, "display_name at {i}");
        assert_eq!(HOT_PATTERN_NAMES[i], *service, "service at {i}");
    }

    // No id may regress to a leaky internal `hot-*` form except the one
    // pattern with no canonical detector.
    for id in HOT_PATTERN_DETECTOR_IDS {
        assert!(
            !id.starts_with("hot-") || *id == "hot-square_secret",
            "{id} leaks an internal hot-* id into scan output"
        );
    }
}
