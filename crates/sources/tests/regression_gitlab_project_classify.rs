//! Regression: GitLab group/project *classification* — the pure, host-independent
//! path that parses a GitLab namespace, builds the `/api/v4` group-projects
//! endpoint, and rejects malformed input, all *before* any socket is opened.
//!
//! This file is deliberately DISTINCT from `regression_hosted_git_endpoint.rs`
//! (which drives the loopback `/api/v4` mock and the endpoint scheme/userinfo/
//! query refusals) and from GitHub coverage (GitHub uses `validate_org_name`
//! with a 39-char limit + leading/trailing-hyphen rule + "unsafe characters";
//! GitLab uses `validate_group_path` -> per-segment `validate_repo_name` with a
//! 100-char cap, `..`/separator refusal, and "non-alphanumeric" charset).
//!
//! Every assertion pins a CONCRETE value: the exact `Ok(())` variant, the exact
//! `SourceError::Other` refusal string (built with the same `{:?}` formatting the
//! production code uses, so the expected value is deterministic), the exact
//! factory arity error, or the exact source name. No accelerator, no git binary,
//! and no network are required — the group-path validator and the factory param
//! parser are pure functions reached through the crate's public API and its
//! `#[doc(hidden)]` testing facade.
#![cfg(feature = "gitlab")]

use keyhog_core::{Source, SourceError};
use keyhog_sources::create_source;
use keyhog_sources::testing::{SourceTestApi, TestApi};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Pin an acceptance to the exact `Ok(())` variant. `SourceError` is not
/// `PartialEq`, so a match (not `assert_eq!(_, Ok(()))`) is how acceptance is
/// bound to a concrete value.
fn assert_group_accepted(group: &str) {
    match TestApi.validate_gitlab_group_path(group) {
        Ok(()) => {}
        Err(err) => panic!("group {group:?} must be accepted, got refusal: {err}"),
    }
}

/// Return the inner `SourceError::Other` message for a refused group path,
/// asserting the error variant is exactly `Other` (never `Io`/`Git`).
fn group_refusal_message(group: &str) -> String {
    match TestApi.validate_gitlab_group_path(group) {
        Ok(()) => panic!("group {group:?} must be refused, but validation accepted it"),
        Err(SourceError::Other(msg)) => msg,
        Err(other) => panic!("group {group:?} refusal must be SourceError::Other, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Namespace (group path) classification — positive
// ---------------------------------------------------------------------------

#[test]
fn group_path_accepts_flat_nested_and_charset_namespaces() {
    // Flat namespace, a two-segment subgroup namespace, and the full
    // [A-Za-z0-9._-] segment alphabet must all classify as valid GitLab groups.
    assert_group_accepted("santhsecurity");
    assert_group_accepted("platform/sub-group");
    assert_group_accepted("platform/sub-group/team-alpha");
    assert_group_accepted("a.b_c-d");
}

// ---------------------------------------------------------------------------
// Namespace classification — negative twins (exact refusal strings)
// ---------------------------------------------------------------------------

#[test]
fn group_path_rejects_empty_with_exact_message() {
    let msg = group_refusal_message("");
    assert_eq!(
        msg,
        format!(
            "gitlab: refusing group path with invalid length or slash placement: {:?}",
            ""
        ),
    );
}

#[test]
fn group_path_rejects_leading_slash() {
    let msg = group_refusal_message("/root");
    assert_eq!(
        msg,
        format!(
            "gitlab: refusing group path with invalid length or slash placement: {:?}",
            "/root"
        ),
    );
}

#[test]
fn group_path_rejects_trailing_slash() {
    let msg = group_refusal_message("root/");
    assert_eq!(
        msg,
        format!(
            "gitlab: refusing group path with invalid length or slash placement: {:?}",
            "root/"
        ),
    );
}

#[test]
fn group_path_rejects_empty_middle_segment_zero_length() {
    // `root//child` splits to ["root", "", "child"]; the empty middle segment is
    // a zero-length repo name, refused by the per-segment length guard — NOT the
    // top-level slash-placement guard (which only checks leading/trailing).
    let msg = group_refusal_message("root//child");
    assert_eq!(
        msg,
        "gitlab: refusing repo with out-of-range name length (0)".to_string(),
    );
}

#[test]
fn group_path_rejects_dotdot_traversal_segment() {
    // `..` as a namespace segment is a path-traversal gadget into the temp clone
    // root and must be refused by name, not silently normalized.
    let msg = group_refusal_message("../root");
    assert_eq!(
        msg,
        format!(
            "gitlab: refusing repo with traversal/separator in name: {:?}",
            ".."
        ),
    );
}

#[test]
fn group_path_rejects_backslash_segment() {
    // A backslash inside a single segment (no '/' to split on) is a Windows
    // separator; the segment validator refuses it as a traversal/separator.
    let group = "my\\group";
    let msg = group_refusal_message(group);
    assert_eq!(
        msg,
        format!(
            "gitlab: refusing repo with traversal/separator in name: {:?}",
            group
        ),
    );
}

#[test]
fn group_path_rejects_space_and_non_ascii_charset() {
    // A space is outside the [A-Za-z0-9._-] alphabet.
    let spaced = "root child";
    assert_eq!(
        group_refusal_message(spaced),
        format!(
            "gitlab: refusing repo with non-alphanumeric name: {:?}",
            spaced
        ),
    );

    // A non-ASCII letter is likewise refused (no Unicode-alphanumeric widening).
    let unicode = "grp\u{00e9}"; // "grpé"
    assert_eq!(
        group_refusal_message(unicode),
        format!(
            "gitlab: refusing repo with non-alphanumeric name: {:?}",
            unicode
        ),
    );
}

// ---------------------------------------------------------------------------
// Namespace classification — boundaries
// ---------------------------------------------------------------------------

#[test]
fn group_path_segment_length_boundary_100_ok_101_rejected() {
    // 100 chars is the inclusive maximum for a single namespace segment.
    assert_group_accepted(&"a".repeat(100));

    // 101 chars is refused, and the diagnostic reports the exact over-limit length.
    let msg = group_refusal_message(&"a".repeat(101));
    assert_eq!(
        msg,
        "gitlab: refusing repo with out-of-range name length (101)".to_string(),
    );
}

#[test]
fn group_path_total_length_boundary_over_512_rejected() {
    // A multi-segment namespace that is long but within all limits is accepted:
    // five 100-char segments joined by '/' = 504 bytes, each segment <= 100.
    let long_ok = vec!["a".repeat(100); 5].join("/");
    assert_eq!(long_ok.len(), 504, "test corpus sanity: joined length");
    assert_group_accepted(&long_ok);

    // A 513-byte group trips the top-level total-length guard *before* segment
    // splitting, so the refusal is the group-path (not per-repo) message.
    let msg = group_refusal_message(&"a".repeat(513));
    assert!(
        msg.starts_with("gitlab: refusing group path with invalid length or slash placement:"),
        "over-512 group must hit the group-path length guard, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Partial-coverage (listing truncation) classification
// ---------------------------------------------------------------------------

#[test]
fn listing_truncated_error_exact_message_and_variant() {
    // The page cap turns a partial GitLab group listing into a loud refusal so
    // unseen projects are never silently reported clean. Platform is "GitLab",
    // owner-kind is "group"; the numbers are echoed verbatim.
    let err = TestApi.gitlab_group_listing_truncated_error("santhsecurity", 250, 3);
    match err {
        SourceError::Other(msg) => assert_eq!(
            msg,
            "GitLab group repository listing for santhsecurity exceeded 3 pages \
             (250 repositories); refusing to scan a partial group repository collection \
             because unseen repositories would be reported clean"
                .to_string(),
        ),
        other => panic!("truncation error must be SourceError::Other, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Factory param classification (arity) — distinct from endpoint validation
// ---------------------------------------------------------------------------

#[test]
fn factory_missing_params_returns_exact_arity_error() {
    match create_source("gitlab-group", None) {
        Ok(_) => panic!("gitlab-group with no params must be refused"),
        Err(SourceError::Other(msg)) => assert_eq!(
            msg,
            "gitlab-group source requires GROUP, TOKEN, and optional ENDPOINT parameters"
                .to_string(),
        ),
        Err(other) => panic!("expected SourceError::Other, got: {other:?}"),
    }
}

#[test]
fn factory_missing_token_field_rejected() {
    // A single line (group only, no '\n' token field) must be refused.
    match create_source("gitlab-group", Some("onlygroup")) {
        Ok(_) => panic!("gitlab-group without a token field must be refused"),
        Err(SourceError::Other(msg)) => assert_eq!(
            msg,
            "gitlab-group source requires group and token".to_string(),
        ),
        Err(other) => panic!("expected SourceError::Other, got: {other:?}"),
    }
}

#[test]
fn factory_empty_token_field_rejected() {
    // Present-but-empty token field ("grp\n") is refused by the emptiness check.
    match create_source("gitlab-group", Some("grp\n")) {
        Ok(_) => panic!("gitlab-group with an empty token must be refused"),
        Err(SourceError::Other(msg)) => assert_eq!(
            msg,
            "gitlab-group source requires group and token".to_string(),
        ),
        Err(other) => panic!("expected SourceError::Other, got: {other:?}"),
    }
}

#[test]
fn factory_empty_group_field_rejected() {
    // Empty group field ("\ntok") is refused by the same emptiness check.
    match create_source("gitlab-group", Some("\ntok")) {
        Ok(_) => panic!("gitlab-group with an empty group must be refused"),
        Err(SourceError::Other(msg)) => assert_eq!(
            msg,
            "gitlab-group source requires group and token".to_string(),
        ),
        Err(other) => panic!("expected SourceError::Other, got: {other:?}"),
    }
}

#[test]
fn factory_constructs_source_and_reports_stable_name() {
    // Valid group+token constructs (no network, no endpoint validation yet) and
    // the source name is the stable "gitlab-group" plugin identifier.
    let dashed = create_source("gitlab-group", Some("grp\ntok"))
        .expect("valid group/token constructs a gitlab-group source");
    assert_eq!(dashed.name(), "gitlab-group");

    // The underscore alias resolves to the same plugin, and a self-hosted
    // ENDPOINT param is accepted at construction (endpoint is validated lazily at
    // scan time, covered by regression_hosted_git_endpoint.rs).
    let underscore = create_source(
        "gitlab_group",
        Some("grp\ntok\nhttps://gitlab.internal.example"),
    )
    .expect("underscore alias with self-hosted endpoint constructs");
    assert_eq!(underscore.name(), "gitlab-group");
}

#[test]
fn factory_unknown_gitlab_like_plugin_rejected() {
    // A look-alike plugin name is refused with the exact unknown-plugin error,
    // naming the offending plugin.
    match create_source("gitlab-project", None) {
        Ok(_) => panic!("unknown plugin name must be refused"),
        Err(SourceError::Other(msg)) => {
            assert_eq!(msg, "unknown source plugin: gitlab-project".to_string())
        }
        Err(other) => panic!("expected SourceError::Other, got: {other:?}"),
    }
}
