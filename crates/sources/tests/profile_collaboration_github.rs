//! Source-instrumentation suite for the GitHub collaboration adapter (surface
//! enumeration, pagination, content emission, rate-limit retries).
//!
//! WHY: the collaboration source enumerates issues / pull requests /
//! discussions / wiki / gists through one paginated API helper and one
//! emission sink. These tests pin the acquisition span, the per-page walk
//! spans, the real emitted content totals after dedup, and the retry
//! annotations recorded on rate limiting, so a refactor of the API helper or
//! the sink cannot silently drop the accounting.

#![cfg(feature = "github")]

mod support;

use keyhog_core::Source;
use keyhog_profile::{AnnotationId, Stage};
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{GitHubCollaborationSelection, SourceLimits};
use support::profile::{run_with_profile, run_with_profile_annotations, stage_calls};

fn issues_only() -> GitHubCollaborationSelection {
    GitHubCollaborationSelection {
        issues: true,
        ..Default::default()
    }
}

/// One issue with no comments records: 1 acquisition, 2 page walks (issues
/// page + comments page), 1 emitted unit, and the exact title+body bytes.
///
/// Locks out: the emission sink counting pre-dedup revisions, and the pages
/// helper losing its per-page walk span.
#[test]
fn collaboration_issues_record_pages_and_content_totals() {
    let title = "Leak in config";
    let body = "AKIACOLLABFIXTURE001";
    let expected_text = format!("{title}\n{body}");
    let server = httpmock::MockServer::start();
    let issues = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/repos/owner/repo/issues");
        then.status(200)
            .header("content-type", "application/json")
            .body(format!(
                r#"[{{"node_id":"I_1","number":1,"title":"{title}","body":"{body}","user":{{"login":"octocat"}},"updated_at":"2024-01-01T00:00:00Z","pull_request":null}}]"#
            ));
    });
    let comments = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/repos/owner/repo/issues/1/comments");
        then.status(200)
            .header("content-type", "application/json")
            .body("[]");
    });

    let (profile, rows) = run_with_profile(|| {
        TestApi
            .github_collaboration_source_with_endpoint(
                "owner/repo",
                &server.url(""),
                issues_only(),
                SourceLimits::default(),
            )
            .expect("collaboration source")
            .chunks()
            .collect::<Vec<_>>()
    });

    let chunks: Vec<_> = rows.iter().filter_map(|row| row.as_ref().ok()).collect();
    assert_eq!(chunks.len(), 1, "one issue yields one chunk: {rows:?}");
    assert_eq!(chunks[0].data.as_str(), expected_text);
    assert_eq!(issues.calls(), 1);
    assert_eq!(comments.calls(), 1);

    assert_eq!(stage_calls(&profile, Stage::SourceAcquire), 1);
    assert_eq!(stage_calls(&profile, Stage::SourceWalk), 2);
    assert_eq!(profile.input_units, 1);
    assert_eq!(profile.input_bytes, expected_text.len() as u64);
}

/// A persistently rate-limited endpoint (HTTP 429, zero-second Retry-After)
/// records one RetryAttempt annotation per backoff retry with the exact
/// 1-based attempt numbers before the gap surfaces.
///
/// Locks out: retries being silently absorbed (operators lose the rate-limit
/// signal) or recorded without their attempt number.
#[test]
fn collaboration_rate_limit_records_retry_annotations() {
    let server = httpmock::MockServer::start();
    let limited = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/repos/owner/repo/issues");
        then.status(429)
            .header("retry-after", "0")
            .header("content-type", "application/json")
            .body(r#"{"message":"API rate limit exceeded"}"#);
    });

    let (profile, retries, rows) = run_with_profile_annotations(
        AnnotationId::RetryAttempt,
        || {
            TestApi
                .github_collaboration_source_with_endpoint(
                    "owner/repo",
                    &server.url(""),
                    issues_only(),
                    SourceLimits::default(),
                )
                .expect("collaboration source")
                .chunks()
                .collect::<Vec<_>>()
        },
    );

    // Four attempts total; the three retries before the final failure record
    // their 1-based attempt numbers.
    assert_eq!(limited.calls(), 4);
    assert_eq!(retries, vec![1, 2, 3]);
    assert!(
        rows.iter().all(|row| row.is_err()),
        "a rate-limited surface surfaces a coverage gap, not chunks: {rows:?}"
    );
    assert_eq!(stage_calls(&profile, Stage::SourceAcquire), 1);
    assert_eq!(stage_calls(&profile, Stage::SourceWalk), 1);
    assert_eq!(profile.input_units, 0);
    assert_eq!(profile.input_bytes, 0);
}
