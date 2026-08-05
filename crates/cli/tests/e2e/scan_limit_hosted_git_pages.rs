//! E2E: `--limit-hosted-git-pages` boundary and partial-listing behavior.
//!
//! KH-204. The page budget is the only thing standing between a hosted-git
//! scan and an unbounded API walk, and a partial repository listing is the
//! worst possible outcome: the repositories that were never listed would be
//! reported clean. This exercises the exact page count issued at the bound,
//! one page short of it, and a mid-listing API failure.

#![cfg(feature = "gitlab")]

use crate::e2e::support::binary;
use httpmock::prelude::*;
use std::process::{Command, Output};

/// GitLab pagination stops on the first short page, so a page carrying fewer
/// than 100 projects terminates the walk.
const FULL_PAGE: usize = 100;

fn page_body(page: usize, count: usize) -> String {
    let projects: Vec<String> = (0..count)
        .map(|index| {
            format!(
                r#"{{"path_with_namespace":"grp/p{page}_{index}",
                    "http_url_to_repo":"http://127.0.0.1:1/grp/p{page}_{index}.git"}}"#
            )
        })
        .collect();
    format!("[{}]", projects.join(","))
}

/// Serve a group whose listing needs exactly `pages` requests: full pages up
/// to the last one, then a short page that terminates pagination.
fn gitlab_server(pages: usize) -> MockServer {
    let server = MockServer::start();
    for page in 1..=pages {
        let count = if page < pages { FULL_PAGE } else { 1 };
        let body = page_body(page, count);
        server.mock(|when, then| {
            when.method(GET)
                .path("/api/v4/groups/grp/projects")
                .query_param("page", page.to_string());
            then.status(200)
                .header("content-type", "application/json")
                .body(body);
        });
    }
    server
}

fn scan_group(server: &MockServer, pages_flag: &str) -> Output {
    Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--no-suppress-test-fixtures",
            "--allow-private-cloud-endpoint",
            "--format",
            "jsonl",
            "--gitlab-group",
            "grp",
            "--gitlab-token",
            "test-token",
            "--gitlab-endpoint",
            &server.base_url(),
            "--limit-hosted-git-pages",
            pages_flag,
        ])
        .output()
        .expect("spawn keyhog")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A listing that needs exactly two pages must issue exactly those two
/// requests under a two-page budget, must not report a page-cap truncation,
/// and must not ask for a third page.
#[test]
fn limit_hosted_git_pages_admits_a_listing_that_fits_the_budget_exactly() {
    let server = MockServer::start();
    let first = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v4/groups/grp/projects")
            .query_param("page", "1");
        then.status(200)
            .header("content-type", "application/json")
            .body(page_body(1, FULL_PAGE));
    });
    let last = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v4/groups/grp/projects")
            .query_param("page", "2");
        then.status(200)
            .header("content-type", "application/json")
            .body(page_body(2, 1));
    });
    let beyond = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v4/groups/grp/projects")
            .query_param("page", "3");
        then.status(200)
            .header("content-type", "application/json")
            .body("[]");
    });

    let output = scan_group(&server, "2");
    let stderr = stderr_of(&output);
    assert!(
        !stderr.contains("exceeded 2 pages"),
        "a listing that fits the budget must not report a page cap; \
         stderr={stderr}"
    );
    first.assert_calls(1);
    last.assert_calls(1);
    beyond.assert_calls(0);
}

/// One page short of what the listing needs, the scan must REFUSE rather than
/// scan the repositories it did manage to list: the unlisted ones would
/// otherwise be reported clean.
#[test]
fn limit_hosted_git_pages_one_short_refuses_a_partial_repository_collection() {
    let server = gitlab_server(2);
    let output = scan_group(&server, "1");
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("exceeded 1 pages"),
        "the page cap must name the budget it hit; stderr={stderr}"
    );
    assert!(
        stderr.contains("refusing to scan a partial group repository collection"),
        "a partial listing must fail closed, not scan a subset; stderr={stderr}"
    );
    assert_ne!(
        output.status.code(),
        Some(0),
        "a refused hosted-git listing must not exit 0"
    );
}

/// A page budget of zero can only ever produce a false clean.
#[test]
fn limit_hosted_git_pages_zero_fails_closed() {
    let server = gitlab_server(1);
    let output = scan_group(&server, "0");
    assert_ne!(
        output.status.code(),
        Some(0),
        "--limit-hosted-git-pages 0 must be refused; stderr={}",
        stderr_of(&output)
    );
}

/// A page that fails mid-listing must surface the failure instead of treating
/// the pages already collected as the whole group.
#[test]
fn hosted_git_partial_api_failure_is_surfaced_not_treated_as_a_complete_listing() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v4/groups/grp/projects")
            .query_param("page", "1");
        then.status(200)
            .header("content-type", "application/json")
            .body(page_body(1, FULL_PAGE));
    });
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v4/groups/grp/projects")
            .query_param("page", "2");
        then.status(500).body("upstream exploded");
    });

    let output = scan_group(&server, "10");
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("GitLab API returned"),
        "a failed listing page must be reported; stderr={stderr}"
    );
    assert_ne!(
        output.status.code(),
        Some(0),
        "a group whose listing failed halfway must not exit 0"
    );
}
