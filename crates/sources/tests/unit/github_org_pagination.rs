//! Contract for the GitHub-org source's rate-limit backoff + pagination owners
//! (`rate_limit_backoff_secs`, `MAX_BACKOFF_SECS`, `REPOS_PER_PAGE`), reached via
//! the `SourceTestApi` facade. Migrated out of an inline `#[cfg(test)]` block in
//! `src/github_org.rs` to satisfy the sources folder contract
//! (`github_org_no_inline_tests`).
//!
//! Load-bearing: a hostile `Retry-After` must clamp to `MAX_BACKOFF_SECS` (60s)
//! so an untrusted header can never wedge the scan thread, an honest one below
//! the ceiling is respected, an absent one uses attempt-based backoff, and
//! `REPOS_PER_PAGE` (100, GitHub's documented max) is the single owner the
//! list-repos query and the last-page check both read.

use keyhog_sources::testing::{SourceTestApi, TestApi};

#[test]
fn hostile_retry_after_is_clamped_to_the_ceiling() {
    // A malicious/compromised endpoint sends a huge Retry-After to wedge the
    // scan thread. The backoff must never exceed MAX_BACKOFF_SECS (60s).
    assert_eq!(TestApi.github_max_backoff_secs(), 60);
    assert_eq!(
        TestApi.github_rate_limit_backoff_secs(Some(4_000_000_000), 0),
        60
    );
    assert_eq!(
        TestApi.github_rate_limit_backoff_secs(Some(u64::MAX), 3),
        60
    );
}

#[test]
fn honest_retry_after_is_respected_below_the_ceiling() {
    assert_eq!(TestApi.github_rate_limit_backoff_secs(Some(5), 0), 5);
    assert_eq!(TestApi.github_rate_limit_backoff_secs(Some(60), 0), 60);
}

#[test]
fn absent_retry_after_uses_attempt_based_backoff() {
    assert_eq!(TestApi.github_rate_limit_backoff_secs(None, 0), 1);
    assert_eq!(TestApi.github_rate_limit_backoff_secs(None, 2), 3);
}

#[test]
fn repos_per_page_is_github_max_and_drives_the_query() {
    // GitHub's documented maximum page size. The list-repos loop pages with
    // this value AND treats a page shorter than it as the last page, so this
    // is the single owner both uses must read.
    let repos_per_page = TestApi.github_repos_per_page();
    assert_eq!(repos_per_page, 100);
    let url = format!("https://api.github.com/orgs/acme/repos?per_page={repos_per_page}&page=1");
    assert_eq!(
        url,
        "https://api.github.com/orgs/acme/repos?per_page=100&page=1"
    );
}
