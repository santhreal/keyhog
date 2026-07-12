//! Contract for the `max_commits_limit` shared owner that both `GitSource` and
//! `GitHistorySource` route their `with_max_commits` builder through (reached via
//! the `SourceTestApi` facade). Migrated out of inline `#[cfg(test)]` blocks in
//! `src/git/source.rs` and `src/git/history.rs` to satisfy the sources folder
//! contract (`git_source_no_inline_tests` + `git_history_no_inline_tests`).
//!
//! Load-bearing: both builders must store the requested cap identically as
//! `Some(n)` via the SINGLE owner (no divergent per-builder copy), and zero is a
//! valid explicit "scan no commits" cap (`git log --max-count 0`), never clamped
//! to `None` (unlimited).

use keyhog_sources::testing::{SourceTestApi, TestApi};

#[test]
fn git_source_routes_max_commits_through_the_shared_owner() {
    assert_eq!(TestApi.git_max_commits_limit(7), Some(7));
    // The GitSource builder stores exactly the shared owner's output.
    assert_eq!(TestApi.git_source_configured_max_commits(5), Some(5));
    assert_eq!(
        TestApi.git_source_configured_max_commits(5),
        TestApi.git_max_commits_limit(5),
    );
}

#[test]
fn git_history_source_delegates_max_commits_to_the_shared_owner() {
    // GitHistorySource must not keep its own copy of the conversion; it routes
    // through the same owner in source.rs so the two builders stay in lockstep.
    assert_eq!(
        TestApi.git_history_source_configured_max_commits(4),
        Some(4)
    );
    assert_eq!(
        TestApi.git_history_source_configured_max_commits(4),
        TestApi.git_max_commits_limit(4),
    );
}

#[test]
fn zero_max_commits_is_an_explicit_cap_not_clamped_to_none() {
    assert_eq!(TestApi.git_max_commits_limit(0), Some(0));
    assert_eq!(TestApi.git_source_configured_max_commits(0), Some(0));
    assert_eq!(
        TestApi.git_history_source_configured_max_commits(0),
        Some(0)
    );
}
