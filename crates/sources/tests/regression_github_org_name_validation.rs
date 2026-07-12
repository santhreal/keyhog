//! Regression: GitHub org/repo *name* validation — the pure, no-network guard
//! that decides whether an org or repo name is safe to interpolate into the
//! `api.github.com` request path (org) or to `join()` onto the temp clone root
//! (repo). A compromised API response or a hostile `--org` argument that slips a
//! slash, control byte, or over-length name through this guard is a URL-path
//! injection (org) or a path-traversal (repo) gadget, so every accept/refuse
//! decision and every refusal *message* is a load-bearing contract.
//!
//! This file is deliberately DISTINCT from `regression_github_repo_classify.rs`
//! (blob→finding-path rewrite, `is_private_url` SSRF classification, clone-URL
//! origin binding, listing truncation) and from the GitLab/Bitbucket name
//! files: GitHub's org rule is its OWN alphabet — ASCII-alphanumeric with
//! interior hyphens, **39-byte** cap, no leading/trailing hyphen — which none of
//! those files exercise as a length-boundary matrix. Here the subject is the
//! exact 39/40-byte boundary, the empty-name floor, the leading/trailing-hyphen
//! twins, the unsafe-character refusals, the length-checks-BEFORE-hyphen
//! precedence, and the GitHub repo-name 100/101-byte boundary + traversal
//! twins — each asserted against its concrete refusal message.
//!
//! HOST-INDEPENDENCE: every assertion is pure string classification (accept vs a
//! concrete refusal substring with an exact byte count). Nothing depends on an
//! accelerator, a socket, or a detector firing, so the results are identical on
//! the scalar/CPU-fallback path and on any accelerated host.
#![cfg(feature = "github")]

use keyhog_core::SourceError;
use keyhog_sources::testing::{SourceTestApi, TestApi};

/// Assert a validator accepted its input by matching the exact `Ok(())`
/// variant. `SourceError` is not `PartialEq`, so a pattern match (not
/// `assert_eq!`) pins acceptance to a concrete value.
fn assert_accepted(result: Result<(), SourceError>, label: &str) {
    match result {
        Ok(()) => {}
        Err(err) => panic!("{label} must be accepted, got refusal: {err}"),
    }
}

// ---------------------------------------------------------------------------
// validate_org_name — positive + length boundary
// ---------------------------------------------------------------------------

#[test]
fn github_org_name_typical_accepted() {
    // A plain lowercase alphanumeric org is the common case and must be accepted
    // so a default `--org octocat` scan reaches `api.github.com`.
    assert_accepted(TestApi.validate_org_name("octocat"), "a typical org name");
}

#[test]
fn github_org_name_mixed_case_and_digits_accepted() {
    // GitHub org/user names are ASCII-alphanumeric; upper, lower, and digits all
    // pass the `is_ascii_alphanumeric()` predicate.
    assert_accepted(
        TestApi.validate_org_name("GitHub42Inc"),
        "a mixed-case alphanumeric org name",
    );
}

#[test]
fn github_org_name_39_byte_boundary_accepted() {
    // BOUNDARY: the cap is `len() > 39` => refuse, so exactly 39 bytes is the
    // last accepted length. A regression that flips this to `>= 39` would refuse
    // a legal 39-char org.
    let name = "a".repeat(39);
    assert_eq!(name.len(), 39, "fixture must be exactly the 39-byte cap");
    assert_accepted(
        TestApi.validate_org_name(&name),
        "a 39-byte org name (the inclusive length cap)",
    );
}

#[test]
fn github_org_name_40_byte_rejected_out_of_range() {
    // BOUNDARY twin: one byte past the cap is refused, and the message reports
    // the exact offending length `(40)` — not a generic "too long".
    let name = "a".repeat(40);
    assert_eq!(name.len(), 40, "fixture must be exactly one past the cap");
    let err = TestApi
        .validate_org_name(&name)
        .expect_err("a 40-byte org name must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("github: refusing org with out-of-range name length (40)"),
        "expected the exact out-of-range(40) refusal, got: {msg}"
    );
}

#[test]
fn github_org_name_empty_rejected_out_of_range_zero() {
    // The floor: an empty org name is refused via the same out-of-range guard,
    // reporting length `(0)` — a hostless `/orgs//repos` request never composes.
    let err = TestApi
        .validate_org_name("")
        .expect_err("an empty org name must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("github: refusing org with out-of-range name length (0)"),
        "expected the exact out-of-range(0) refusal, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// validate_org_name — hyphen placement twins
// ---------------------------------------------------------------------------

#[test]
fn github_org_name_leading_hyphen_rejected() {
    // A leading hyphen is not a legal GitHub org and is also a CLI
    // option-injection shape; it is refused with the dedicated hyphen message.
    let err = TestApi
        .validate_org_name("-acme")
        .expect_err("a leading-hyphen org name must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("github: refusing org with leading/trailing hyphen"),
        "expected the leading/trailing-hyphen refusal, got: {msg}"
    );
}

#[test]
fn github_org_name_trailing_hyphen_rejected() {
    // The mirror twin: a trailing hyphen is refused by the same guard.
    let err = TestApi
        .validate_org_name("acme-")
        .expect_err("a trailing-hyphen org name must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("github: refusing org with leading/trailing hyphen"),
        "expected the leading/trailing-hyphen refusal, got: {msg}"
    );
}

#[test]
fn github_org_name_interior_hyphen_accepted() {
    // Positive control for the hyphen twins: an interior hyphen is legal and must
    // NOT trip the leading/trailing guard.
    assert_accepted(
        TestApi.validate_org_name("my-cool-org"),
        "an interior-hyphen org name",
    );
}

// ---------------------------------------------------------------------------
// validate_org_name — unsafe-character refusals (URL-path injection guards)
// ---------------------------------------------------------------------------

#[test]
fn github_org_name_slash_rejected_unsafe() {
    // ADVERSARIAL: a slash would inject an extra path segment into
    // `/orgs/<org>/repos`. It is neither alphanumeric nor a hyphen, so it is
    // refused as an unsafe character.
    let err = TestApi
        .validate_org_name("acme/repos")
        .expect_err("a slash in an org name must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("github: refusing org with unsafe characters"),
        "expected the unsafe-characters refusal, got: {msg}"
    );
}

#[test]
fn github_org_name_underscore_rejected_unsafe() {
    // GitHub org/user names disallow underscores; the guard refuses it as an
    // unsafe character (distinct from the hyphen twins).
    let err = TestApi
        .validate_org_name("ac_me")
        .expect_err("an underscore org name must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("github: refusing org with unsafe characters"),
        "expected the unsafe-characters refusal, got: {msg}"
    );
}

#[test]
fn github_org_name_query_metachar_rejected_unsafe() {
    // ADVERSARIAL: a `?` would turn the org into a query-string injection against
    // `?per_page=100&page=1`. It is refused as an unsafe character.
    let err = TestApi
        .validate_org_name("acme?x=1")
        .expect_err("a query metacharacter in an org name must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("github: refusing org with unsafe characters"),
        "expected the unsafe-characters refusal, got: {msg}"
    );
}

#[test]
fn github_org_name_length_check_precedes_hyphen_check() {
    // PRECEDENCE (adversarial): a 40-byte name that ALSO begins with a hyphen
    // must be caught by the length guard FIRST — the reported message is the
    // out-of-range(40) length, not the hyphen message. This pins the check order
    // so a refactor that reorders the guards is caught.
    let name = format!("-{}", "a".repeat(39)); // leading hyphen + 39 = 40 bytes
    assert_eq!(name.len(), 40, "fixture must be exactly one past the cap");
    let err = TestApi
        .validate_org_name(&name)
        .expect_err("an over-length hyphen-led org name must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("out-of-range name length (40)"),
        "length guard must win over the hyphen guard, got: {msg}"
    );
    assert!(
        !msg.contains("leading/trailing hyphen"),
        "the hyphen message must NOT appear when length wins, got: {msg}"
    );
}

#[test]
fn github_accepted_org_composes_documented_listing_endpoint() {
    // The org guard exists precisely so an accepted name interpolates cleanly
    // into the documented listing endpoint. `octocat` is accepted, and the
    // endpoint the pager composes for page 1 (per_page=100, GitHub's max) is
    // exactly this string with no injected path/query segment.
    assert_accepted(
        TestApi.validate_org_name("octocat"),
        "the endpoint-fixture org name",
    );
    let endpoint = format!(
        "https://api.github.com/orgs/{}/repos?per_page=100&page=1",
        "octocat"
    );
    assert_eq!(
        endpoint, "https://api.github.com/orgs/octocat/repos?per_page=100&page=1",
        "an accepted org must compose the exact documented listing endpoint"
    );
}

// ---------------------------------------------------------------------------
// validate_repo_name — GitHub's 100-byte cap + traversal twins
// (distinct alphabet/cap from the org rule above)
// ---------------------------------------------------------------------------

#[test]
fn github_repo_name_101_byte_rejected_out_of_range() {
    // BOUNDARY: repo names cap at `len() > 100` => refuse, with the exact
    // offending length `(101)`. Note this cap (100) differs from the org cap
    // (39), so this is a separate contract.
    let name = "a".repeat(101);
    assert_eq!(name.len(), 101, "fixture must be one past the 100-byte cap");
    let err = TestApi
        .validate_repo_name(&name)
        .expect_err("a 101-byte repo name must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("github: refusing repo with out-of-range name length (101)"),
        "expected the exact out-of-range(101) refusal, got: {msg}"
    );
}

#[test]
fn github_repo_name_100_byte_boundary_accepted() {
    // BOUNDARY twin: exactly 100 bytes of the repo alphabet is the last accepted
    // length.
    let name = "a".repeat(100);
    assert_eq!(name.len(), 100, "fixture must be exactly the 100-byte cap");
    assert_accepted(
        TestApi.validate_repo_name(&name),
        "a 100-byte repo name (the inclusive cap)",
    );
}

#[test]
fn github_repo_name_dotdot_rejected_traversal() {
    // ADVERSARIAL: `..` is a parent-directory escape for `clone_root.join(name)`
    // and is refused as a traversal/separator name (not a length or alphabet
    // refusal).
    let err = TestApi
        .validate_repo_name("..")
        .expect_err("a `..` repo name must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("github: refusing repo with traversal/separator in name"),
        "expected the traversal/separator refusal for `..`, got: {msg}"
    );
}

#[test]
fn github_repo_name_backslash_rejected_traversal() {
    // ADVERSARIAL: a Windows-style separator inside the name is a traversal
    // gadget and is refused as a traversal/separator name.
    let err = TestApi
        .validate_repo_name("a\\b")
        .expect_err("a backslash repo name must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("github: refusing repo with traversal/separator in name"),
        "expected the traversal/separator refusal for a backslash, got: {msg}"
    );
}

#[test]
fn github_repo_name_space_rejected_non_alphanumeric() {
    // A space is outside the repo alphabet ([A-Za-z0-9._-]) and is refused with
    // the non-alphanumeric message — distinct from the traversal refusal above.
    let err = TestApi
        .validate_repo_name("my repo")
        .expect_err("a space in a repo name must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("github: refusing repo with non-alphanumeric name"),
        "expected the non-alphanumeric refusal, got: {msg}"
    );
}

#[test]
fn github_repo_name_dotted_alphabet_accepted() {
    // Positive control: the `.`/`_`/`-` characters ARE in the repo alphabet, so a
    // conventional versioned repo name is accepted.
    assert_accepted(
        TestApi.validate_repo_name("my.repo_name-2026"),
        "a dotted/underscore/hyphen repo name",
    );
}
