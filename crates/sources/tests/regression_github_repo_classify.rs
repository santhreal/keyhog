//! Regression: GitHub org repo/blob *classification*, the pure, no-network
//! contracts that decide (a) how a cloned repository blob's on-disk path is
//! rewritten into an operator-visible `github-org` finding path
//! (`<org>/<repo>/<relative>`), (b) whether the `api.github.com` /
//! GitHub-Enterprise-Server endpoint a scan would talk to is a public routable
//! host or a private/SSRF target, and (c) the exact refusal shapes for the
//! clone-URL / org-name / repo-name / truncation surfaces.
//!
//! This file is deliberately DISTINCT from the two `regression_hosted_git_*`
//! files: they exercise clone-URL *shape* rules (ssh/userinfo/query/metachar/
//! port) and the GitLab/Bitbucket API-base normalization against loopback
//! `httpmock` servers. Here the subject is GitHub's blob→finding-path
//! classification (`github_org_rewrite_chunk_path`, driven against a real temp
//! clone tree so `std::fs::canonicalize` runs for real), the concrete
//! `api.github.com` endpoint the pager composes, and the GitHub-flavored SSRF
//! host set (none of which those files assert).
//!
//! HOST-INDEPENDENCE: every assertion here is pure classification (path string,
//! `is_private_url` bool, refusal phrase, error message). Nothing depends on an
//! accelerator, a network socket, or a detector firing, so the results are
//! identical on the scalar/CPU-fallback path and on an accelerated host.
//!
//! Every assertion checks a concrete value: an exact rewritten path string, an
//! exact `source_type`, an exact `is_private_url` boolean, an exact refusal
//! phrase, or an exact truncation-message substring with the real page/repo
//! counts.
#![cfg(feature = "github")]

use keyhog_core::{Chunk, ChunkMetadata, SourceError};
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_verifier::ssrf::is_private_url;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Assert a validator accepted its input by matching the exact `Ok(())`
/// variant. `SourceError` is not `PartialEq`, so a pattern match (not
/// `assert_eq!`) pins acceptance to a concrete value.
fn assert_accepted(result: Result<(), SourceError>, label: &str) {
    match result {
        Ok(()) => {}
        Err(err) => panic!("{label} must be accepted, got refusal: {err}"),
    }
}

/// Build a scannable chunk whose `path` is `path` and whose git provenance
/// (commit/author/date) is populated, so a rewrite test can prove that
/// classification both rewrites the path AND strips the clone's per-commit
/// metadata (a shallow clone has no meaningful history to attribute).
fn chunk_with_path(path: Option<&str>) -> Chunk {
    Chunk {
        data: "AKIAIOSFODNN7EXAMPLE".into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: path.map(Into::into),
            commit: Some("deadbeefcafebabe".into()),
            author: Some("cloned-history-author".into()),
            date: Some("2026-07-01T00:00:00Z".into()),
            ..Default::default()
        },
    }
}

// ---------------------------------------------------------------------------
// Blob → finding-path classification (github_org_rewrite_chunk_path)
// ---------------------------------------------------------------------------

#[test]
fn github_blob_path_classifies_to_org_repo_relative_and_strips_history() {
    // A blob discovered at `<clone_root>/src/config.rs` in the shallow clone of
    // `acme/myrepo` must be classified to the operator-visible finding path
    // `acme/myrepo/src/config.rs`, tagged `github-org`, with the clone's
    // per-commit provenance cleared (a shallow clone attributes nothing).
    let dir = tempfile::TempDir::new().expect("temp clone root");
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).expect("mk src dir");
    std::fs::write(root.join("src/config.rs"), b"secret").expect("write blob");

    let out = TestApi
        .github_org_rewrite_chunk_path(
            chunk_with_path(Some("src/config.rs")),
            "acme",
            "myrepo",
            root,
        )
        .expect("a blob inside the clone root must classify");

    assert_eq!(
        out.metadata.path.as_deref(),
        Some("acme/myrepo/src/config.rs"),
        "blob path must classify to <org>/<repo>/<relative>"
    );
    assert_eq!(
        out.metadata.source_type.as_ref(),
        "github-org",
        "the rewritten chunk must be tagged as the github-org source"
    );
    assert_eq!(
        out.metadata.commit, None,
        "shallow-clone commit provenance must be stripped"
    );
    assert_eq!(
        out.metadata.author, None,
        "shallow-clone author provenance must be stripped"
    );
    assert_eq!(
        out.metadata.date, None,
        "shallow-clone date provenance must be stripped"
    );
}

#[test]
fn github_blob_path_classifies_nested_subdirectories_exactly() {
    // A deeply nested blob keeps every interior path segment under the
    // `<org>/<repo>/` prefix (no segment collapsing, no separator rewriting).
    let dir = tempfile::TempDir::new().expect("temp clone root");
    let root = dir.path();
    std::fs::create_dir_all(root.join("a/b/c")).expect("mk nested dirs");
    std::fs::write(root.join("a/b/c/creds.env"), b"k=v").expect("write nested blob");

    let out = TestApi
        .github_org_rewrite_chunk_path(
            chunk_with_path(Some("a/b/c/creds.env")),
            "octo-org",
            "deep-repo",
            root,
        )
        .expect("a nested blob inside the clone root must classify");

    assert_eq!(
        out.metadata.path.as_deref(),
        Some("octo-org/deep-repo/a/b/c/creds.env"),
        "nested blob path must be classified verbatim under <org>/<repo>/"
    );
}

#[test]
fn github_chunk_without_path_is_refused_exactly() {
    // A chunk that carries no file path cannot be classified into a finding
    // path; the source must fail loudly rather than emit a path-less github-org
    // finding.
    let dir = tempfile::TempDir::new().expect("temp clone root");
    let err = TestApi
        .github_org_rewrite_chunk_path(chunk_with_path(None), "acme", "myrepo", dir.path())
        .expect_err("a path-less chunk must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("produced a chunk without a file path"),
        "expected a no-path refusal, got: {msg}"
    );
    assert!(
        msg.contains("myrepo"),
        "refusal must name the repo it came from, got: {msg}"
    );
}

#[test]
fn github_blob_outside_clone_root_is_refused_exactly() {
    // ADVERSARIAL: a compromised clone that hands back an absolute path pointing
    // OUTSIDE the temp clone root (a path-traversal / finding-path spoofing
    // gadget) must be refused after canonicalization, not silently classified as
    // if it belonged to the repo.
    let clone_dir = tempfile::TempDir::new().expect("temp clone root");
    let outside_dir = tempfile::TempDir::new().expect("unrelated dir outside the clone");
    let escape = outside_dir.path().join("etc_shadow_lookalike");
    std::fs::write(&escape, b"root:x:0:0").expect("write outside blob");
    let escape_abs = escape.to_str().expect("utf-8 temp path");

    let err = TestApi
        .github_org_rewrite_chunk_path(
            chunk_with_path(Some(escape_abs)),
            "acme",
            "myrepo",
            clone_dir.path(),
        )
        .expect_err("a blob outside the clone root must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("is outside clone root"),
        "expected an outside-clone-root refusal, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// api.github.com endpoint + GitHub-Enterprise-Server SSRF classification
// (canonical keyhog_verifier::ssrf::is_private_url, never a hand-rolled copy)
// ---------------------------------------------------------------------------

#[test]
fn github_public_api_endpoint_classifies_public() {
    // The exact endpoint the pager composes (`per_page=100`, GitHub's max) is a
    // routable public host: the canonical classifier must NOT flag it, or every
    // default github-org scan would be refused as SSRF before the first request.
    assert_eq!(
        is_private_url("https://api.github.com/orgs/acme/repos?per_page=100&page=1"),
        false,
        "the composed api.github.com listing endpoint must classify public"
    );
}

#[test]
fn github_public_web_and_clone_hosts_classify_public() {
    // github.com and its public content subdomains are routable; a scan of a
    // public GitHub org must be able to reach them.
    assert_eq!(
        is_private_url("https://github.com/acme/repo.git"),
        false,
        "github.com clone host must classify public"
    );
    assert_eq!(
        is_private_url("https://raw.githubusercontent.com/acme/repo/main/README.md"),
        false,
        "raw.githubusercontent.com content host must classify public"
    );
    assert_eq!(
        is_private_url("https://codeload.github.com/acme/repo/zip/refs/heads/main"),
        false,
        "codeload.github.com download host must classify public"
    );
}

#[test]
fn github_enterprise_nonroutable_hosts_classify_private() {
    // A self-hosted GitHub Enterprise Server endpoint pointed at a non-routable
    // name is an SSRF / token-exfiltration target and must classify private so
    // the operator's GitHub token is never forwarded to it.
    assert_eq!(
        is_private_url("https://github.internal/api/v3/orgs/acme/repos"),
        true,
        ".internal GHES host must classify private"
    );
    assert_eq!(
        is_private_url("https://ghe.localhost/api/v3/orgs/acme/repos"),
        true,
        ".localhost GHES host must classify private"
    );
    assert_eq!(
        is_private_url("https://ghe-host/api/v3/orgs/acme/repos"),
        true,
        "a dotless single-label GHES host must classify private"
    );
}

#[test]
fn github_endpoint_metadata_and_integer_hosts_classify_private() {
    // A GHES endpoint pointed at the cloud metadata service or an integer-encoded
    // loopback (both of which a permissive resolver canonicalizes to a blocked
    // address) must classify private.
    assert_eq!(
        is_private_url("http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        true,
        "link-local cloud metadata host must classify private"
    );
    assert_eq!(
        is_private_url("http://2130706433/api/v3/orgs/acme/repos"),
        true,
        "decimal-encoded 127.0.0.1 must classify private"
    );
    assert_eq!(
        is_private_url("http://0x7f000001/api/v3/orgs/acme/repos"),
        true,
        "hex-encoded 127.0.0.1 must classify private"
    );
    assert_eq!(
        is_private_url("https://10.20.30.40/api/v3/orgs/acme/repos"),
        true,
        "RFC1918 10/8 GHES host must classify private"
    );
}

#[test]
fn github_malformed_or_nonhttp_endpoint_fails_closed_private() {
    // Law 10 fail-closed: an endpoint that cannot be DNS-screened (unparseable,
    // hostless, or a non-http(s) scheme) must classify private rather than be
    // let through.
    assert_eq!(
        is_private_url("http://"),
        true,
        "empty-host endpoint must fail closed to private"
    );
    assert_eq!(
        is_private_url("::::not a url"),
        true,
        "garbage endpoint must fail closed to private"
    );
    assert_eq!(
        is_private_url("ssh://git@github.enterprise.example/acme/repo.git"),
        true,
        "a non-http(s) scheme must fail closed to private"
    );
}

// ---------------------------------------------------------------------------
// Clone-URL origin binding (GitHub-subdomain adversarial + boundary)
// ---------------------------------------------------------------------------

#[test]
fn github_canonical_clone_url_accepted() {
    assert_accepted(
        TestApi.validate_clone_url("https://github.com/acme/repo.git"),
        "a canonical github.com clone URL",
    );
}

#[test]
fn github_subdomain_clone_url_refused_naming_origin() {
    // ADVERSARIAL: `codeload.github.com` is a REAL GitHub download host, but the
    // clone origin is bound to `github.com:443` exactly. A clone URL on a github
    // subdomain is a cross-origin token-forwarding gadget and must be refused,
    // naming the expected origin.
    let err = TestApi
        .validate_clone_url("https://codeload.github.com/acme/repo.git")
        .expect_err("a github-subdomain clone URL must be refused by the origin binding");
    let msg = err.to_string();
    assert!(
        msg.contains("outside expected clone origin github.com:443"),
        "expected cross-origin refusal naming github.com:443, got: {msg}"
    );
}

#[test]
fn github_clone_url_with_whitespace_refused() {
    // A whitespace byte in a clone URL is an argument-splitting / control gadget
    // for the downstream git invocation and is refused before URL parsing.
    let err = TestApi
        .validate_clone_url("https://github.com/acme/re po.git")
        .expect_err("a clone URL containing whitespace must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("whitespace/control characters"),
        "expected a whitespace/control refusal, got: {msg}"
    );
}

#[test]
fn github_clone_url_over_length_cap_refused() {
    // BOUNDARY: a clone URL longer than the 2048-char cap is refused with the
    // exact over-length count, closing an unbounded-input vector.
    let long_url = format!("https://github.com/acme/{}.git", "a".repeat(2100));
    assert!(long_url.len() > 2048, "fixture must exceed the 2048 cap");
    let err = TestApi
        .validate_clone_url(&long_url)
        .expect_err("an over-length clone URL must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("longer than 2048 chars"),
        "expected an over-length refusal, got: {msg}"
    );
    assert!(
        msg.contains(&format!("({})", long_url.len())),
        "refusal must report the exact over-length count {}, got: {msg}",
        long_url.len()
    );
}

// ---------------------------------------------------------------------------
// Org-name / repo-name classification (positive + adversarial twins)
// ---------------------------------------------------------------------------

#[test]
fn github_org_name_interior_hyphen_accepted_underscore_refused() {
    // GitHub org/user names allow interior hyphens but NOT underscores; an
    // underscore is rejected as an unsafe character that could otherwise reshape
    // the api.github.com URL.
    assert_accepted(
        TestApi.validate_org_name("ac-me"),
        "an interior-hyphen org name",
    );
    let err = TestApi
        .validate_org_name("ac_me")
        .expect_err("an underscore org name must be refused");
    assert!(
        err.to_string().contains("unsafe characters"),
        "expected an unsafe-characters refusal, got: {err}"
    );
}

#[test]
fn github_repo_name_dotted_alphabet_accepted_single_dot_refused() {
    // A repo name in the [A-Za-z0-9._-] alphabet is accepted; a bare `.` is a
    // clone-root self-reference and is refused as a traversal/separator name
    // (the negative twin of the accepted dotted name).
    assert_accepted(
        TestApi.validate_repo_name("v1.2.3_final-build"),
        "a dotted/underscore/hyphen repo name",
    );
    let err = TestApi
        .validate_repo_name(".")
        .expect_err("a bare `.` repo name must be refused");
    assert!(
        err.to_string().contains("traversal/separator in name"),
        "expected a traversal/separator refusal for `.`, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Listing-truncation classification (exact message + real counts)
// ---------------------------------------------------------------------------

#[test]
fn github_listing_truncated_error_names_org_pages_and_repo_count() {
    // When an org's repo listing exceeds the page budget, the scan must refuse
    // to report a PARTIAL collection clean, with a message naming the org, the
    // page cap, and the repos seen so far (all exact).
    let err = TestApi.github_org_listing_truncated_error("acme", 500, 5);
    let msg = err.to_string();
    assert!(
        msg.contains("GitHub organization repository listing for acme exceeded 5 pages"),
        "expected the org/page-cap phrasing, got: {msg}"
    );
    assert!(
        msg.contains("(500 repositories)"),
        "expected the exact seen-repo count, got: {msg}"
    );
    assert!(
        msg.contains("refusing to scan a partial organization repository collection"),
        "expected the partial-collection refusal rationale, got: {msg}"
    );
}
