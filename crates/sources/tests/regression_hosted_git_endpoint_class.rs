//! Regression: hosted-Git endpoint *classification*, forge host-kind, API
//! base composition, and SSRF host refusal.
//!
//! This file is deliberately DISTINCT from `regression_hosted_git_endpoint.rs`
//! (iter2). Where that file exercises the GitHub clone-URL shape rules
//! (ssh/userinfo/query/metachar/port) and the GitLab `http`-scheme /
//! embedded-credential refusals, this file pins the *classification* contracts:
//!
//!   * which forge a URL binds to (GitHub clone origin = `github.com:443`,
//!     rejecting the OTHER two forges' hosts as cross-origin token-forwarding
//!     gadgets), asserted through the crate's `#[doc(hidden)]` testing facade;
//!   * the exact API base each forge composes its listing request under
//!     GitLab's idempotent `/api/v4` suffix and Bitbucket's `/2.0` base
//!     asserted by driving the real `create_source` factory against a loopback
//!     `httpmock` server and checking the exact request path;
//!   * that a private / loopback / metadata / integer-encoded / malformed host
//!     is classified private, asserted by REUSING the fleet-canonical
//!     `keyhog_verifier::ssrf::is_private_url` classifier (never a hand-rolled
//!     copy: Law: ONE PLACE) with exact `bool` expectations.
//!
//! Every assertion checks a concrete value: an exact `Ok(())`, an exact refusal
//! phrase naming the expected origin, an exact request path + call count, or an
//! exact `is_private_url` boolean.
#![cfg(all(feature = "github", feature = "gitlab", feature = "bitbucket"))]

use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_verifier::ssrf::is_private_url;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Assert a validator accepted its input by matching the exact `Ok(())`
/// variant. `SourceError` is not `PartialEq`, so a pattern match (not
/// `assert_eq!`) pins acceptance to a concrete value.
fn assert_accepted(result: Result<(), keyhog_core::SourceError>, label: &str) {
    match result {
        Ok(()) => {}
        Err(err) => panic!("{label} must be accepted, got refusal: {err}"),
    }
}

/// Build a hosted-git source from `params`, drive it, and return the single
/// source-error string it yields. Endpoint validation fails closed *before* any
/// socket opens, so a rejected endpoint deterministically produces exactly one
/// `Err` chunk and no network I/O.
fn hosted_single_error(source_type: &str, params: &str) -> String {
    let source = keyhog_sources::create_source(source_type, Some(params))
        .unwrap_or_else(|e| panic!("{source_type} source must construct from params: {e}"));
    let rows: Vec<_> = source.chunks().collect();
    assert_eq!(
        rows.len(),
        1,
        "a rejected {source_type} endpoint must yield exactly one visible source error, got {} rows",
        rows.len()
    );
    rows.into_iter()
        .next()
        .unwrap()
        .expect_err("rejected endpoint must be an Err chunk")
        .to_string()
}

// ---------------------------------------------------------------------------
// Canonical SSRF classifier reuse (keyhog_verifier::ssrf::is_private_url)
// ---------------------------------------------------------------------------

#[test]
fn public_forge_api_bases_classify_public() {
    // The three forges' public API bases are routable, public hosts: the
    // canonical classifier must NOT flag them, or every default hosted-Git scan
    // would be refused as SSRF.
    assert_eq!(
        is_private_url("https://api.github.com/orgs/acme/repos"),
        false,
        "GitHub public API base must classify public"
    );
    assert_eq!(
        is_private_url("https://gitlab.com/api/v4/groups/acme/projects"),
        false,
        "GitLab public API base must classify public"
    );
    assert_eq!(
        is_private_url("https://api.bitbucket.org/2.0/repositories/acme"),
        false,
        "Bitbucket public API base must classify public"
    );
}

#[test]
fn loopback_and_rfc1918_forge_hosts_classify_private() {
    // A self-hosted forge endpoint pointed at any of these is an SSRF /
    // token-exfiltration target and must be classified private.
    assert_eq!(
        is_private_url("http://127.0.0.1/api/v4"),
        true,
        "IPv4 loopback"
    );
    assert_eq!(is_private_url("https://10.0.0.5/2.0"), true, "RFC1918 10/8");
    assert_eq!(
        is_private_url("https://192.168.1.10/api/v4"),
        true,
        "RFC1918 192.168/16"
    );
    assert_eq!(
        is_private_url("http://169.254.169.254/latest/meta-data/"),
        true,
        "link-local cloud metadata"
    );
    assert_eq!(
        is_private_url("https://gitlab.internal/api/v4"),
        true,
        ".internal suffix (non-routable self-host name)"
    );
}

#[test]
fn integer_encoded_loopback_forge_host_classifies_private() {
    // A permissive resolver canonicalizes both of these to 127.0.0.1; the
    // classifier must block them before the forge token is forwarded.
    assert_eq!(
        is_private_url("http://2130706433/api/v4"),
        true,
        "decimal-encoded 127.0.0.1"
    );
    assert_eq!(
        is_private_url("http://0x7f000001/2.0"),
        true,
        "hex-encoded 127.0.0.1"
    );
}

#[test]
fn malformed_forge_endpoint_url_classifies_private_fail_closed() {
    // Law 10 fail-closed: an unparseable endpoint cannot be DNS-screened, so
    // the classifier blocks it (`true`) rather than letting it through.
    assert_eq!(
        is_private_url("http://"),
        true,
        "empty-host URL must fail closed to private"
    );
    assert_eq!(
        is_private_url("::::not a url"),
        true,
        "garbage URL must fail closed to private"
    );
    assert_eq!(
        is_private_url("ftp://gitlab.example.com/api"),
        true,
        "non-http(s) scheme must fail closed to private"
    );
}

// ---------------------------------------------------------------------------
// GitHub clone-origin host-kind classification (via the testing facade)
// ---------------------------------------------------------------------------

#[test]
fn github_clone_url_binds_to_github_com_origin() {
    assert_accepted(
        TestApi.validate_clone_url("https://github.com/acme/repo.git"),
        "a canonical github.com clone URL",
    );
}

#[test]
fn github_clone_url_case_insensitive_host_accepted() {
    // Host comparison is `eq_ignore_ascii_case`; a mixed-case host still binds
    // to the github.com origin.
    assert_accepted(
        TestApi.validate_clone_url("https://GitHub.COM/acme/repo.git"),
        "a mixed-case github.com clone URL",
    );
}

#[test]
fn github_clone_url_rejects_gitlab_host_naming_github_origin() {
    // GitHub is bound to github.com:443. A gitlab.com clone URL is a
    // cross-forge token-forwarding gadget and must be refused, naming the
    // expected origin.
    let err = TestApi
        .validate_clone_url("https://gitlab.com/acme/repo.git")
        .expect_err("a gitlab.com clone URL must be refused by the github origin binding");
    let msg = err.to_string();
    assert!(
        msg.contains("outside expected clone origin github.com:443"),
        "expected cross-forge refusal naming github.com:443, got: {msg}"
    );
    assert!(
        msg.contains("gitlab.com"),
        "refusal must name the rejected host, got: {msg}"
    );
}

#[test]
fn github_clone_url_rejects_bitbucket_host_naming_github_origin() {
    let err = TestApi
        .validate_clone_url("https://bitbucket.org/acme/repo.git")
        .expect_err("a bitbucket.org clone URL must be refused by the github origin binding");
    let msg = err.to_string();
    assert!(
        msg.contains("outside expected clone origin github.com:443"),
        "expected cross-forge refusal naming github.com:443, got: {msg}"
    );
    assert!(
        msg.contains("bitbucket.org"),
        "refusal must name the rejected host, got: {msg}"
    );
}

#[test]
fn github_clone_url_malformed_errors_exactly() {
    // A relative-without-base URL reaches `reqwest::Url::parse`, which fails;
    // the shape validator surfaces the exact "refusing invalid clone URL"
    // refusal (not a host-origin comparison).
    let err = TestApi
        .validate_clone_url("://missing-scheme")
        .expect_err("a malformed clone URL must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("refusing invalid clone URL"),
        "expected an invalid-URL refusal, got: {msg}"
    );
    assert!(
        !msg.contains("outside expected clone origin"),
        "a malformed URL must fail at parse, not at the origin comparison, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// GitLab API-base normalization (real factory, loopback mock, no external I/O)
// ---------------------------------------------------------------------------

#[test]
fn gitlab_endpoint_api_v4_suffix_is_not_double_appended() {
    // `normalize_gitlab_api_root` appends `/api/v4` ONLY when the operator did
    // not already supply it. An endpoint that already ends in `/api/v4` must be
    // used as-is: the listing is served only at `/api/v4/groups/acme/projects`
    // never a doubled `/api/v4/api/v4/...`.
    let server = httpmock::MockServer::start();
    let list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/api/v4/groups/acme/projects");
        then.status(200)
            .header("content-type", "application/json")
            .body("[]");
    });
    let doubled = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/api/v4/api/v4/groups/acme/projects");
        then.status(500);
    });

    let endpoint = server.url("/api/v4");
    let params = format!("acme\nglt_testtoken\n{endpoint}");
    let source = keyhog_sources::create_source("gitlab-group", Some(&params))
        .expect("gitlab-group source constructs against an /api/v4 loopback endpoint");
    let rows: Vec<_> = source.chunks().collect();

    assert_eq!(
        rows.len(),
        0,
        "an accepted /api/v4 endpoint with an empty project list yields zero chunks, got {} rows",
        rows.len()
    );
    assert_eq!(
        list.calls(),
        1,
        "the idempotently-normalized /api/v4 base must be hit exactly once"
    );
    assert_eq!(
        doubled.calls(),
        0,
        "the /api/v4 suffix must not be double-appended"
    );
}

#[test]
fn gitlab_malformed_endpoint_errors_exactly_before_network() {
    // A syntactically invalid endpoint fails `validated_api_endpoint`'s
    // `Url::parse` before any socket opens, surfacing exactly one visible error.
    let msg = hosted_single_error("gitlab-group", "acme\nglt_testtoken\nnot a valid url");
    assert!(
        msg.contains("invalid API endpoint"),
        "expected an invalid-endpoint refusal, got: {msg}"
    );
    assert!(
        !msg.contains("GitLab API request failed"),
        "a malformed endpoint must be refused before the network, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Bitbucket API-base composition + endpoint refusals (real factory)
// ---------------------------------------------------------------------------

#[test]
fn bitbucket_endpoint_composes_repositories_path_under_2_0_api_base() {
    // Bitbucket's default API base is `.../2.0`; the listing request is
    // composed as `<base>/repositories/<workspace>?pagelen=100`. Driving a
    // loopback `/2.0` endpoint proves that composition against a real request.
    let server = httpmock::MockServer::start();
    let list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/2.0/repositories/acme")
            .query_param("pagelen", "100");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"values":[],"next":null}"#);
    });

    let endpoint = server.url("/2.0");
    let params = format!("acme\nci-user\napp-pass\n{endpoint}");
    let source = keyhog_sources::create_source("bitbucket-workspace", Some(&params))
        .expect("bitbucket-workspace source constructs against a /2.0 loopback endpoint");
    let rows: Vec<_> = source.chunks().collect();

    assert_eq!(
        rows.len(),
        0,
        "an accepted /2.0 endpoint with an empty repo list yields zero chunks, got {} rows",
        rows.len()
    );
    assert_eq!(
        list.calls(),
        1,
        "the /2.0-based repositories listing path must be hit exactly once"
    );
}

#[test]
fn bitbucket_non_https_public_endpoint_refused_before_network() {
    // Plain http against a NON-loopback host is refused by
    // `validated_api_endpoint`: only https, or loopback http for local tests,
    // is allowed. This closes a downgrade that would send Basic auth in clear.
    let msg = hosted_single_error(
        "bitbucket-workspace",
        "acme\nci-user\napp-pass\nhttp://bitbucket.mirror.example",
    );
    assert!(
        msg.contains("refusing \"http\" API endpoint"),
        "expected an http-scheme refusal, got: {msg}"
    );
    assert!(
        msg.contains("use https, or loopback http only for local tests"),
        "refusal must explain the https/loopback policy, got: {msg}"
    );
}

#[test]
fn bitbucket_malformed_endpoint_errors_exactly_before_network() {
    let msg = hosted_single_error(
        "bitbucket-workspace",
        "acme\nci-user\napp-pass\nnot a valid url",
    );
    assert!(
        msg.contains("invalid API endpoint"),
        "expected an invalid-endpoint refusal, got: {msg}"
    );
    assert!(
        !msg.contains("Bitbucket API request failed"),
        "a malformed endpoint must be refused before the network, got: {msg}"
    );
}
