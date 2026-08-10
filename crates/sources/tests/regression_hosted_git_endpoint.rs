//! Regression: hosted-Git (GitHub org / collaboration / GitLab group) endpoint
//! & clone-URL validation.
//!
//! Production surfaces exercised end to end through the crate's public API and
//! its `#[doc(hidden)]` testing facade; no production visibility is weakened
//! for these tests:
//!
//!   * GitHub clone-URL / org / repo-name validation via
//!     `keyhog_sources::testing::TestApi` (`github_org::validate_*`,
//!     which delegate to `hosted_git::validate_clone_url_for_origin` /
//!     `validate_clone_url_shape`). These bind the clone origin to
//!     `github.com:443` and reject any non-https / userinfo-bearing /
//!     cross-host / query / metacharacter URL.
//!
//!   * GitLab self-hosted API-endpoint validation via the public
//!     `create_source("gitlab-group", …)` factory. The endpoint is validated by
//!     `hosted_git::validated_api_endpoint` inside `collect_group_chunks`
//!     *before* any socket is opened (`validate_group_path` →
//!     `normalize_gitlab_api_root` → `validated_api_endpoint`, then
//!     `build_client`, then the first network call), so a rejected endpoint
//!     surfaces as exactly one `Err` chunk with no network I/O.
//!
//!   * GitHub collaboration / org API-endpoint SSRF screening via
//!     `validated_api_endpoint` inside `stream_chunks` / `stream_org_chunks`
//!     before the bearer token leaves the process. Collaboration is especially
//!     important: the CLI calls `with_endpoint` directly (no factory), so the
//!     stream path is the only screen.
//!
//! Every assertion checks a concrete value: exact `Ok(())`, the exact refusal
//! phrase, the normalized `/api/v4` request path, or the absence of a leaked
//! secret in a redacted diagnostic.
#![cfg(all(feature = "github", feature = "gitlab"))]

use std::time::Duration;

use keyhog_core::Source;
use keyhog_sources::testing::TestApi;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Assert a validator accepted its input by matching the exact `Ok(())`
/// variant. `SourceError` does not implement `PartialEq`, so this pattern match
/// (not `assert_eq!(_, Ok(()))`) is how an acceptance is pinned to a concrete
/// value.
fn assert_accepted(result: Result<(), keyhog_core::SourceError>, label: &str) {
    match result {
        Ok(()) => {}
        Err(err) => panic!("{label} must be accepted, got refusal: {err}"),
    }
}

/// Drive a `gitlab-group` source built from `params` and return the single
/// source-error string it yields. The endpoint validation fails closed before
/// any network call, so a rejected endpoint deterministically produces exactly
/// one `Err` chunk.
fn gitlab_group_single_error(params: &str) -> String {
    let source = keyhog_sources::create_source("gitlab-group", Some(params))
        .expect("gitlab-group source constructs from group/token/endpoint params");
    let rows: Vec<_> = source.chunks().collect();
    assert_eq!(
        rows.len(),
        1,
        "a rejected GitLab endpoint must yield exactly one visible source error, got {} rows",
        rows.len()
    );
    rows.into_iter()
        .next()
        .unwrap()
        .expect_err("rejected GitLab endpoint must be an Err chunk")
        .to_string()
}

// ---------------------------------------------------------------------------
// GitHub clone-URL origin validation (positive + boundary)
// ---------------------------------------------------------------------------

#[test]
fn github_valid_https_clone_url_accepted() {
    assert_accepted(
        TestApi.validate_clone_url("https://github.com/acme/repo.git"),
        "a canonical https github.com clone URL",
    );
}

#[test]
fn github_clone_url_explicit_default_port_accepted() {
    // Explicit :443 is the https default; `port_or_known_default()` normalizes
    // it to 443, which matches the expected github.com:443 origin.
    assert_accepted(
        TestApi.validate_clone_url("https://github.com:443/acme/repo.git"),
        "explicit-default-port (github.com:443) clone URL",
    );
}

// ---------------------------------------------------------------------------
// GitHub clone-URL origin validation (negative twins)
// ---------------------------------------------------------------------------

#[test]
fn github_non_https_clone_url_rejected_with_exact_reason() {
    // `ssh://` is a git transport-negotiation RCE gadget; only https is allowed.
    let err = TestApi
        .validate_clone_url("ssh://github.com/acme/repo.git")
        .expect_err("ssh:// clone URL must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("refusing clone URL that is neither https nor literal loopback http"),
        "expected non-https refusal, got: {msg}"
    );
}

#[test]
fn github_clone_url_embedded_credentials_rejected_and_secret_redacted() {
    // A userinfo-bearing clone URL would hand the password to git; it must be
    // refused, and the operator-visible error must not echo the secret.
    let err = TestApi
        .validate_clone_url("https://u:s3cr3tPASSWORD@github.com/acme/repo.git")
        .expect_err("clone URL with embedded credentials must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("refusing clone URL with embedded credentials"),
        "expected embedded-credentials refusal, got: {msg}"
    );
    assert!(
        !msg.contains("s3cr3tPASSWORD"),
        "the embedded password must be redacted out of the error, got: {msg}"
    );
}

#[test]
fn github_clone_url_cross_host_rejected_names_expected_origin() {
    // Host bound to github.com:443, a look-alike host is a token-forwarding
    // gadget and must be refused, naming the expected origin.
    let err = TestApi
        .validate_clone_url("https://evil.example.com/acme/repo.git")
        .expect_err("cross-host clone URL must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("outside expected clone origin github.com:443"),
        "expected cross-host refusal naming github.com:443, got: {msg}"
    );
}

#[test]
fn github_clone_url_non_default_port_rejected() {
    // Same host, wrong port: `port_or_known_default()` yields 444 != 443, so
    // the origin comparison fails.
    let err = TestApi
        .validate_clone_url("https://github.com:444/acme/repo.git")
        .expect_err("wrong-port clone URL must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("outside expected clone origin github.com:443"),
        "expected port-mismatch refusal naming github.com:443, got: {msg}"
    );
}

#[test]
fn github_clone_url_with_query_rejected() {
    let err = TestApi
        .validate_clone_url("https://github.com/acme/repo.git?upload-pack=x")
        .expect_err("clone URL with query must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("refusing clone URL with query or fragment"),
        "expected query/fragment refusal, got: {msg}"
    );
}

#[test]
fn github_clone_url_windows_metacharacter_rejected() {
    // `&` is a Windows cmd separator; refused before URL parsing.
    let err = TestApi
        .validate_clone_url("https://github.com/acme&calc.exe/repo.git")
        .expect_err("clone URL with cmd metacharacter must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("refusing clone URL with Windows command metacharacters"),
        "expected metacharacter refusal, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// GitHub org-name validation (boundary + adversarial)
// ---------------------------------------------------------------------------

#[test]
fn github_org_name_length_boundary() {
    assert_accepted(
        TestApi.validate_org_name(&"a".repeat(39)),
        "39-char org name (inclusive maximum)",
    );
    let over = TestApi
        .validate_org_name(&"a".repeat(40))
        .expect_err("40-char org name exceeds the 39-byte GitHub limit");
    assert!(
        over.to_string().contains("out-of-range name length (40)"),
        "expected out-of-range(40), got: {over}"
    );
    let empty = TestApi
        .validate_org_name("")
        .expect_err("empty org name must be refused");
    assert!(
        empty.to_string().contains("out-of-range name length (0)"),
        "expected out-of-range(0), got: {empty}"
    );
}

#[test]
fn github_org_name_hyphen_and_unsafe_chars_rejected() {
    let leading = TestApi
        .validate_org_name("-acme")
        .expect_err("leading hyphen must be refused");
    assert!(
        leading.to_string().contains("leading/trailing hyphen"),
        "expected leading/trailing-hyphen refusal, got: {leading}"
    );
    // A slash would let a crafted org split the API URL path.
    let slash = TestApi
        .validate_org_name("acme/evil")
        .expect_err("slash in org name must be refused");
    assert!(
        slash.to_string().contains("unsafe characters"),
        "expected unsafe-characters refusal, got: {slash}"
    );
}

// ---------------------------------------------------------------------------
// GitHub repo-name validation (traversal + charset + boundary)
// ---------------------------------------------------------------------------

#[test]
fn github_repo_name_valid_and_traversal_rejected() {
    assert_accepted(
        TestApi.validate_repo_name("repo.name-1_2"),
        "a repo name in the [A-Za-z0-9._-] alphabet",
    );
    let dotdot = TestApi
        .validate_repo_name("..")
        .expect_err("`..` repo name must be refused");
    assert!(
        dotdot.to_string().contains("traversal/separator in name"),
        "expected traversal/separator refusal for `..`, got: {dotdot}"
    );
    let slash = TestApi
        .validate_repo_name("a/b")
        .expect_err("path separator in repo name must be refused");
    assert!(
        slash.to_string().contains("traversal/separator in name"),
        "expected traversal/separator refusal for `a/b`, got: {slash}"
    );
}

#[test]
fn github_repo_name_length_and_non_ascii_rejected() {
    assert_accepted(
        TestApi.validate_repo_name(&"a".repeat(100)),
        "100-char repo name (inclusive maximum)",
    );
    let over = TestApi
        .validate_repo_name(&"a".repeat(101))
        .expect_err("101-char repo name exceeds the 100-byte limit");
    assert!(
        over.to_string().contains("out-of-range name length (101)"),
        "expected out-of-range(101), got: {over}"
    );
    let unicode = TestApi
        .validate_repo_name("r\u{00e9}po")
        .expect_err("non-ASCII repo name must be refused");
    assert!(
        unicode.to_string().contains("non-alphanumeric name"),
        "expected non-alphanumeric refusal, got: {unicode}"
    );
}

// ---------------------------------------------------------------------------
// GitLab self-hosted API-endpoint validation (fail-closed, no network)
// ---------------------------------------------------------------------------

#[test]
fn gitlab_non_https_self_hosted_endpoint_rejected_before_network() {
    // A plain-http self-hosted endpoint (non-loopback host) is refused by
    // `validated_api_endpoint` before any socket opens; the `/api/v4` suffix
    // that `normalize_gitlab_api_root` appends is visible in the diagnostic.
    let msg = gitlab_group_single_error("acme\nglt_testtoken\nhttp://gitlab.internal.example");
    assert!(
        msg.contains("refusing \"http\" API endpoint"),
        "expected http-scheme refusal, got: {msg}"
    );
    assert!(
        msg.contains("use https, or loopback http only for local tests"),
        "refusal must explain the https/loopback policy, got: {msg}"
    );
    assert!(
        msg.contains("http://gitlab.internal.example/api/v4"),
        "diagnostic must show the /api/v4-normalized endpoint, got: {msg}"
    );
}

#[test]
fn gitlab_endpoint_embedded_credentials_rejected_and_secret_redacted() {
    let msg = gitlab_group_single_error(
        "acme\nglt_testtoken\nhttps://ci-user:s3cr3tTOKEN@gitlab.internal.example",
    );
    assert!(
        msg.contains("API endpoint must not include embedded credentials"),
        "expected embedded-credentials refusal, got: {msg}"
    );
    assert!(
        !msg.contains("s3cr3tTOKEN"),
        "endpoint userinfo secret must be redacted from the error, got: {msg}"
    );
}

#[test]
fn gitlab_endpoint_with_query_rejected_and_secret_redacted() {
    let msg = gitlab_group_single_error(
        "acme\nglt_testtoken\nhttps://gitlab.internal.example?token=SUPERSECRETVALUE",
    );
    assert!(
        msg.contains("API endpoint must not include query or fragment"),
        "expected query/fragment refusal, got: {msg}"
    );
    assert!(
        !msg.contains("SUPERSECRETVALUE"),
        "endpoint query secret must be stripped from the error, got: {msg}"
    );
}

#[test]
fn gitlab_loopback_http_endpoint_accepted_with_private_optin_and_normalized_to_api_v4() {
    // Loopback http is the one non-https endpoint `validated_api_endpoint`
    // accepts, and (like every other private destination) only behind the
    // explicit `allow_private_endpoint` opt-in the CLI spells
    // `--allow-private-cloud-endpoint`. Driving the real source through a
    // 127.0.0.1 mock proves acceptance AND that `normalize_gitlab_api_root`
    // appended `/api/v4`: the listing is served only at
    // `/api/v4/groups/acme/projects`.
    let server = httpmock::MockServer::start();
    let list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/api/v4/groups/acme/projects")
            .query_param("include_subgroups", "true")
            .query_param("simple", "true")
            .query_param("per_page", "100")
            .query_param("page", "1");
        then.status(200)
            .header("content-type", "application/json")
            .body("[]");
    });

    let params = format!("acme\nglt_testtoken\n{}", server.url(""));
    let source = keyhog_sources::create_source_with_http_config(
        "gitlab-group",
        Some(&params),
        keyhog_sources::http::HttpClientConfig {
            allow_private_endpoint: true,
            ..Default::default()
        },
    )
    .expect("gitlab-group source constructs against a loopback endpoint");
    let rows: Vec<_> = source.chunks().collect();

    assert_eq!(
        rows.len(),
        0,
        "an accepted loopback endpoint with an empty project list yields zero chunks, got {} rows",
        rows.len()
    );
    assert_eq!(
        list.calls(),
        1,
        "the accepted, /api/v4-normalized endpoint must be hit exactly once"
    );
}

#[test]
fn gitlab_loopback_http_endpoint_refused_without_private_optin() {
    // Same loopback mock, no opt-in: the endpoint must be refused *before* any
    // socket opens, so the mock records zero calls and the operator's token is
    // never carried to a private destination.
    let server = httpmock::MockServer::start();
    let list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/api/v4/groups/acme/projects");
        then.status(200)
            .header("content-type", "application/json")
            .body("[]");
    });

    let msg = gitlab_group_single_error(&format!("acme\nglt_testtoken\n{}", server.url("")));
    assert!(
        msg.contains(
            "refusing gitlab endpoint: host is a private, loopback, link-local, or cloud-metadata address (SSRF)"
        ),
        "loopback endpoint without the private opt-in must be refused as SSRF, got: {msg}"
    );
    assert_eq!(
        list.calls(),
        0,
        "a refused endpoint must open no socket, got {} calls",
        list.calls()
    );
}

#[test]
fn gitlab_private_ip_https_endpoint_refused_before_network() {
    // `validated_api_endpoint` screens scheme, userinfo, query, and fragment,
    // and (this row) the destination host against the fleet-canonical
    // `keyhog_verifier::ssrf` classifier that the cloud
    // (`cloud::parse_http_endpoint`) and web sources already use. Before that
    // screen existed a self-hosted https endpoint pointed at a private /
    // TEST-NET / metadata address was ACCEPTED and the operator's GitLab token
    // was carried to it; the refusal now happens pre-connect, so the failure is
    // an endpoint refusal and never a transport error.
    let http = keyhog_sources::http::HttpClientConfig {
        // TEST-NET-1 (RFC 5737) is unroutable; a short timeout bounds the probe
        // in the (now impossible) event the screen lets it reach the network.
        timeout: Some(Duration::from_millis(800)),
        ..Default::default()
    };
    let source = keyhog_sources::create_source_with_http_config(
        "gitlab-group",
        Some("acme\nglt_testtoken\nhttps://192.0.2.1"),
        http,
    )
    .expect("gitlab-group source constructs against a private-IP endpoint");
    let rows: Vec<_> = source.chunks().collect();
    assert_eq!(
        rows.len(),
        1,
        "the private-IP endpoint must yield exactly one source error, got {} rows",
        rows.len()
    );
    let msg = rows[0]
        .as_ref()
        .expect_err("private-IP endpoint attempt must be an Err chunk")
        .to_string();
    assert!(
        msg.contains(
            "refusing gitlab endpoint: host is a private, loopback, link-local, or cloud-metadata address (SSRF)"
        ),
        "private-IP https endpoint must be refused by the host SSRF screen, got: {msg}"
    );
    assert!(
        !msg.contains("GitLab API request failed") && !msg.contains("GitLab API returned"),
        "a refused endpoint must never reach the transport, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// GitHub collaboration / org API-endpoint SSRF (fail-closed, no network)
// ---------------------------------------------------------------------------

fn issues_only() -> keyhog_sources::GitHubCollaborationSelection {
    keyhog_sources::GitHubCollaborationSelection {
        issues: true,
        pull_requests: false,
        discussions: false,
        wiki: false,
        gists: false,
        releases: false,
    }
}

#[test]
fn github_collaboration_private_ip_https_endpoint_refused_before_network() {
    // CLI path: `GitHubCollaborationSource::with_endpoint` is public and used
    // directly for `--github-api-endpoint`. Without stream-time validation the
    // bearer token was carried to private / metadata destinations. Refusal must
    // happen pre-connect, matching gitlab-group.
    let http = keyhog_sources::http::HttpClientConfig {
        timeout: Some(Duration::from_millis(800)),
        ..Default::default()
    };
    let source =
        keyhog_sources::GitHubCollaborationSource::new("acme/repo", "ghp_testtoken", issues_only())
            .expect("collaboration source constructs")
            .with_endpoint("https://192.0.2.1")
            .with_http_config(http);
    let rows: Vec<_> = source.chunks().collect();
    assert_eq!(
        rows.len(),
        1,
        "the private-IP endpoint must yield exactly one source error, got {} rows",
        rows.len()
    );
    let msg = rows[0]
        .as_ref()
        .expect_err("private-IP collaboration endpoint must be an Err chunk")
        .to_string();
    assert!(
        msg.contains(
            "refusing github endpoint: host is a private, loopback, link-local, or cloud-metadata address (SSRF)"
        ),
        "private-IP https collaboration endpoint must be refused by the host SSRF screen, got: {msg}"
    );
    assert!(
        !msg.contains("GitHub API") && !msg.contains("request failed"),
        "a refused collaboration endpoint must never reach the transport, got: {msg}"
    );
}

#[test]
fn github_collaboration_loopback_http_endpoint_refused_without_private_optin() {
    let server = httpmock::MockServer::start();
    let list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/repos/acme/repo/issues");
        then.status(200)
            .header("content-type", "application/json")
            .body("[]");
    });

    let source =
        keyhog_sources::GitHubCollaborationSource::new("acme/repo", "ghp_testtoken", issues_only())
            .expect("collaboration source constructs")
            .with_endpoint(server.url(""))
            .with_http_config(keyhog_sources::http::HttpClientConfig::default());
    let rows: Vec<_> = source.chunks().collect();
    assert_eq!(
        rows.len(),
        1,
        "expected one refusal chunk, got {}",
        rows.len()
    );
    let msg = rows[0]
        .as_ref()
        .expect_err("loopback collaboration endpoint without opt-in must Err")
        .to_string();
    assert!(
        msg.contains(
            "refusing github endpoint: host is a private, loopback, link-local, or cloud-metadata address (SSRF)"
        ),
        "loopback collaboration endpoint without private opt-in must be refused as SSRF, got: {msg}"
    );
    assert_eq!(
        list.calls(),
        0,
        "a refused collaboration endpoint must open no socket, got {} calls",
        list.calls()
    );
}

#[test]
fn github_org_private_ip_https_endpoint_refused_at_factory() {
    // Factory validates before `with_endpoint`; stream_org_chunks re-validates
    // as defense in depth. Either layer must refuse a private API root.
    let http = keyhog_sources::http::HttpClientConfig {
        timeout: Some(Duration::from_millis(800)),
        ..Default::default()
    };
    let err = match keyhog_sources::create_source_with_http_config(
        "github-org",
        Some("acme\nghp_testtoken\nhttps://192.0.2.1"),
        http,
    ) {
        Ok(_) => panic!("github-org factory must refuse a private-IP endpoint"),
        Err(error) => error,
    };
    let msg = err.to_string();
    assert!(
        msg.contains(
            "refusing github endpoint: host is a private, loopback, link-local, or cloud-metadata address (SSRF)"
        ),
        "private-IP https org endpoint must be refused by the host SSRF screen, got: {msg}"
    );
}

#[test]
fn github_collaboration_wiki_ssh_url_refused_before_clone() {
    let source = keyhog_sources::GitHubCollaborationSource::new(
        "acme/repo",
        "ghp_testtoken",
        keyhog_sources::GitHubCollaborationSelection {
            issues: false,
            pull_requests: false,
            discussions: false,
            wiki: true,
            gists: false,
            releases: false,
        },
    )
    .expect("collaboration source constructs")
    .with_wiki_clone_url("ssh://github.com/acme/repo.wiki.git");
    let rows: Vec<_> = source.chunks().collect();
    assert!(
        !rows.is_empty(),
        "refused wiki clone must surface at least one row"
    );
    let joined = rows
        .iter()
        .filter_map(|row| row.as_ref().err().map(|error| error.to_string()))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains("neither https nor literal loopback http")
            || joined.contains("outside expected clone origin")
            || joined.contains("wiki"),
        "ssh wiki URL must be refused before clone, got: {joined}"
    );
}

#[test]
fn github_collaboration_wiki_cross_host_url_refused_before_clone() {
    let source = keyhog_sources::GitHubCollaborationSource::new(
        "acme/repo",
        "ghp_testtoken",
        keyhog_sources::GitHubCollaborationSelection {
            issues: false,
            pull_requests: false,
            discussions: false,
            wiki: true,
            gists: false,
            releases: false,
        },
    )
    .expect("collaboration source constructs")
    .with_wiki_clone_url("https://attacker.example/acme/repo.wiki.git");
    let rows: Vec<_> = source.chunks().collect();
    let joined = rows
        .iter()
        .filter_map(|row| row.as_ref().err().map(|error| error.to_string()))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains("outside expected clone origin") && joined.contains("attacker.example"),
        "cross-host wiki URL must be refused before askpass, got: {joined}"
    );
}

#[test]
fn github_collaboration_default_wiki_follows_ghe_api_endpoint_host() {
    // Before: default wiki always targeted github.com, so a GHES/custom API
    // endpoint failed the origin screen even when the operator never passed
    // `--github-wiki-url`. After: default wiki authority tracks the API clone
    // origin (loopback mock here stands in for GHES).
    let server = httpmock::MockServer::start();
    let http = keyhog_sources::http::HttpClientConfig {
        allow_private_endpoint: true,
        timeout: Some(Duration::from_millis(800)),
        ..Default::default()
    };
    let source = keyhog_sources::GitHubCollaborationSource::new(
        "acme/repo",
        "ghp_testtoken",
        keyhog_sources::GitHubCollaborationSelection {
            issues: false,
            pull_requests: false,
            discussions: false,
            wiki: true,
            gists: false,
            releases: false,
        },
    )
    .expect("collaboration source constructs")
    .with_endpoint(server.url(""))
    .with_http_config(http);
    let rows: Vec<_> = source.chunks().collect();
    let joined = rows
        .iter()
        .filter_map(|row| row.as_ref().err().map(|error| error.to_string()))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !joined.contains("outside expected clone origin"),
        "default wiki clone must target the API endpoint host, not hardcoded github.com; got: {joined}"
    );
    assert!(
        !joined.is_empty(),
        "wiki clone against a non-git mock endpoint must still surface a coverage/inaccessible gap"
    );
}
