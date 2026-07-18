use keyhog_core::{Chunk, SourceError};

use super::{
    merge_hosted_repo_results, validate_clone_url_for_origin, ExpectedCloneOrigin, HostedRepo,
};

fn repo(name: &str) -> HostedRepo {
    HostedRepo {
        clone_dir_name: name.to_string(),
        display_path: name.to_string(),
        clone_url: format!("https://example.com/{name}.git"),
    }
}

#[test]
fn repo_failure_keeps_sibling_chunks_and_counts_unreadable() {
    let chunk = Chunk::from("found-secret");
    let rows = merge_hosted_repo_results(
        "github",
        &[repo("good"), repo("bad")],
        vec![
            Ok(vec![chunk]),
            Err(SourceError::Git("clone failed".to_string())),
        ],
    );

    assert_eq!(rows.len(), 2, "one good chunk and one repo error row");
    let good = rows[0]
        .as_ref()
        .expect("successful sibling chunk must be preserved");
    assert_eq!(good.data.as_ref(), "found-secret");
    let error = rows[1]
        .as_ref()
        .expect_err("failed sibling must become a visible row")
        .to_string();
    assert!(
        error.contains("bad")
            && error.contains("clone failed")
            && error.contains("repository was not scanned"),
        "repo error must identify the unscanned sibling, got {error}"
    );
    // The error ROW is the deterministic proof that the failed repo was
    // accounted unreadable: `merge_hosted_repo_results` bumps the global
    // unreadable counter in the same `repo_unreadable_error` call that builds
    // this row. Reading that process-global counter here would race the other
    // backends' `--lib` tests, so the counter-delta contract is asserted in
    // the process-isolated `regression_hosted_git_api_failures_counted.rs`.
}

#[test]
fn clone_url_origin_policy_blocks_cross_host_token_forwarding() {
    let github = ExpectedCloneOrigin::host("github.com");
    assert!(
        validate_clone_url_for_origin("github", "https://github.com/org/repo.git", &github).is_ok()
    );
    assert!(validate_clone_url_for_origin(
        "github",
        "https://github.com:443/org/repo.git",
        &github
    )
    .is_ok());

    let err =
        validate_clone_url_for_origin("github", "https://attacker.example/org/repo.git", &github)
            .expect_err("cross-host clone URL must be refused before askpass is installed")
            .to_string();
    assert!(
        err.contains("outside expected clone origin")
            && err.contains("github.com")
            && err.contains("attacker.example"),
        "origin error must name expected and actual host, got {err}"
    );

    let self_hosted = ExpectedCloneOrigin {
        host: "gitlab.internal".to_string(),
        port: 443,
    };
    assert!(
        validate_clone_url_for_origin(
            "gitlab",
            "https://gitlab.internal/group/repo.git",
            &self_hosted,
        )
        .is_ok(),
        "operator-configured self-hosted clone origins must not be rejected as SSRF"
    );
}

#[test]
fn git_clone_disables_redirects_and_ambient_credential_helpers() {
    let args = super::git_clone_args();
    assert!(
        args.windows(2)
            .any(|pair| pair == ["-c", "http.followRedirects=false"]),
        "hosted git clone must disable HTTP redirects before askpass credentials are available"
    );
    assert!(
            args.windows(2)
                .any(|pair| pair == ["-c", "credential.helper="]),
            "hosted git clone must ignore ambient credential helpers and use only its scoped askpass material"
        );
    assert_eq!(
        args[6..],
        ["clone", "--depth", "1", "--quiet"],
        "git config overrides must precede the clone subcommand"
    );
}

#[test]
fn hosted_git_api_json_cap_is_counted_unreadable() {
    let cap = 16;
    let server = httpmock::MockServer::start();
    let _api = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/api");
        then.status(200)
            .header("content-type", "application/json")
            .body(format!(r#"{{"padding":"{}"}}"#, "x".repeat(cap)));
    });
    let response = reqwest::blocking::Client::new()
        .get(server.url("/api"))
        .send()
        .expect("mock API response");

    let error = super::read_api_json::<serde_json::Value>(response, "GitHub API response", cap)
        .expect_err("oversized hosted Git API response must fail");

    let message = error.to_string();
    assert!(
        message.contains("GitHub API response")
            && message.contains("web_response_bytes")
            && message.contains(&cap.to_string()),
        "hosted Git API cap error must be visible, got {message}"
    );
    // The unreadable-counter delta for the API response cap is asserted
    // process-isolated in `regression_hosted_git_api_failures_counted.rs`
    // (gitlab/bitbucket oversized-response tests, same `read_api_json` path);
    // re-reading the process-global counter here would race the `--lib` run.
}

#[test]
fn hosted_git_stderr_drain_is_bounded_and_marks_truncation() {
    let payload = vec![b'E'; crate::process_excerpt::STDERR_EXCERPT_BYTES * 2];
    let excerpt = crate::process_excerpt::drain_stderr_excerpt(&payload[..]);
    assert!(
        excerpt.len() <= crate::process_excerpt::STDERR_EXCERPT_BYTES + 64,
        "stderr excerpt must remain bounded, got {} bytes",
        excerpt.len()
    );
    assert!(
        excerpt.contains("[stderr truncated after 65536 bytes]"),
        "large stderr must be marked truncated"
    );
}

#[test]
fn hosted_git_stdout_drain_consumes_large_output_without_buffering() {
    let payload = vec![b'O'; crate::process_excerpt::STDERR_EXCERPT_BYTES * 2];
    super::drain_hosted_git_stdout(&payload[..]).expect("stdout drain");
}

#[test]
fn hosted_git_error_suffix_redacts_captured_stderr_credentials() {
    let secret = format!("ghp_{}", "a".repeat(36));
    let stderr = format!(
            "fatal: unable to access https://alice:{secret}@github.com/o/r.git/\nAuthorization: Bearer {secret}"
        );
    let suffix = super::hosted_git_stderr_suffix(&stderr);
    assert!(
        suffix.contains("; git stderr:"),
        "non-empty stderr should be surfaced with context, got {suffix:?}"
    );
    assert!(
        suffix.contains("<redacted>") || suffix.contains("<redacted-token>"),
        "credential-bearing stderr should show redaction markers, got {suffix:?}"
    );
    for leaked in [&secret, "alice:"] {
        assert!(
            !suffix.contains(leaked),
            "hosted Git stderr suffix leaked {leaked:?}: {suffix:?}"
        );
    }
}

#[test]
fn hosted_git_error_suffix_omits_empty_captured_stderr() {
    assert_eq!(super::hosted_git_stderr_suffix(" \n\t "), "");
}

#[cfg(unix)]
#[test]
fn askpass_refuses_prompts_outside_expected_origin_without_printing_secret_or_path_tools() {
    let auth =
        super::GitAskpassAuth::create("github", "x-access-token", "SECRET_TOKEN", "github.com")
            .expect("askpass auth");

    let allowed = std::process::Command::new(&auth.askpass_path)
        .arg("Password for 'https://x-access-token@github.com':")
        .env("PATH", "/keyhog/path/must/not/be/used")
        .output()
        .expect("run allowed askpass");
    assert!(
        allowed.status.success(),
        "matching-origin prompt should succeed: {allowed:?}"
    );
    assert_eq!(
        String::from_utf8_lossy(&allowed.stdout).trim(),
        "SECRET_TOKEN"
    );

    let blocked = std::process::Command::new(&auth.askpass_path)
        .arg("Password for 'https://attacker.example':")
        .env("PATH", "/keyhog/path/must/not/be/used")
        .output()
        .expect("run blocked askpass");
    assert!(
        !blocked.status.success(),
        "mismatched-origin prompt must fail closed"
    );
    assert!(
        !String::from_utf8_lossy(&blocked.stdout).contains("SECRET_TOKEN"),
        "mismatched-origin prompt must not print the token"
    );
    assert!(
        String::from_utf8_lossy(&blocked.stderr).contains("outside expected origin"),
        "mismatched-origin prompt must explain refusal"
    );
}

#[cfg(any(feature = "gitlab", feature = "bitbucket"))]
#[test]
fn api_endpoint_rejects_embedded_credentials_without_leaking_secrets() {
    let err = super::validated_api_endpoint(
        "gitlab",
        "https://user:SECRET@gitlab.example/api/v4?token=SECRET2#SECRET3",
    )
    .expect_err("API endpoints must not carry embedded auth material")
    .to_string();

    assert!(
        err.contains("embedded credentials") && err.contains("https://gitlab.example/api/v4"),
        "error must explain the credential refusal and keep the endpoint identifiable, got {err}"
    );
    for secret in ["user", "SECRET", "SECRET2", "SECRET3", "token="] {
        assert!(
            !err.contains(secret),
            "API endpoint error leaked {secret:?}: {err}"
        );
    }
}

#[cfg(any(feature = "gitlab", feature = "bitbucket"))]
#[test]
fn api_endpoint_and_pagination_errors_redact_query_fragment_and_userinfo() {
    let endpoint_err =
        super::validated_api_endpoint("gitlab", "https://gitlab.example/api/v4?token=SECRET")
            .expect_err("API endpoints with query material must be refused")
            .to_string();
    assert!(
        endpoint_err.contains("query or fragment")
            && endpoint_err.contains("https://gitlab.example/api/v4")
            && !endpoint_err.contains("SECRET")
            && !endpoint_err.contains("token="),
        "endpoint error must not leak query credentials, got {endpoint_err}"
    );

    let base = reqwest::Url::parse("https://gitlab.example/api/v4").expect("base url");
    let candidate =
        reqwest::Url::parse("https://user:SECRET@evil.example/api?next=SECRET2#SECRET3")
            .expect("candidate url");
    let origin_err = super::require_same_api_origin("gitlab", &base, &candidate)
        .expect_err("cross-origin pagination must be refused")
        .to_string();
    assert!(
        origin_err.contains("outside configured API origin")
            && origin_err.contains("https://evil.example/api"),
        "pagination origin error must keep sanitized candidate origin, got {origin_err}"
    );
    for secret in ["user", "SECRET", "SECRET2", "SECRET3", "next="] {
        assert!(
            !origin_err.contains(secret),
            "pagination origin error leaked {secret:?}: {origin_err}"
        );
    }
}
