//! Shared clone-and-scan machinery for hosted Git repository collections.

use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use keyhog_core::{Chunk, Source, SourceError};
use serde::de::DeserializeOwned;

use crate::capped_read::MAX_PREALLOCATED_READ_BYTES;
use crate::FilesystemSource;

mod sanitize;
use sanitize::sanitize_git_error_message;

#[derive(Debug, Clone)]
pub(crate) struct HostedRepo {
    pub(crate) clone_dir_name: String,
    pub(crate) display_path: String,
    pub(crate) clone_url: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ExpectedCloneOrigin {
    host: String,
    port: u16,
}

impl ExpectedCloneOrigin {
    pub(crate) fn host(host: &str) -> Self {
        Self {
            host: host.to_ascii_lowercase(),
            port: 443,
        }
    }

    #[cfg(feature = "gitlab")]
    pub(crate) fn from_api_root(api_root: &reqwest::Url) -> Result<Self, SourceError> {
        let host = api_root.host_str().ok_or_else(|| {
            SourceError::Other("gitlab: API endpoint did not include a host".into())
        })?;
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port: api_root.port_or_known_default().ok_or_else(|| {
                SourceError::Other("gitlab: API endpoint did not expose a comparable port".into())
            })?,
        })
    }

    #[cfg(feature = "bitbucket")]
    pub(crate) fn bitbucket(api_root: &reqwest::Url) -> Result<Self, SourceError> {
        let host = api_root.host_str().ok_or_else(|| {
            SourceError::Other("bitbucket: API endpoint did not include a host".into())
        })?;
        if host.eq_ignore_ascii_case("api.bitbucket.org") {
            return Ok(Self::host("bitbucket.org"));
        }
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port: api_root.port_or_known_default().ok_or_else(|| {
                SourceError::Other(
                    "bitbucket: API endpoint did not expose a comparable port".into(),
                )
            })?,
        })
    }
}

pub(crate) fn scan_hosted_repos(
    platform: &str,
    source_type: &str,
    namespace: Option<&str>,
    token_username: &str,
    token_secret: &str,
    expected_clone_origin: &ExpectedCloneOrigin,
    repos: &[HostedRepo],
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
) -> Result<Vec<Result<Chunk, SourceError>>, SourceError> {
    use rayon::prelude::*;

    let temp_dir = tempfile::tempdir().map_err(SourceError::Io)?;
    let temp_root = temp_dir.path().to_path_buf();

    let pool = crate::parallel_fetch::bounded_fetch_pool(
        platform,
        crate::parallel_fetch::REMOTE_API_FETCH_THREADS,
    )?;

    let per_repo: Vec<Result<Vec<Chunk>, SourceError>> = pool.install(|| {
        repos
            .par_iter()
            .map(|repo| {
                scan_single_hosted_repo(
                    platform,
                    source_type,
                    namespace,
                    token_username,
                    token_secret,
                    expected_clone_origin,
                    repo,
                    &temp_root,
                    limits,
                    respect_default_excludes,
                )
            })
            .collect()
    });

    Ok(merge_hosted_repo_results(platform, repos, per_repo))
}

fn scan_single_hosted_repo(
    platform: &str,
    source_type: &str,
    namespace: Option<&str>,
    token_username: &str,
    token_secret: &str,
    expected_clone_origin: &ExpectedCloneOrigin,
    repo: &HostedRepo,
    temp_root: &Path,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
) -> Result<Vec<Chunk>, SourceError> {
    validate_repo_name(platform, &repo.clone_dir_name)?;
    validate_display_path(platform, &repo.display_path)?;
    validate_clone_url_for_origin(platform, &repo.clone_url, expected_clone_origin)?;
    let clone_path = temp_root.join(&repo.clone_dir_name);
    clone_repo(
        platform,
        &repo.display_path,
        &repo.clone_url,
        token_username,
        token_secret,
        &clone_path,
    )?;
    scan_repo(
        platform,
        source_type,
        namespace,
        &repo.display_path,
        &clone_path,
        limits,
        respect_default_excludes,
    )
}

fn merge_hosted_repo_results(
    platform: &str,
    repos: &[HostedRepo],
    per_repo: Vec<Result<Vec<Chunk>, SourceError>>,
) -> Vec<Result<Chunk, SourceError>> {
    let mut rows = Vec::new();
    for (repo, result) in repos.iter().zip(per_repo) {
        match result {
            Ok(chunks) => rows.extend(chunks.into_iter().map(Ok)),
            Err(error) => rows.push(Err(repo_unreadable_error(
                platform,
                &repo.display_path,
                error,
            ))),
        }
    }
    rows
}

fn repo_unreadable_error(
    platform: &str,
    repo_display_path: &str,
    error: SourceError,
) -> SourceError {
    let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
    SourceError::Other(format!(
        "{platform}: failed to scan hosted repository {repo_display_path}: {error}; repository was not scanned"
    ))
}

#[cfg(feature = "bitbucket")]
pub(crate) fn repo_listing_unreadable_error(
    platform: &str,
    repo_display_path: &str,
    error: SourceError,
) -> SourceError {
    repo_unreadable_error(platform, repo_display_path, error)
}

#[cfg(test)]
mod tests {
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
        assert!(validate_clone_url_for_origin(
            "github",
            "https://github.com/org/repo.git",
            &github
        )
        .is_ok());
        assert!(validate_clone_url_for_origin(
            "github",
            "https://github.com:443/org/repo.git",
            &github
        )
        .is_ok());

        let err = validate_clone_url_for_origin(
            "github",
            "https://attacker.example/org/repo.git",
            &github,
        )
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
}

/// Refuse repo directory names that escape the temp clone root: `..`, absolute
/// paths, path separators, or characters outside the forge repo-name alphabet.
pub(crate) fn validate_repo_name(platform: &str, name: &str) -> Result<(), SourceError> {
    if name.is_empty() || name.len() > 100 {
        return Err(SourceError::Other(format!(
            "{platform}: refusing repo with out-of-range name length ({})",
            name.len()
        )));
    }
    if name == "." || name == ".." || name.contains('/') || name.contains('\\') {
        return Err(SourceError::Other(format!(
            "{platform}: refusing repo with traversal/separator in name: {name:?}"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err(SourceError::Other(format!(
            "{platform}: refusing repo with non-alphanumeric name: {name:?}"
        )));
    }
    Ok(())
}

/// Validate a slash-separated forge display path before it is copied into
/// finding paths. This may contain subgroup/project separators, but each segment
/// must still be a normal repo-name component.
pub(crate) fn validate_display_path(platform: &str, path: &str) -> Result<(), SourceError> {
    if path.is_empty() || path.len() > 512 || path.starts_with('/') || path.ends_with('/') {
        return Err(SourceError::Other(format!(
            "{platform}: refusing repository display path with invalid length or slash placement: {path:?}"
        )));
    }
    for segment in path.split('/') {
        validate_repo_name(platform, segment)?;
    }
    Ok(())
}

/// Refuse clone URLs that git would interpret as anything other than an HTTPS
/// repository URL bound to the forge origin that supplied it.
pub(crate) fn validate_clone_url_for_origin(
    platform: &str,
    url: &str,
    expected: &ExpectedCloneOrigin,
) -> Result<(), SourceError> {
    let parsed = validate_clone_url_shape(platform, url)?;
    let actual_host = parsed.host_str().ok_or_else(|| {
        SourceError::Other(format!(
            "{platform}: refusing hostless clone URL after validation"
        ))
    })?;
    let actual_port = parsed.port_or_known_default().ok_or_else(|| {
        SourceError::Other(format!(
            "{platform}: refusing clone URL without a comparable port after validation"
        ))
    })?;
    if actual_host.eq_ignore_ascii_case(&expected.host) && actual_port == expected.port {
        return Ok(());
    }
    Err(SourceError::Other(format!(
        "{platform}: refusing clone URL outside expected clone origin {}:{}: {}",
        expected.host,
        expected.port,
        crate::url_redaction::redact_url(url)
    )))
}

fn validate_clone_url_shape(platform: &str, url: &str) -> Result<reqwest::Url, SourceError> {
    let redacted = crate::url_redaction::redact_url(url);
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(SourceError::Other(format!(
            "{platform}: refusing clone URL with whitespace/control characters: {redacted:?}"
        )));
    }
    if url.len() > 2048 {
        return Err(SourceError::Other(format!(
            "{platform}: refusing clone URL longer than 2048 chars ({})",
            url.len()
        )));
    }
    if contains_windows_cmd_metachar(url) {
        return Err(SourceError::Other(format!(
            "{platform}: refusing clone URL with Windows command metacharacters: {redacted:?}"
        )));
    }

    let parsed = reqwest::Url::parse(url).map_err(|error| {
        SourceError::Other(format!(
            "{platform}: refusing invalid clone URL {redacted:?}: {error}"
        ))
    })?;
    if parsed.scheme() != "https" {
        return Err(SourceError::Other(format!(
            "{platform}: refusing non-https clone URL (potential ext::/ssh:// RCE vector): {redacted:?}"
        )));
    }
    if parsed.host_str().is_none() {
        return Err(SourceError::Other(format!(
            "{platform}: refusing hostless clone URL: {redacted:?}"
        )));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(SourceError::Other(format!(
            "{platform}: refusing clone URL with embedded credentials: {redacted:?}"
        )));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(SourceError::Other(format!(
            "{platform}: refusing clone URL with query or fragment: {redacted:?}"
        )));
    }
    Ok(parsed)
}

fn contains_windows_cmd_metachar(url: &str) -> bool {
    url.contains(['&', '|', '<', '>', '^'])
}

pub(crate) fn listing_truncated_error(
    platform: &str,
    owner_kind: &str,
    owner_name: &str,
    repo_count: usize,
    max_pages: usize,
) -> SourceError {
    let _event = crate::record_skip_event(crate::SourceSkipEvent::SourceTruncated);
    SourceError::Other(format!(
        "{platform} {owner_kind} repository listing for {owner_name} exceeded {max_pages} pages \
         ({repo_count} repositories); refusing to scan a partial {owner_kind} repository collection \
         because unseen repositories would be reported clean"
    ))
}

#[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
pub(crate) fn api_unreadable_error(message: impl Into<String>) -> SourceError {
    let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
    SourceError::Other(message.into())
}

#[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
pub(crate) fn read_api_json<T: DeserializeOwned>(
    response: reqwest::blocking::Response,
    context: &str,
    max_response_bytes: usize,
) -> Result<T, SourceError> {
    let max_response_bytes_u64 = match u64::try_from(max_response_bytes) {
        Ok(value) => value,
        Err(_) => u64::MAX, // LAW10: unreachable on real platforms — only a usize wider than u64 takes this arm, where reqwest content lengths and Read::take caps are u64-bounded, so every representable HTTP body length is still capped.
    };
    if let Some(content_length) = response.content_length() {
        if content_length > max_response_bytes_u64 {
            return Err(api_unreadable_error(format!(
                "{context} Content-Length {content_length} exceeds the web_response_bytes cap {max_response_bytes}"
            )));
        }
    }

    let capacity_hint = response.content_length().map(|len| {
        len.min(max_response_bytes_u64)
            .min(MAX_PREALLOCATED_READ_BYTES)
    });
    let read = crate::capped_read::read_to_cap(response, max_response_bytes_u64, capacity_hint)
        .map_err(|error| api_unreadable_error(format!("failed to read {context}: {error}")))?;
    if read.truncated {
        return Err(api_unreadable_error(format!(
            "streamed {context} exceeded the web_response_bytes cap {max_response_bytes}"
        )));
    }
    serde_json::from_slice(&read.bytes)
        .map_err(|error| api_unreadable_error(format!("failed to parse {context}: {error}")))
}

#[cfg(any(feature = "gitlab", feature = "bitbucket"))]
pub(crate) fn validated_api_endpoint(
    platform: &str,
    endpoint: &str,
) -> Result<reqwest::Url, SourceError> {
    let safe_endpoint = api_endpoint_for_error(endpoint);
    let url = reqwest::Url::parse(endpoint).map_err(|error| {
        SourceError::Other(format!(
            "{platform}: invalid API endpoint {safe_endpoint:?}: {error}"
        ))
    })?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(SourceError::Other(format!(
            "{platform}: API endpoint must not include embedded credentials: {safe_endpoint:?}"
        )));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(SourceError::Other(format!(
            "{platform}: API endpoint must not include query or fragment: {safe_endpoint:?}"
        )));
    }
    match url.scheme() {
        "https" => Ok(url),
        "http" if url.host_str().is_some_and(is_loopback_host) => Ok(url),
        scheme => Err(SourceError::Other(format!(
            "{platform}: refusing {scheme:?} API endpoint {safe_endpoint:?}; use https, or loopback http only for local tests"
        ))),
    }
}

#[cfg(any(feature = "gitlab", feature = "bitbucket"))]
fn api_endpoint_for_error(endpoint: &str) -> String {
    let redacted = crate::url_redaction::redact_url(endpoint);
    if let Ok(mut url) = reqwest::Url::parse(redacted.as_ref()) {
        // LAW10: malformed endpoint diagnostics fall back to delimiter trimming below; validation is fail-closed at the caller
        let _ = url.set_username(""); // LAW10: reporting-only URL sanitization (diagnostic display); failure leaves the already-redacted URL without changing scan behavior
        let _ = url.set_password(None); // LAW10: reporting-only URL sanitization (diagnostic display); failure leaves the already-redacted URL without changing scan behavior
        url.set_query(None);
        url.set_fragment(None);
        return url.to_string();
    }
    let cutoff = redacted.find(['?', '#']).unwrap_or(redacted.len()); // LAW10: display-only — malformed endpoint diagnostics keep only the non-secret prefix
    redacted[..cutoff].to_string()
}

#[cfg(any(feature = "gitlab", feature = "bitbucket"))]
pub(crate) fn require_same_api_origin(
    platform: &str,
    base: &reqwest::Url,
    candidate: &reqwest::Url,
) -> Result<(), SourceError> {
    if base.scheme() == candidate.scheme()
        && base.host_str() == candidate.host_str()
        && base.port_or_known_default() == candidate.port_or_known_default()
    {
        return Ok(());
    }
    Err(api_unreadable_error(format!(
        "{platform}: refusing pagination URL outside configured API origin: {}",
        api_endpoint_for_error(candidate.as_str())
    )))
}

pub(crate) fn scan_repo_chunks<I>(
    input_chunks: I,
    platform: &str,
    source_type: &str,
    namespace: Option<&str>,
    repo_display_path: &str,
    clone_path: &Path,
) -> Result<Vec<Chunk>, SourceError>
where
    I: IntoIterator<Item = Result<Chunk, SourceError>>,
{
    let mut rewritten = Vec::new();

    for chunk in input_chunks.into_iter() {
        match chunk {
            Ok(chunk) => rewritten.push(rewrite_chunk_path(
                chunk,
                platform,
                source_type,
                namespace,
                repo_display_path,
                clone_path,
            )?),
            Err(error) => {
                return Err(SourceError::Other(format!(
                    "{platform}: failed to scan cloned repo {repo_display_path}: {error}"
                )));
            }
        }
    }

    Ok(rewritten)
}

pub(crate) fn rewrite_chunk_path(
    mut chunk: Chunk,
    platform: &str,
    source_type: &str,
    namespace: Option<&str>,
    repo_display_path: &str,
    clone_path: &Path,
) -> Result<Chunk, SourceError> {
    let source_path = chunk.metadata.path.as_deref().ok_or_else(|| {
        SourceError::Other(format!(
            "{platform}: cloned repo {repo_display_path} produced a chunk without a file path"
        ))
    })?;
    let relative_path = make_relative_path(platform, source_path, clone_path)?;

    chunk.metadata.source_type = source_type.into();
    chunk.metadata.path = Some(match namespace {
        Some(namespace) if !namespace.is_empty() => {
            format!("{namespace}/{repo_display_path}/{relative_path}").into()
        }
        _ => format!("{repo_display_path}/{relative_path}").into(),
    });
    chunk.metadata.commit = None;
    chunk.metadata.author = None;
    chunk.metadata.date = None;

    Ok(chunk)
}

fn clone_repo(
    platform: &str,
    repo_display_path: &str,
    clone_url: &str,
    token_username: &str,
    token_secret: &str,
    clone_path: &Path,
) -> Result<(), SourceError> {
    let clone_target = clone_path.to_str().ok_or_else(|| {
        SourceError::Other(format!(
            "{platform}: non-UTF-8 clone path for repo {repo_display_path}"
        ))
    })?;
    let parsed_clone_url = reqwest::Url::parse(clone_url).map_err(|error| {
        SourceError::Other(format!(
            "{platform}: validated clone URL could not be reparsed for askpass origin binding: {}: {error}",
            crate::url_redaction::redact_url(clone_url)
        ))
    })?;
    let expected_prompt_host = parsed_clone_url
        .host_str()
        .ok_or_else(|| {
            SourceError::Other(format!(
                "{platform}: validated clone URL lost its prompt host for repo {repo_display_path}"
            ))
        })?
        .to_string();
    let auth_material = GitAskpassAuth::create(
        platform,
        token_username,
        token_secret,
        &expected_prompt_host,
    )?;

    // ONE PLACE: build the clone via the hermetic git factory so it nulls
    // GIT_CONFIG_GLOBAL/GIT_CONFIG_SYSTEM (a host `commit.gpgsign` /
    // `credential.helper` / `core.hooksPath` cannot hook, sign, or block the
    // clone on a prompt) and resolves the trusted git binary — the exact
    // isolation every other git spawn uses. `git_command()`'s own doc requires
    // that "every git spawn goes through here rather than Command::new(git_bin)";
    // this clone was the one bypass. The auth-specific askpass is layered on top.
    let mut child = crate::git::git_command()?
        .env("GIT_ASKPASS", &auth_material.askpass_path)
        .env("SSH_ASKPASS", &auth_material.askpass_path)
        .args(git_clone_args())
        .arg("--end-of-options")
        .arg(clone_url)
        .arg(clone_target)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(SourceError::Io)?;
    let stdout_drain = child
        .stdout
        .take()
        .map(|pipe| thread::spawn(move || drain_hosted_git_stdout(pipe)));
    let stderr_drain = child
        .stderr
        .take()
        .map(|pipe| thread::spawn(move || crate::process_excerpt::drain_stderr_excerpt(pipe)));

    let output = wait_for_command_with_timeout(
        child,
        stdout_drain,
        stderr_drain,
        crate::timeouts::GIT_CLONE,
    )
    .map_err(|err| SourceError::Git(format!("failed to clone {repo_display_path}: {err}")))?;

    if !output.status.success() {
        return Err(SourceError::Git(format!(
            "failed to clone {repo_display_path}: {}",
            sanitize_git_error_message(&output.stderr)
        )));
    }

    Ok(())
}

fn git_clone_args() -> [&'static str; 10] {
    [
        "-c",
        "http.followRedirects=false",
        "-c",
        "credential.helper=",
        "-c",
        "credential.useHttpPath=true",
        "clone",
        "--depth",
        "1",
        "--quiet",
    ]
}

fn scan_repo(
    platform: &str,
    source_type: &str,
    namespace: Option<&str>,
    repo_display_path: &str,
    clone_path: &Path,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
) -> Result<Vec<Chunk>, SourceError> {
    let source = FilesystemSource::new(clone_path.to_path_buf())
        .with_max_file_size(limits.git_blob_bytes)
        .with_default_excludes(respect_default_excludes);
    scan_repo_chunks(
        source.chunks(),
        platform,
        source_type,
        namespace,
        repo_display_path,
        clone_path,
    )
}

fn make_relative_path(
    platform: &str,
    path: &str,
    clone_path: &Path,
) -> Result<String, SourceError> {
    let raw_path = Path::new(path);
    let candidate = if raw_path.is_absolute() {
        raw_path.to_path_buf()
    } else {
        clone_path.join(raw_path)
    };
    let normalized_path = std::fs::canonicalize(&candidate).map_err(|error| {
        SourceError::Other(format!(
            "{platform}: cannot canonicalize cloned repo chunk path {}: {error}",
            candidate.display()
        ))
    })?;
    let normalized_clone_path = std::fs::canonicalize(clone_path).map_err(|error| {
        SourceError::Other(format!(
            "{platform}: cannot canonicalize cloned repo root {}: {error}",
            clone_path.display()
        ))
    })?;
    let relative = normalized_path
        .strip_prefix(&normalized_clone_path)
        .map_err(|_| {
            SourceError::Other(format!(
                "{platform}: cloned repo chunk path {} is outside clone root {}",
                normalized_path.display(),
                normalized_clone_path.display()
            ))
        })?
        .to_path_buf();
    Ok(relative.to_string_lossy().into_owned())
}

struct HostedGitCommandOutput {
    status: ExitStatus,
    stderr: String,
}

fn wait_for_command_with_timeout(
    mut child: Child,
    stdout_drain: Option<thread::JoinHandle<Result<(), String>>>,
    stderr_drain: Option<thread::JoinHandle<String>>,
    timeout: Duration,
) -> Result<HostedGitCommandOutput, String> {
    let start = Instant::now();
    let mut stdout_drain = stdout_drain;
    let mut stderr_drain = stderr_drain;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return finish_hosted_git_child(status, stdout_drain.take(), stderr_drain.take());
            }
            Ok(None) => {}
            Err(error) => {
                kill_and_reap_child(&mut child).map_err(|cleanup_error| {
                    format!(
                        "git clone status check failed: {error}; additionally failed to stop child: {cleanup_error}"
                    )
                })?;
                let stdout_cleanup = match join_hosted_git_stdout(stdout_drain.take()) {
                    Ok(()) => String::new(),
                    Err(error) => format!("; stdout cleanup failed: {error}"),
                };
                let stderr = join_hosted_git_stderr(stderr_drain.take());
                let stderr_suffix = hosted_git_stderr_suffix(&stderr);
                return Err(format!(
                    "git clone status check failed: {error}; child was killed and reaped{stdout_cleanup}{stderr_suffix}"
                ));
            }
        }

        if start.elapsed() >= timeout {
            kill_and_reap_child(&mut child).map_err(|cleanup_error| {
                format!(
                    "git clone timed out after {}s; additionally failed to stop child: {cleanup_error}",
                    timeout.as_secs()
                )
            })?;
            let stderr = join_hosted_git_stderr(stderr_drain.take());
            let stderr_suffix = hosted_git_stderr_suffix(&stderr);
            let stdout_cleanup = match join_hosted_git_stdout(stdout_drain.take()) {
                Ok(()) => String::new(),
                Err(error) => format!("; stdout cleanup failed: {error}"),
            };
            return Err(format!(
                "git clone timed out after {}s{stdout_cleanup}{stderr_suffix}",
                timeout.as_secs()
            ));
        }

        thread::sleep(Duration::from_millis(100));
    }
}

fn finish_hosted_git_child(
    status: ExitStatus,
    stdout_drain: Option<thread::JoinHandle<Result<(), String>>>,
    stderr_drain: Option<thread::JoinHandle<String>>,
) -> Result<HostedGitCommandOutput, String> {
    let stdout_result = join_hosted_git_stdout(stdout_drain);
    let stderr = join_hosted_git_stderr(stderr_drain);
    stdout_result?;
    Ok(HostedGitCommandOutput { status, stderr })
}

fn join_hosted_git_stdout(
    stdout_drain: Option<thread::JoinHandle<Result<(), String>>>,
) -> Result<(), String> {
    match stdout_drain {
        Some(handle) => match handle.join() {
            Ok(result) => result,
            Err(_panic_payload) => Err("git clone stdout reader panicked".to_string()),
        },
        None => Ok(()),
    }
}

fn join_hosted_git_stderr(stderr_drain: Option<thread::JoinHandle<String>>) -> String {
    match stderr_drain {
        Some(handle) => match handle.join() {
            Ok(stderr) => stderr,
            Err(_panic_payload) => "stderr unavailable: git clone stderr reader panicked".into(),
        },
        None => "stderr unavailable: git clone stderr was not captured".into(),
    }
}

fn hosted_git_stderr_suffix(stderr: &str) -> String {
    let stderr = sanitize_git_error_message(stderr);
    if stderr.is_empty() {
        String::new()
    } else {
        format!("; git stderr: {stderr}")
    }
}

fn drain_hosted_git_stdout(mut stdout_pipe: impl std::io::Read) -> Result<(), String> {
    let mut buffer = [0_u8; 8192];
    loop {
        match std::io::Read::read(&mut stdout_pipe, &mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) => return Err(format!("stdout unavailable: {error}")),
        }
    }
}

fn kill_and_reap_child(child: &mut std::process::Child) -> Result<(), String> {
    let kill_result = child.kill();
    let wait_result = child.wait();
    match (kill_result, wait_result) {
        (_, Ok(_status)) => Ok(()),
        (Ok(()), Err(wait_error)) => Err(format!("failed to reap child: {wait_error}")),
        (Err(kill_error), Err(wait_error)) => Err(format!(
            "failed to kill child: {kill_error}; failed to reap child: {wait_error}"
        )),
    }
}

#[derive(Debug)]
struct GitAskpassAuth {
    _dir: tempfile::TempDir,
    askpass_path: PathBuf,
}

impl GitAskpassAuth {
    fn create(
        platform: &str,
        username: &str,
        secret: &str,
        expected_prompt_host: &str,
    ) -> Result<Self, SourceError> {
        validate_auth_part(platform, "username", username)?;
        validate_auth_part(platform, "token", secret)?;
        validate_auth_part(platform, "expected clone host", expected_prompt_host)?;

        let dir = tempfile::tempdir().map_err(SourceError::Io)?;
        let username_path = dir.path().join("username");
        let token_path = dir.path().join("token");
        let origin_path = dir.path().join("origin-host");
        write_secret_file(&username_path, username.as_bytes())?;
        write_secret_file(&token_path, secret.as_bytes())?;
        write_secret_file(&origin_path, expected_prompt_host.as_bytes())?;

        let askpass_path = if cfg!(unix) {
            let path = dir.path().join("askpass.sh");
            write_askpass_file(
                &path,
                b"#!/bin/sh\nset -eu\nDIR=${0%/*}\n[ \"$DIR\" != \"$0\" ] || DIR=.\nread_one() {\n  IFS= read -r line < \"$1\" || [ -n \"${line-}\" ] || exit 1\n  printf '%s\\n' \"$line\"\n}\nORIGIN=$(read_one \"$DIR/origin-host\")\ncase \"${1-}\" in\n*\"$ORIGIN\"*) ;;\n*) printf '%s\\n' \"keyhog: refusing git credential prompt outside expected origin\" >&2; exit 1 ;;\nesac\ncase \"${1-}\" in\n*Username*) read_one \"$DIR/username\" ;;\n*) read_one \"$DIR/token\" ;;\nesac\n",
            )?;
            path
        } else {
            let path = dir.path().join("askpass.bat");
            let content = format!(
                "@echo off\r\nsetlocal EnableExtensions EnableDelayedExpansion\r\nset \"prompt=%~1\"\r\nset /p origin=<\"{}\"\r\necho(!prompt!| findstr /I /L /C:\"!origin!\" >nul\r\nif errorlevel 1 (\r\n  >&2 echo keyhog: refusing git credential prompt outside expected origin\r\n  exit /b 1\r\n)\r\necho(!prompt!| findstr /I /C:\"Username\" >nul\r\nif not errorlevel 1 (\r\n  type \"{}\"\r\n) else (\r\n  type \"{}\"\r\n)\r\n",
                origin_path.display(),
                username_path.display(),
                token_path.display()
            );
            write_askpass_file(&path, content.as_bytes())?;
            path
        };

        Ok(Self {
            _dir: dir,
            askpass_path,
        })
    }
}

fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<(), SourceError> {
    #[cfg(unix)]
    return write_private_file(path, bytes, 0o600);
    #[cfg(not(unix))]
    write_private_file(path, bytes)
}

fn write_askpass_file(path: &Path, bytes: &[u8]) -> Result<(), SourceError> {
    #[cfg(unix)]
    return write_private_file(path, bytes, 0o700);
    #[cfg(not(unix))]
    write_private_file(path, bytes)
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8], unix_mode: u32) -> Result<(), SourceError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    options.mode(unix_mode);

    let mut file = options.open(path).map_err(SourceError::Io)?;
    file.write_all(bytes).map_err(SourceError::Io)
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), SourceError> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);

    let mut file = options.open(path).map_err(SourceError::Io)?;
    file.write_all(bytes).map_err(SourceError::Io)
}

fn validate_auth_part(platform: &str, label: &str, value: &str) -> Result<(), SourceError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(SourceError::Other(format!(
            "{platform}: {label} contains unsafe characters"
        )));
    }
    Ok(())
}

#[cfg(any(feature = "gitlab", feature = "bitbucket"))]
fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}
