//! Shared clone-and-scan machinery for hosted Git repository collections.

use std::path::Path;
use std::process::Stdio;
use std::thread;

use keyhog_core::{Chunk, Source, SourceCoverageGapKind, SourceError};
use serde::de::DeserializeOwned;

use crate::capped_read::MAX_PREALLOCATED_READ_BYTES;
use crate::FilesystemSource;

mod process;
mod sanitize;
use process::{
    clone_materialization_truncated, drain_hosted_git_stdout, wait_for_command_with_timeout,
    CloneMaterializationGuard, GitAskpassAuth, HostedGitWaitError,
};
use sanitize::sanitize_git_error_message;

// The `#[path]`-included unit test modules below reach these through `super::`,
// so they keep their pre-split spelling at this level rather than having the
// test file path into `process` directly.
#[cfg(test)]
use process::{clone_materialization_cap, hosted_git_stderr_suffix, CloneMaterializationCap};

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

    pub(crate) fn from_endpoint(platform: &str, endpoint: &str) -> Result<Self, SourceError> {
        let url = reqwest::Url::parse(endpoint).map_err(|error| {
            SourceError::Other(format!(
                "{platform}: invalid API endpoint for clone origin: {error}"
            ))
        })?;
        let host = url.host_str().ok_or_else(|| {
            SourceError::Other(format!("{platform}: API endpoint has no clone origin host"))
        })?;
        let port = url.port_or_known_default().ok_or_else(|| {
            SourceError::Other(format!("{platform}: API endpoint has no clone origin port"))
        })?;
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port,
        })
    }

    /// GitHub.com's REST API lives on `api.github.com` while HTTPS clones use
    /// `github.com`. Map the public API host to the public clone host the same
    /// way Bitbucket maps `api.bitbucket.org` → `bitbucket.org`. Self-hosted
    /// GHES keeps the API host as the clone origin.
    #[cfg(feature = "github")]
    pub(crate) fn github_from_api_endpoint(endpoint: &str) -> Result<Self, SourceError> {
        let origin = Self::from_endpoint("github", endpoint)?;
        if origin.host.eq_ignore_ascii_case("api.github.com") {
            return Ok(Self::host("github.com"));
        }
        Ok(origin)
    }

    /// Host[:port] suitable for an `https://` clone URL authority.
    pub(crate) fn https_authority(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
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

pub(crate) fn stream_hosted_repos(
    platform: &str,
    source_type: &str,
    namespace: Option<&str>,
    token_username: &str,
    token_secret: &str,
    expected_clone_origin: &ExpectedCloneOrigin,
    repos: &[HostedRepo],
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
    scan_lease: &crate::skip::ScanReadLease,
    mut emit: impl FnMut(Result<Chunk, SourceError>) -> bool,
) -> Result<(), SourceError> {
    let temp_dir = tempfile::tempdir().map_err(SourceError::Io)?;
    let temp_root = temp_dir.path().to_path_buf();
    let worker_count = crate::parallel_fetch::REMOTE_API_FETCH_THREADS.min(repos.len());
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    let profile_runtime = crate::profile::current_runtime();
    let (jobs, pending_jobs) = crossbeam_channel::unbounded();
    let mut receivers = Vec::with_capacity(repos.len());
    for repo in repos {
        let (output, receiver) = std::sync::mpsc::sync_channel(1);
        let _ = jobs.send((repo, output)); // LAW10: the unbounded job receiver is retained until after enqueueing, so this send cannot fail during normal construction.
        receivers.push(receiver);
    }
    drop(jobs);

    std::thread::scope(|scope| {
        for _ in 0..worker_count {
            let pending_jobs = pending_jobs.clone();
            let worker_lease = (*scan_lease).clone();
            let profile_runtime = profile_runtime.clone();
            let cancelled = &cancelled;
            let temp_root = &temp_root;
            scope.spawn(move || {
                let _attributed = worker_lease.enter();
                let _profile_guard = profile_runtime.as_ref().map(|runtime| runtime.enter());
                while !cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                    let Ok((repo, output)) = pending_jobs.recv() else {
                        break;
                    };
                    let mut send = |chunk| {
                        !cancelled.load(std::sync::atomic::Ordering::Relaxed)
                            && output.send(Ok(chunk)).is_ok()
                    };
                    match scan_single_hosted_repo_into(
                        platform,
                        source_type,
                        namespace,
                        token_username,
                        token_secret,
                        expected_clone_origin,
                        repo,
                        temp_root,
                        limits,
                        respect_default_excludes,
                        &mut send,
                    ) {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(error) => {
                            let _ = output.send(Err(repo_unreadable_error(
                                // LAW10: a failed send means this repository's result consumer is already closed; no recipient remains.
                                platform,
                                &repo.display_path,
                                error,
                            )));
                        }
                    }
                }
            });
        }

        let mut accepting = true;
        for receiver in receivers {
            while let Ok(row) = receiver.recv() {
                if accepting && !emit(row) {
                    accepting = false;
                    cancelled.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
    });
    Ok(())
}

#[cfg(test)]
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

fn scan_single_hosted_repo_into(
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
    emit: &mut impl FnMut(Chunk) -> bool,
) -> Result<bool, SourceError> {
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
        limits,
    )?;
    scan_repo_into(
        platform,
        source_type,
        namespace,
        &repo.display_path,
        &clone_path,
        limits,
        respect_default_excludes,
        emit,
    )
}

fn repo_unreadable_error(
    platform: &str,
    repo_display_path: &str,
    error: SourceError,
) -> SourceError {
    if matches!(
        error,
        SourceError::Coverage {
            kind: SourceCoverageGapKind::Truncated,
            ..
        }
    ) {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::SourceTruncated);
        return error;
    }
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
#[path = "../tests/unit/hosted_git.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/unit/hosted_git_materialization.rs"]
mod materialization_tests;

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
    let loopback_http = parsed.scheme() == "http"
        && parsed.host_str().is_some_and(|host| {
            host.parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        });
    if parsed.scheme() != "https" && !loopback_http {
        return Err(SourceError::Other(format!(
            "{platform}: refusing clone URL that is neither https nor literal loopback http (potential ext::/ssh:// RCE vector): {redacted:?}"
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
        Err(_) => u64::MAX, // LAW10: unreachable on real platforms, only a usize wider than u64 takes this arm, where reqwest content lengths and Read::take caps are u64-bounded, so every representable HTTP body length is still capped.
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

/// Validate an operator-supplied hosted-git API endpoint (`--github-api-endpoint`,
/// `--gitlab-endpoint`, `--bitbucket-endpoint`) before any socket opens.
///
/// Shape rules: https only, or plain http to a loopback host for local testing;
/// never embedded credentials, a query, or a fragment.
///
/// Destination policy: unless the operator opted into private endpoints
/// (`HttpClientConfig::allow_private_endpoint`, i.e. the CLI's
/// `--allow-private-cloud-endpoint`), the host must survive the same
/// `crate::endpoint_screen` SSRF gate the cloud object stores and WebSource use.
/// Without it a self-hosted endpoint aimed at `127.0.0.1`, `10.0.0.5`,
/// `169.254.169.254`, or a public name that *resolves* to one of those was
/// accepted, and the operator's GitHub/GitLab/Bitbucket credential was carried to it.
#[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
pub(crate) fn validated_api_endpoint(
    platform: &str,
    endpoint: &str,
    allow_private_endpoint: bool,
) -> Result<
    (
        reqwest::Url,
        Option<crate::endpoint_screen::ScreenedEndpoint>,
    ),
    SourceError,
> {
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
        "https" => {}
        "http" if url.host_str().is_some_and(is_loopback_host) => {}
        scheme => {
            return Err(SourceError::Other(format!(
                "{platform}: refusing {scheme:?} API endpoint {safe_endpoint:?}; use https, or loopback http only for local tests"
            )))
        }
    }
    let screened = if allow_private_endpoint {
        None
    } else {
        crate::endpoint_screen::screen_endpoint_host(&url, platform)?
    };
    Ok((url, screened))
}

#[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
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
    let cutoff = redacted.find(['?', '#']).unwrap_or(redacted.len()); // LAW10: display-only, malformed endpoint diagnostics keep only the non-secret prefix
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
    rewrite_repo_chunks_into(
        input_chunks,
        platform,
        source_type,
        namespace,
        repo_display_path,
        clone_path,
        &mut |chunk| {
            rewritten.push(chunk);
            true
        },
    )?;
    Ok(rewritten)
}

fn rewrite_repo_chunks_into<I>(
    input_chunks: I,
    platform: &str,
    source_type: &str,
    namespace: Option<&str>,
    repo_display_path: &str,
    clone_path: &Path,
    emit: &mut impl FnMut(Chunk) -> bool,
) -> Result<bool, SourceError>
where
    I: IntoIterator<Item = Result<Chunk, SourceError>>,
{
    for chunk in input_chunks {
        let chunk = match chunk {
            Ok(chunk) => rewrite_chunk_path(
                chunk,
                platform,
                source_type,
                namespace,
                repo_display_path,
                clone_path,
            )?,
            Err(error) => {
                return Err(SourceError::Other(format!(
                    "{platform}: failed to scan cloned repo {repo_display_path}: {error}"
                )));
            }
        };
        if !emit(chunk) {
            return Ok(false);
        }
    }
    Ok(true)
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
    limits: crate::SourceLimits,
) -> Result<(), SourceError> {
    clone_repo_with_history_mode(
        platform,
        repo_display_path,
        clone_url,
        token_username,
        token_secret,
        clone_path,
        false,
        limits,
    )
}

pub(crate) fn clone_authenticated_history(
    platform: &str,
    repo_display_path: &str,
    clone_url: &str,
    token_username: &str,
    token_secret: &str,
    clone_path: &Path,
    limits: crate::SourceLimits,
) -> Result<(), SourceError> {
    clone_repo_with_history_mode(
        platform,
        repo_display_path,
        clone_url,
        token_username,
        token_secret,
        clone_path,
        true,
        limits,
    )
}

fn clone_repo_with_history_mode(
    platform: &str,
    repo_display_path: &str,
    clone_url: &str,
    token_username: &str,
    token_secret: &str,
    clone_path: &Path,
    full_history: bool,
    limits: crate::SourceLimits,
) -> Result<(), SourceError> {
    // Cloning one hosted repo (object fetch over the git protocol) is an
    // acquisition boundary.
    let _clone = crate::profile::acquire_span();
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
    // clone on a prompt) and resolves the trusted git binary, the exact
    // isolation every other git spawn uses. `git_command()`'s own doc requires
    // that "every git spawn goes through here rather than Command::new(git_bin)";
    // this clone was the one bypass. The auth-specific askpass is layered on top.
    let mut command = crate::git::git_command()?;
    command
        .env("GIT_ASKPASS", &auth_material.askpass_path)
        .env("SSH_ASKPASS", &auth_material.askpass_path);
    if full_history {
        command.args(git_full_clone_args());
    } else {
        command.args(git_clone_args());
    }
    let mut child = command
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

    let materialization_guard =
        CloneMaterializationGuard::new(clone_path, limits.git_total_bytes, limits.git_chunk_count);
    let output = wait_for_command_with_timeout(
        child,
        stdout_drain,
        stderr_drain,
        crate::timeouts::GIT_CLONE,
        materialization_guard,
    )
    .map_err(|error| match error {
        HostedGitWaitError::MaterializationCap { cap, cleanup_error } => {
            clone_materialization_truncated(
                platform,
                repo_display_path,
                cap,
                cleanup_error.as_deref(),
            )
        }
        HostedGitWaitError::Command(detail) => {
            SourceError::Git(format!("failed to clone {repo_display_path}: {detail}"))
        }
    })?;

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

fn git_full_clone_args() -> [&'static str; 8] {
    [
        "-c",
        "http.followRedirects=false",
        "-c",
        "credential.helper=",
        "-c",
        "credential.useHttpPath=true",
        "clone",
        "--quiet",
    ]
}

fn scan_repo_into(
    platform: &str,
    source_type: &str,
    namespace: Option<&str>,
    repo_display_path: &str,
    clone_path: &Path,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
    emit: &mut impl FnMut(Chunk) -> bool,
) -> Result<bool, SourceError> {
    let source = FilesystemSource::new(clone_path.to_path_buf())
        .with_max_file_size(limits.git_blob_bytes)
        .with_default_excludes(respect_default_excludes);
    rewrite_repo_chunks_into(
        source.chunks(),
        platform,
        source_type,
        namespace,
        repo_display_path,
        clone_path,
        emit,
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

#[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}
