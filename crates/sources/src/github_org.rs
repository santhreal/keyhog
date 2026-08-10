//! GitHub organization source: clones and scans all repositories in a GitHub
//! organization via the GitHub API.

use keyhog_core::{Chunk, Source, SourceError};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION};
use serde::Deserialize;

use crate::hosted_git::{self, HostedRepo};

/// Scans all repositories in a GitHub organization by shallow-cloning them to a temp directory.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::Source;
/// use keyhog_sources::GitHubOrgSource;
///
/// let source = GitHubOrgSource::new("acme".into(), "ghp_example".into());
/// assert_eq!(source.name(), "github-org");
/// ```
#[derive(Clone)]
pub struct GitHubOrgSource {
    org: String,
    token: String,
    endpoint: String,
    /// Shared HTTP policy (proxy, insecure_tls, ua_suffix, timeout). Defaults
    /// to `HttpClientConfig::default()`. Set via `with_http_config` so the
    /// CLI's `--proxy` / `--insecure` reach the GitHub API client; without
    /// this every `/orgs/<org>/repos` call would silently bypass the
    /// configured corporate proxy.
    http: crate::http::HttpClientConfig,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
}

impl GitHubOrgSource {
    /// Create a source that scans all repositories in a GitHub organization.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::Source;
    /// use keyhog_sources::GitHubOrgSource;
    ///
    /// let source = GitHubOrgSource::new("acme".into(), "ghp_example".into());
    /// assert_eq!(source.name(), "github-org");
    /// ```
    pub fn new(org: String, token: String) -> Self {
        Self {
            org,
            token,
            endpoint: "https://api.github.com".into(),
            http: crate::http::HttpClientConfig {
                ua_suffix: Some("github-org".into()),
                ..Default::default()
            },
            limits: crate::SourceLimits::default(),
            respect_default_excludes: true,
        }
    }

    pub(crate) fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into().trim_end_matches('/').to_string();
        self
    }

    /// Override the shared HTTP policy. Threads CLI `--proxy` / `--insecure`
    /// into the GitHub API client.
    pub(crate) fn with_http_config(mut self, http: crate::http::HttpClientConfig) -> Self {
        self.http = http;
        self
    }

    pub(crate) fn with_limits(mut self, limits: crate::SourceLimits) -> Self {
        self.limits = limits;
        self
    }

    pub(crate) fn with_default_excludes(mut self, respect_default_excludes: bool) -> Self {
        self.respect_default_excludes = respect_default_excludes;
        self
    }
}

impl Source for GitHubOrgSource {
    fn name(&self) -> &str {
        "github-org"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        let lease = crate::acquire_scan_read_lease();
        let source = self.clone();
        let worker_lease = lease.clone();
        let profile_runtime = crate::profile::current_runtime();
        let stream = crate::parallel_fetch::RemoteChunkStream::spawn(
            "keyhog-github-org",
            "github-org",
            worker_lease,
            move |sender, worker_lease| {
                let _attributed = worker_lease.enter();
                let _profile_guard = profile_runtime.as_ref().map(|runtime| runtime.enter());
                let result = stream_org_chunks(
                    &source.org,
                    &source.token,
                    &source.endpoint,
                    &source.http,
                    source.limits,
                    source.respect_default_excludes,
                    &worker_lease,
                    |row| sender.send(row).is_ok(),
                );
                if let Err(error) = result {
                    let _ = sender.send(Err(error)); // LAW10: a failed send means the stream consumer is already closed; no recipient remains for this source error.
                }
            },
        );
        match stream {
            Ok(stream) => crate::attach_scan_lease(lease, Box::new(stream)),
            Err(error) => crate::attach_scan_lease(lease, Box::new(std::iter::once(Err(error)))),
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Repositories requested per `/orgs/<org>/repos` page (GitHub's maximum).
///
/// Single owner for the two coupled uses: the `per_page` query parameter and
/// the "a short page means the last page" terminator (`count < PER_PAGE`).
/// Changing one without the other silently breaks pagination, either an early
/// stop that drops repos or an extra empty page (so both read this constant).
pub(crate) const REPOS_PER_PAGE: usize = 100;

#[derive(Debug, Deserialize)]
struct GitHubRepo {
    name: String,
    clone_url: String,
}

/// Refuse repo names that escape the temp clone root: `..`, absolute
/// paths, anything with a path separator, or anything but the GitHub
/// repo-name alphabet ([A-Za-z0-9._-], 1..=100 chars). Closes a
/// path-traversal vector where a compromised API response can drive
/// `temp_root.join(&repo.name)` outside the temp dir.
pub(crate) fn validate_repo_name(name: &str) -> Result<(), SourceError> {
    hosted_git::validate_repo_name("github", name)
}

/// Refuse organization names that can alter the GitHub API URL path or query.
/// GitHub org/user names are ASCII alphanumeric with interior hyphens, up to
/// 39 bytes. This keeps `list_repos` from interpolating slashes, `?`, `#`, or
/// control bytes into the request URL.
pub(crate) fn validate_org_name(name: &str) -> Result<(), SourceError> {
    if name.is_empty() || name.len() > 39 {
        return Err(SourceError::Other(format!(
            "github: refusing org with out-of-range name length ({})",
            name.len()
        )));
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err(SourceError::Other(format!(
            "github: refusing org with leading/trailing hyphen: {name:?}"
        )));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(SourceError::Other(format!(
            "github: refusing org with unsafe characters: {name:?}"
        )));
    }
    Ok(())
}

/// Refuse clone URLs that git would interpret as anything other than
/// an https GitHub clone. `ext::`, `ssh://`, file paths, and any other
/// scheme are arbitrary-code-execution gadgets in git's transport
/// negotiation. We accept only `https://<host>/...` URLs because that
/// is the only shape the GitHub API ever returns for public repos.
pub(crate) fn validate_clone_url(url: &str) -> Result<(), SourceError> {
    hosted_git::validate_clone_url_for_origin(
        "github",
        url,
        &hosted_git::ExpectedCloneOrigin::host("github.com"),
    )
}

fn stream_org_chunks(
    org: &str,
    token: &str,
    endpoint: &str,
    http: &crate::http::HttpClientConfig,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
    scan_lease: &crate::skip::ScanReadLease,
    emit: impl FnMut(Result<Chunk, SourceError>) -> bool,
) -> Result<(), SourceError> {
    validate_org_name(org)?;
    // Defense in depth with the factory: screen the API root before any socket
    // opens, matching gitlab-group / bitbucket-workspace / github-collaboration.
    let (api_root, screened) =
        hosted_git::validated_api_endpoint("github", endpoint, http.allow_private_endpoint)?;
    let endpoint = api_root.as_str().trim_end_matches('/').to_string();
    let client = build_client(token, http, screened.as_ref())?;
    let repos = {
        let _enumerate = crate::profile::acquire_span();
        list_repos(
            &client,
            org,
            &endpoint,
            limits.hosted_git_pages,
            limits.web_response_bytes,
        )?
    };
    hosted_git::stream_hosted_repos(
        "github",
        "github-org",
        Some(org),
        "x-access-token",
        token,
        &hosted_git::ExpectedCloneOrigin::from_endpoint("github", &endpoint)?,
        &repos,
        limits,
        respect_default_excludes,
        scan_lease,
        emit,
    )
}

fn build_client(
    token: &str,
    http: &crate::http::HttpClientConfig,
    screened: Option<&crate::endpoint_screen::ScreenedEndpoint>,
) -> Result<Client, SourceError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/vnd.github+json"),
    );
    // USER_AGENT is set by `blocking_client_builder` (`keyhog/<version>
    // (github-org)`). We intentionally don't set it in default_headers -
    // reqwest's user_agent() takes precedence anyway and the duplicate
    // header would confuse GitHub's rate-limiting which keys off UA.
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|e| SourceError::Other(format!("invalid GitHub authorization header: {e}")))?,
    );

    let builder = crate::http::blocking_client_builder(http)
        .map_err(SourceError::Other)?
        .default_headers(headers)
        // SECURITY: kimi-5 audit finding #3. Without an explicit redirect
        // policy, reqwest follows up to 10 redirects and re-sends the
        // Authorization: Bearer header to any same-host target. A
        // compromised api.github.com mirror or hostile GHE instance can
        // bounce us to an attacker-controlled host and capture the
        // token. The GitHub REST API never legitimately redirects
        // /orgs/.../repos, so blocking redirects entirely is the safe
        // default. `blocking_client_builder` sets a 5-hop limit by
        // default; we override to none() here because GitHub auth
        // tokens are higher-value than the average scan target.
        .redirect(reqwest::redirect::Policy::none());
    crate::endpoint_screen::pin_screened_addrs(builder, screened, http.proxy.is_some())
        .build()
        .map_err(|e| SourceError::Other(format!("failed to build GitHub client: {e}")))
}


fn list_repos(
    client: &Client,
    org: &str,
    endpoint: &str,
    max_pages: usize,
    max_response_bytes: usize,
) -> Result<Vec<HostedRepo>, SourceError> {
    let mut repos = Vec::new();
    let mut page = 1;

    while page <= max_pages {
        // One walk span per listing page.
        let _page_span = crate::profile::walk_span();
        let response = send_github_request_with_backoff(client, org, endpoint, page)?;

        if !response.status().is_success() {
            return Err(hosted_git::api_unreadable_error(format!(
                "GitHub API returned {} while listing repositories for org {org}",
                response.status()
            )));
        }

        let page_repos: Vec<GitHubRepo> =
            hosted_git::read_api_json(response, "GitHub API response", max_response_bytes)?;

        let count = page_repos.len();
        repos.extend(page_repos.into_iter().map(|repo| HostedRepo {
            clone_dir_name: repo.name.clone(),
            display_path: repo.name,
            clone_url: repo.clone_url,
        }));

        if count < REPOS_PER_PAGE {
            return Ok(repos);
        }

        page += 1;
    }

    Err(github_listing_truncated_error(org, repos.len(), max_pages))
}

fn github_listing_truncated_error(org: &str, repo_count: usize, max_pages: usize) -> SourceError {
    hosted_git::listing_truncated_error("GitHub", "organization", org, repo_count, max_pages)
}

const MAX_BACKOFF_ATTEMPTS: usize = 4;
/// Ceiling on a single rate-limit backoff sleep. `Retry-After` is an untrusted
/// response header: a hostile/compromised endpoint, a MITM under `--insecure`,
/// or a proxy returning `Retry-After: 4000000000` would otherwise wedge a scan
/// thread in `thread::sleep` effectively forever. Clamp before sleeping.
pub(crate) const MAX_BACKOFF_SECS: u64 = 60;

/// Backoff sleep (seconds) for a rate-limited attempt: the server's parsed
/// `Retry-After` if present, else attempt-based linear backoff, always clamped
/// to `MAX_BACKOFF_SECS` so an untrusted header can never wedge the thread.
pub(crate) fn rate_limit_backoff_secs(retry_after: Option<u64>, attempt: usize) -> u64 {
    retry_after
        .map_or((attempt + 1) as u64, |seconds| seconds)
        .min(MAX_BACKOFF_SECS)
}

fn send_github_request_with_backoff(
    client: &Client,
    org: &str,
    endpoint: &str,
    page: usize,
) -> Result<reqwest::blocking::Response, SourceError> {
    for attempt in 0..MAX_BACKOFF_ATTEMPTS {
        let response = client
            .get(format!(
                "{endpoint}/orgs/{org}/repos?per_page={REPOS_PER_PAGE}&page={page}"
            ))
            .send()
            .map_err(|e| {
                hosted_git::api_unreadable_error(format!("GitHub API request failed: {e}"))
            })?;

        let status = response.status();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok()) // LAW10: non-ASCII/absent header value => skipped via None (intended HTTP header parse), recall-irrelevant
            .and_then(|value| value.parse::<u64>().ok()); // LAW10: malformed input => None (fail-closed at the boundary), recall-safe
        let rate_limited = response
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|value| value.to_str().ok()) // LAW10: non-ASCII/absent header value => skipped via None (intended HTTP header parse), recall-irrelevant
            .is_some_and(|value| value == "0");

        if !(status.as_u16() == 429 || (status.as_u16() == 403 && rate_limited)) {
            return Ok(response);
        }

        if attempt + 1 == MAX_BACKOFF_ATTEMPTS {
            return Err(hosted_git::api_unreadable_error(format!(
                "GitHub API rate limited while listing repositories for org {org}"
            )));
        }

        // LAW10: absent Retry-After => attempt-based backoff; hostile/oversized
        // header clamped to MAX_BACKOFF_SECS so it can't wedge the thread.
        // Record the retry with its 1-based attempt number.
        crate::profile::record_retry(attempt as u64 + 1);
        let backoff_secs = rate_limit_backoff_secs(retry_after, attempt);
        std::thread::sleep(std::time::Duration::from_secs(backoff_secs));
    }

    Err(hosted_git::api_unreadable_error(
        "GitHub API retry limit exceeded",
    ))
}

pub(crate) fn rewrite_chunk_path_for_test(
    chunk: Chunk,
    org: &str,
    repo_name: &str,
    clone_path: &std::path::Path,
) -> Result<Chunk, SourceError> {
    hosted_git::rewrite_chunk_path(
        chunk,
        "github",
        "github-org",
        Some(org),
        repo_name,
        clone_path,
    )
}

pub(crate) fn scan_repo_chunks_for_test<I>(
    chunks: I,
    org: &str,
    repo_name: &str,
    clone_path: &std::path::Path,
) -> Result<Vec<Chunk>, SourceError>
where
    I: IntoIterator<Item = Result<Chunk, SourceError>>,
{
    hosted_git::scan_repo_chunks(
        chunks,
        "github",
        "github-org",
        Some(org),
        repo_name,
        clone_path,
    )
}

pub(crate) fn github_listing_truncated_error_for_test(
    org: &str,
    repo_count: usize,
    max_pages: usize,
) -> SourceError {
    github_listing_truncated_error(org, repo_count, max_pages)
}
