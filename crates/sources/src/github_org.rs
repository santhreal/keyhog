//! GitHub organization source: clones and scans all repositories in a GitHub
//! organization via the GitHub API.

use std::thread;

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
pub struct GitHubOrgSource {
    org: String,
    token: String,
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
            http: crate::http::HttpClientConfig {
                ua_suffix: Some("github-org".into()),
                ..Default::default()
            },
            limits: crate::SourceLimits::default(),
            respect_default_excludes: true,
        }
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
        // `reqwest::blocking` must not be driven from inside the CLI's
        // `#[tokio::main]` runtime: the blocking client spins its own internal
        // runtime, and dropping that within an async context aborts the whole
        // process ("Cannot drop a runtime in a context where blocking is not
        // allowed" -> SIGABRT). Collection is already eager, so run it on a
        // scoped std thread, which carries no ambient tokio runtime; the
        // blocking client builds, fetches, and drops there safely, and a fetch
        // failure (bad org/token, unreachable API) surfaces as an `Err` chunk
        // the orchestrator turns into a non-zero exit instead of a crash.
        // Hold the scan read lease across the synchronous fetch so a
        // counter-asserting test's exclusive scope serializes this source's skip
        // recording (unreachable API / bad token). A no-op in production where the
        // gate is never armed; see `skip::gate_scan`.
        crate::gate_scan(|| {
            let result = thread::scope(|s| {
                match s
                    .spawn(|| {
                        collect_org_chunks(
                            &self.org,
                            &self.token,
                            &self.http,
                            self.limits,
                            self.respect_default_excludes,
                        )
                    })
                    .join()
                {
                    Ok(result) => result,
                    Err(_panic) => Err(SourceError::Other(
                        "github-org fetch thread panicked".to_string(),
                    )),
                }
            });
            match result {
                Ok(rows) => Box::new(rows.into_iter()),
                Err(err) => Box::new(std::iter::once(Err(err))),
            }
        })
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Repositories requested per `/orgs/<org>/repos` page (GitHub's maximum).
///
/// Single owner for the two coupled uses: the `per_page` query parameter and
/// the "a short page means the last page" terminator (`count < PER_PAGE`).
/// Changing one without the other silently breaks pagination — either an early
/// stop that drops repos or an extra empty page — so both read this constant.
const REPOS_PER_PAGE: usize = 100;

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

fn collect_org_chunks(
    org: &str,
    token: &str,
    http: &crate::http::HttpClientConfig,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
) -> Result<Vec<Result<Chunk, SourceError>>, SourceError> {
    validate_org_name(org)?;
    let client = build_client(token, http)?;
    let repos = list_repos(
        &client,
        org,
        limits.hosted_git_pages,
        limits.web_response_bytes,
    )?;
    hosted_git::scan_hosted_repos(
        "github",
        "github-org",
        Some(org),
        "x-access-token",
        token,
        &hosted_git::ExpectedCloneOrigin::host("github.com"),
        &repos,
        limits,
        respect_default_excludes,
    )
}

fn build_client(token: &str, http: &crate::http::HttpClientConfig) -> Result<Client, SourceError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/vnd.github+json"),
    );
    // USER_AGENT is set by `blocking_client_builder` (`keyhog/<version>
    // (github-org)`). We intentionally don'"'"'t set it in default_headers -
    // reqwest's user_agent() takes precedence anyway and the duplicate
    // header would confuse GitHub'"'"'s rate-limiting which keys off UA.
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|e| SourceError::Other(format!("invalid GitHub authorization header: {e}")))?,
    );

    crate::http::blocking_client_builder(http)
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
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| SourceError::Other(format!("failed to build GitHub client: {e}")))
}

fn list_repos(
    client: &Client,
    org: &str,
    max_pages: usize,
    max_response_bytes: usize,
) -> Result<Vec<HostedRepo>, SourceError> {
    let mut repos = Vec::new();
    let mut page = 1;

    while page <= max_pages {
        let response = send_github_request_with_backoff(client, org, page)?;

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

fn send_github_request_with_backoff(
    client: &Client,
    org: &str,
    page: usize,
) -> Result<reqwest::blocking::Response, SourceError> {
    const MAX_ATTEMPTS: usize = 4;

    for attempt in 0..MAX_ATTEMPTS {
        let response = client
            .get(format!(
                "https://api.github.com/orgs/{org}/repos?per_page={REPOS_PER_PAGE}&page={page}"
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

        if attempt + 1 == MAX_ATTEMPTS {
            return Err(hosted_git::api_unreadable_error(format!(
                "GitHub API rate limited while listing repositories for org {org}"
            )));
        }

        std::thread::sleep(std::time::Duration::from_secs(
            retry_after.unwrap_or((attempt + 1) as u64), // LAW10: absent Retry-After => attempt-based backoff default; perf/timing, recall-irrelevant
        ));
    }

    Err(hosted_git::api_unreadable_error(
        "GitHub API retry limit exceeded",
    ))
}

#[cfg(test)]
mod pagination_tests {
    use super::REPOS_PER_PAGE;

    #[test]
    fn repos_per_page_is_github_max_and_drives_the_query() {
        // GitHub's documented maximum page size. The list-repos loop pages with
        // this value AND treats a page shorter than it as the last page, so this
        // is the single owner both uses must read.
        assert_eq!(REPOS_PER_PAGE, 100);
        let url = format!(
            "https://api.github.com/orgs/acme/repos?per_page={REPOS_PER_PAGE}&page=1"
        );
        assert_eq!(
            url,
            "https://api.github.com/orgs/acme/repos?per_page=100&page=1"
        );
    }
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
