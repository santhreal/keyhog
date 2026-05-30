//! GitHub organization source: clones and scans all repositories in a GitHub
//! organization via the GitHub API.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION};
use serde::Deserialize;

use crate::FilesystemSource;

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
        }
    }

    /// Override the shared HTTP policy. Threads CLI `--proxy` / `--insecure`
    /// into the GitHub API client.
    pub fn with_http_config(mut self, http: crate::http::HttpClientConfig) -> Self {
        self.http = http;
        self
    }
}

impl Source for GitHubOrgSource {
    fn name(&self) -> &str {
        "github-org"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        match collect_org_chunks(&self.org, &self.token, &self.http) {
            Ok(chunks) => Box::new(chunks.into_iter().map(Ok)),
            Err(err) => Box::new(std::iter::once(Err(err))),
        }
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

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
    if name.is_empty() || name.len() > 100 {
        return Err(SourceError::Other(format!(
            "github: refusing repo with out-of-range name length ({})",
            name.len()
        )));
    }
    if name == "." || name == ".." || name.contains('/') || name.contains('\\') {
        return Err(SourceError::Other(format!(
            "github: refusing repo with traversal/separator in name: {name:?}"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err(SourceError::Other(format!(
            "github: refusing repo with non-alphanumeric name: {name:?}"
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
    if !url.starts_with("https://") {
        return Err(SourceError::Other(format!(
            "github: refusing non-https clone URL (potential ext::/ssh:// RCE vector): {url:?}"
        )));
    }
    if url.contains(' ') || url.contains('\n') || url.contains('\r') || url.contains('\0') {
        return Err(SourceError::Other(format!(
            "github: refusing clone URL with control characters: {url:?}"
        )));
    }
    if url.len() > 2048 {
        return Err(SourceError::Other(format!(
            "github: refusing clone URL longer than 2048 chars ({})",
            url.len()
        )));
    }
    Ok(())
}

fn collect_org_chunks(
    org: &str,
    token: &str,
    http: &crate::http::HttpClientConfig,
) -> Result<Vec<Chunk>, SourceError> {
    use rayon::prelude::*;

    let client = build_client(token, http)?;
    let repos = list_repos(&client, org)?;
    let temp_dir = tempfile::tempdir().map_err(SourceError::Io)?;
    let temp_root = temp_dir.path().to_path_buf();

    // Concurrent clone + scan: GitHub clone bandwidth is the bottleneck on
    // org scans, not the API. Eight parallel slots saturate typical
    // network links without provoking abuse-detection backoff. The previous
    // sequential `for repo in repos` loop wasted 7/8ths of the wall-clock
    // on a 200-repo org. See audits/legendary-2026-04-26.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build()
        .map_err(|e| SourceError::Other(format!("rayon pool build: {e}")))?;
    let per_repo: Vec<Result<Vec<Chunk>, SourceError>> = pool.install(|| {
        repos
            .par_iter()
            .map(|repo| -> Result<Vec<Chunk>, SourceError> {
                // SECURITY: validate repo name + clone URL BEFORE any
                // filesystem-join or process-spawn happens. A hostile
                // GitHub API response (compromised endpoint, GHE proxy)
                // could return `name = "../../etc/passwd"` (path
                // traversal - kimi-5 finding #2) or
                // `clone_url = "ext::sh -c whoami"` (git URL-scheme
                // RCE - kimi-5 finding #1). We refuse anything that
                // is not a single safe path component and an https://
                // clone URL.
                validate_repo_name(&repo.name)?;
                validate_clone_url(&repo.clone_url)?;
                let clone_path = temp_root.join(&repo.name);
                clone_repo(repo, token, &clone_path)?;
                Ok(scan_repo(org, &repo.name, &clone_path))
            })
            .collect()
    });

    let mut chunks = Vec::new();
    for result in per_repo {
        chunks.extend(result?);
    }
    Ok(chunks)
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

fn list_repos(client: &Client, org: &str) -> Result<Vec<GitHubRepo>, SourceError> {
    let mut repos = Vec::new();
    let mut page = 1;
    // Hard ceiling: GitHub returns max 100 repos/page, so 1000 pages =
    // 100k repos. No legitimate org needs to be scanned past that in a
    // single CLI invocation. Without this, a maliciously paginated
    // response (or a GitHub Enterprise instance with 10M repos) would
    // spin keyhog indefinitely.
    const MAX_PAGES: usize = 1000;

    while page <= MAX_PAGES {
        let response = send_github_request_with_backoff(client, org, page)?;

        if !response.status().is_success() {
            return Err(SourceError::Other(format!(
                "GitHub API returned {} while listing repositories for org {org}",
                response.status()
            )));
        }

        let page_repos: Vec<GitHubRepo> = response
            .json()
            .map_err(|e| SourceError::Other(format!("failed to parse GitHub API response: {e}")))?;

        let count = page_repos.len();
        repos.extend(page_repos);

        if count < 100 {
            return Ok(repos);
        }

        page += 1;
    }

    tracing::warn!(
        org = %org,
        max_pages = MAX_PAGES,
        repos = repos.len(),
        "github listing reached MAX_PAGES; truncating result set"
    );
    Ok(repos)
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
                "https://api.github.com/orgs/{org}/repos?per_page=100&page={page}"
            ))
            .send()
            .map_err(|e| SourceError::Other(format!("GitHub API request failed: {e}")))?;

        let status = response.status();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        let rate_limited = response
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value == "0");

        if !(status.as_u16() == 429 || (status.as_u16() == 403 && rate_limited)) {
            return Ok(response);
        }

        if attempt + 1 == MAX_ATTEMPTS {
            return Err(SourceError::Other(format!(
                "GitHub API rate limited while listing repositories for org {org}"
            )));
        }

        std::thread::sleep(std::time::Duration::from_secs(
            retry_after.unwrap_or((attempt + 1) as u64),
        ));
    }

    Err(SourceError::Other("GitHub API retry limit exceeded".into()))
}

fn clone_repo(repo: &GitHubRepo, token: &str, clone_path: &Path) -> Result<(), SourceError> {
    let clone_target = clone_path.to_str().ok_or_else(|| {
        SourceError::Other(format!("non-UTF-8 clone path for repo {}", repo.name))
    })?;
    let auth_material = GitAskpassAuth::create(token)?;

    // SECURITY: kimi-wave1 audit finding 3.PATH-git. Use trusted-system-bin
    // resolution; refuse falling back to $PATH lookup.
    let git_bin = keyhog_core::safe_bin::resolve_safe_bin("git").ok_or_else(|| {
        SourceError::Other(
            "git binary not found in trusted system bin dirs (refusing $PATH lookup)".into(),
        )
    })?;
    let child = Command::new(&git_bin)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", &auth_material.askpass_path)
        .env("SSH_ASKPASS", &auth_material.askpass_path)
        .args(["clone", "--depth", "1", "--quiet"])
        .arg("--end-of-options")
        .arg(&repo.clone_url)
        .arg(clone_target)
        .spawn()
        .map_err(SourceError::Io)?;

    let output = wait_for_command_with_timeout(child, crate::timeouts::GIT_CLONE)
        .map_err(|err| SourceError::Git(format!("failed to clone {}: {}", repo.name, err)))?;

    if !output.status.success() {
        return Err(SourceError::Git(format!(
            "failed to clone {}: {}",
            repo.name,
            sanitize_git_error_message(&String::from_utf8_lossy(&output.stderr))
        )));
    }

    Ok(())
}

fn wait_for_command_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output, String> {
    let start = Instant::now();
    loop {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            return child.wait_with_output().map_err(|e| e.to_string());
        }

        if start.elapsed() >= timeout {
            child.kill().map_err(|e| e.to_string())?;
            let _ = child.wait();
            return Err(format!("git clone timed out after {}s", timeout.as_secs()));
        }

        thread::sleep(Duration::from_millis(100));
    }
}

#[derive(Debug)]
struct GitAskpassAuth {
    _dir: tempfile::TempDir,
    askpass_path: PathBuf,
}

impl GitAskpassAuth {
    fn create(token: &str) -> Result<Self, SourceError> {
        validate_github_token(token)?;
        let dir = tempfile::tempdir().map_err(SourceError::Io)?;
        let token_path = dir.path().join("token");

        // Create the token file with restricted permissions.
        // On Unix, we use O_NOFOLLOW and mode 0600.
        // On Windows, we rely on tempdir creating a private directory (usually).
        {
            use std::io::Write;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);

            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }

            let mut file = options.open(&token_path).map_err(SourceError::Io)?;
            file.write_all(token.as_bytes()).map_err(SourceError::Io)?;
        }

        let askpass_path = if cfg!(unix) {
            let path = dir.path().join("askpass.sh");
            std::fs::write(
                &path,
                "#!/bin/sh\nset -eu\nTOKEN_FILE=\"$(dirname \"$0\")/token\"\ncase \"$1\" in\n*Username*) printf '%s' x-access-token ;;\n*) exec cat -- \"$TOKEN_FILE\" ;;\nesac\n",
            )
            .map_err(SourceError::Io)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                    .map_err(SourceError::Io)?;
            }
            path
        } else {
            let path = dir.path().join("askpass.bat");
            let content = format!(
                "@echo off\r\necho %1 | findstr /I \"Username\" >nul\r\nif %errorlevel% == 0 (\r\n  echo x-access-token\r\n) else (\r\n  type \"{}\"\r\n)\r\n",
                token_path.display()
            );
            std::fs::write(&path, content).map_err(SourceError::Io)?;
            path
        };

        Ok(Self {
            _dir: dir,
            askpass_path,
        })
    }
}

fn validate_github_token(token: &str) -> Result<(), SourceError> {
    if token.is_empty() || token.chars().any(char::is_control) {
        return Err(SourceError::Other(
            "github token contains unsafe characters".into(),
        ));
    }
    Ok(())
}

fn scan_repo(org: &str, repo_name: &str, clone_path: &Path) -> Vec<Chunk> {
    let source = FilesystemSource::new(clone_path.to_path_buf());
    let mut chunks = Vec::new();

    for chunk in source.chunks().flatten() {
        chunks.push(rewrite_chunk_path(chunk, org, repo_name, clone_path));
    }

    chunks
}

fn rewrite_chunk_path(mut chunk: Chunk, org: &str, repo_name: &str, clone_path: &Path) -> Chunk {
    let relative_path = chunk
        .metadata
        .path
        .as_ref()
        .and_then(|path| make_relative_path(path, clone_path));

    chunk.metadata = ChunkMetadata {
        base_offset: 0,
        source_type: "github-org".into(),
        path: relative_path.map(|relative| format!("{org}/{repo_name}/{relative}")),
        commit: None,
        author: None,
        date: None,
        mtime_ns: None,
        size_bytes: None,
    };

    chunk
}

fn make_relative_path(path: &str, clone_path: &Path) -> Option<String> {
    let normalized_path = std::fs::canonicalize(path).ok()?;
    let normalized_clone_path = std::fs::canonicalize(clone_path).ok()?;
    let relative = normalized_path
        .strip_prefix(&normalized_clone_path)
        .ok()?
        .to_path_buf();
    Some(relative.to_string_lossy().into_owned())
}

fn sanitize_git_error_message(stderr: &str) -> String {
    use std::sync::OnceLock;

    static URL_CRED_RE: OnceLock<Option<Regex>> = OnceLock::new();
    static AUTH_HEADER_RE: OnceLock<Option<Regex>> = OnceLock::new();
    static TOKEN_RE: OnceLock<Option<Regex>> = OnceLock::new();

    let url_cred =
        URL_CRED_RE.get_or_init(|| Regex::new(r"([a-z][a-z0-9+\-.]*://)([^/@\s]+)@").ok());
    let auth_header = AUTH_HEADER_RE
        .get_or_init(|| Regex::new(r"(?i)(authorization:\s*(?:basic|bearer)\s+)\S+").ok());
    let token_pat = TOKEN_RE.get_or_init(|| {
        // Tighten common token patterns to avoid over-redaction of short strings.
        Regex::new(r"(?:ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}|xoxb-[A-Za-z0-9-]{24,}|xoxp-[A-Za-z0-9-]{24,}|sk-proj-[A-Za-z0-9_-]{24,}|sk_live_[A-Za-z0-9]{24,}|sk_test_[A-Za-z0-9]{24,}|AKIA[0-9A-Z]{16})").ok()
    });

    let mut result = stderr.to_string();
    if let Some(re) = url_cred {
        result = re.replace_all(&result, "${1}<redacted>@").into_owned();
    }
    if let Some(re) = auth_header {
        result = re.replace_all(&result, "${1}<redacted>").into_owned();
    }
    if let Some(re) = token_pat {
        result = re.replace_all(&result, "<redacted-token>").into_owned();
    }
    result.trim().to_string()
}
