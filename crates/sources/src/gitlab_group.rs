//! GitLab group source: clone and scan every project in a GitLab group.

use std::thread;

use keyhog_core::{Chunk, Source, SourceError};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT};
use serde::Deserialize;

use crate::hosted_git::{self, HostedRepo};

const DEFAULT_ENDPOINT: &str = "https://gitlab.com";

/// Single owner of the missing-required-field diagnostic. `source_from_params`
/// reports the same shortfall from three branches (too few `\n`-separated fields,
/// or either of group/token empty); one const keeps the operator-facing wording
/// identical across every branch instead of pasting it inline three times.
const MISSING_REQUIRED_FIELDS_ERROR: &str = "gitlab-group source requires group and token";
const PRIVATE_TOKEN: HeaderName = HeaderName::from_static("private-token");

pub(crate) struct GitLabGroupSource {
    group: String,
    token: String,
    endpoint: String,
    http: crate::http::HttpClientConfig,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
}

impl GitLabGroupSource {
    pub(crate) fn new(group: String, token: String) -> Self {
        Self {
            group,
            token,
            endpoint: DEFAULT_ENDPOINT.into(),
            http: crate::http::HttpClientConfig {
                ua_suffix: Some("gitlab-group".into()),
                ..Default::default()
            },
            limits: crate::SourceLimits::default(),
            respect_default_excludes: true,
        }
    }

    pub(crate) fn with_endpoint(mut self, endpoint: String) -> Self {
        self.endpoint = endpoint;
        self
    }

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

impl Source for GitLabGroupSource {
    fn name(&self) -> &str {
        "gitlab-group"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        // Hold the scan read lease across the synchronous fetch so a
        // counter-asserting test's exclusive scope serializes this source's skip
        // recording (unreachable API / bad token). A no-op in production where the
        // gate is never armed; see `skip::gate_scan`.
        crate::gate_scan(|| {
            let result = thread::scope(|s| {
                match s
                    .spawn(|| {
                        collect_group_chunks(
                            &self.group,
                            &self.token,
                            &self.endpoint,
                            &self.http,
                            self.limits,
                            self.respect_default_excludes,
                        )
                    })
                    .join()
                {
                    Ok(result) => result,
                    Err(_panic) => Err(SourceError::Other(
                        "gitlab-group fetch thread panicked".to_string(),
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

#[derive(Debug, Deserialize)]
struct GitLabProject {
    path_with_namespace: String,
    http_url_to_repo: String,
}

fn collect_group_chunks(
    group: &str,
    token: &str,
    endpoint: &str,
    http: &crate::http::HttpClientConfig,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
) -> Result<Vec<Result<Chunk, SourceError>>, SourceError> {
    validate_group_path(group)?;
    let api_root = normalize_gitlab_api_root(endpoint)?;
    let client = build_client(token, http)?;
    let repos = list_projects(
        &client,
        &api_root,
        group,
        limits.hosted_git_pages,
        limits.web_response_bytes,
    )?;
    let expected_clone_origin = hosted_git::ExpectedCloneOrigin::from_api_root(&api_root)?;
    hosted_git::scan_hosted_repos(
        "gitlab",
        "gitlab-group",
        None,
        "oauth2",
        token,
        &expected_clone_origin,
        &repos,
        limits,
        respect_default_excludes,
    )
}

fn build_client(token: &str, http: &crate::http::HttpClientConfig) -> Result<Client, SourceError> {
    validate_token(token)?;
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(
        PRIVATE_TOKEN,
        HeaderValue::from_str(token)
            .map_err(|e| SourceError::Other(format!("invalid GitLab private-token header: {e}")))?,
    );

    crate::http::blocking_client_builder(http)
        .map_err(SourceError::Other)?
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| SourceError::Other(format!("failed to build GitLab client: {e}")))
}

fn list_projects(
    client: &Client,
    api_root: &reqwest::Url,
    group: &str,
    max_pages: usize,
    max_response_bytes: usize,
) -> Result<Vec<HostedRepo>, SourceError> {
    let mut repos = Vec::new();
    let encoded_group = urlencoding::encode(group);

    for page in 1..=max_pages {
        let mut url = api_root.clone();
        url.set_path(&format!(
            "{}/groups/{}/projects",
            api_root.path().trim_end_matches('/'),
            encoded_group
        ));
        url.set_query(Some(&format!(
            "include_subgroups=true&simple=true&per_page=100&page={page}"
        )));

        let response = client.get(url).send().map_err(|e| {
            hosted_git::api_unreadable_error(format!("GitLab API request failed: {e}"))
        })?;
        if !response.status().is_success() {
            return Err(hosted_git::api_unreadable_error(format!(
                "GitLab API returned {} while listing projects for group {group}",
                response.status()
            )));
        }

        let projects: Vec<GitLabProject> =
            hosted_git::read_api_json(response, "GitLab API response", max_response_bytes)?;
        let count = projects.len();
        for project in projects {
            repos.push(HostedRepo {
                clone_dir_name: format!("repo-{}", repos.len()),
                display_path: project.path_with_namespace,
                clone_url: project.http_url_to_repo,
            });
        }

        if count < 100 {
            return Ok(repos);
        }
    }

    Err(hosted_git::listing_truncated_error(
        "GitLab",
        "group",
        group,
        repos.len(),
        max_pages,
    ))
}

fn normalize_gitlab_api_root(endpoint: &str) -> Result<reqwest::Url, SourceError> {
    let trimmed = endpoint.trim_end_matches('/');
    let root = if trimmed.ends_with("/api/v4") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/api/v4")
    };
    hosted_git::validated_api_endpoint("gitlab", &root)
}

pub(crate) fn validate_group_path(group: &str) -> Result<(), SourceError> {
    if group.is_empty() || group.len() > 512 || group.starts_with('/') || group.ends_with('/') {
        return Err(SourceError::Other(format!(
            "gitlab: refusing group path with invalid length or slash placement: {group:?}"
        )));
    }
    for segment in group.split('/') {
        hosted_git::validate_repo_name("gitlab", segment)?;
    }
    Ok(())
}

fn validate_token(token: &str) -> Result<(), SourceError> {
    if token.is_empty() || token.chars().any(char::is_control) {
        return Err(SourceError::Other(
            "gitlab token contains unsafe characters".into(),
        ));
    }
    Ok(())
}

pub(crate) fn source_from_params(
    params: &str,
    http: crate::http::HttpClientConfig,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
) -> Result<GitLabGroupSource, SourceError> {
    let mut parts = params.splitn(3, '\n');
    let Some(group) = parts.next() else {
        return Err(SourceError::Other(MISSING_REQUIRED_FIELDS_ERROR.into()));
    };
    let Some(token) = parts.next() else {
        return Err(SourceError::Other(MISSING_REQUIRED_FIELDS_ERROR.into()));
    };
    let endpoint = match parts.next() {
        Some(endpoint) if !endpoint.is_empty() => endpoint,
        Some(_) | None => DEFAULT_ENDPOINT,
    };
    if group.is_empty() || token.is_empty() {
        return Err(SourceError::Other(MISSING_REQUIRED_FIELDS_ERROR.into()));
    }
    Ok(GitLabGroupSource::new(group.to_string(), token.to_string())
        .with_endpoint(endpoint.to_string())
        .with_http_config(http)
        .with_limits(limits)
        .with_default_excludes(respect_default_excludes))
}

pub(crate) fn listing_truncated_error_for_test(
    group: &str,
    repo_count: usize,
    max_pages: usize,
) -> SourceError {
    hosted_git::listing_truncated_error("GitLab", "group", group, repo_count, max_pages)
}

#[cfg(test)]
mod tests {
    use super::{source_from_params, validate_token};

    #[test]
    fn validate_token_rejects_control_chars_and_empty() {
        // A clean PAT passes (a benign non-credential-shaped value — never a
        // `glpat-`-prefixed literal, which self-scan would flag).
        assert!(validate_token("clean-token-value").is_ok());

        // Control characters (CR/LF/NUL/TAB/DEL) are banned: raw bytes injected
        // into the `PRIVATE-TOKEN: …` request header enable CRLF header/request
        // splitting. Every reject carries the shared 'unsafe characters' contract.
        for bad in ["a\rb", "a\nb", "a\0b", "a\tb", "a\u{7f}b"] {
            let err = validate_token(bad).expect_err("control char rejected");
            assert!(
                err.to_string().contains("unsafe characters"),
                "gitlab token control-char error must carry the shared contract, got {err}"
            );
        }

        // Empty token is rejected (an unauthenticated request pre-image).
        assert!(validate_token("").is_err(), "empty token rejected");
    }

    #[test]
    fn source_from_params_requires_group_and_token() {
        // `HttpClientConfig` moves into each call; build a fresh default per call.
        // `SourceLimits` is `Copy`.
        let cfg = || crate::http::HttpClientConfig::default();
        let limits = crate::SourceLimits::default();

        // Fewer than two newline-separated fields → error (missing token).
        assert!(
            source_from_params("acme", cfg(), limits, true).is_err(),
            "missing token line must be an error"
        );
        // Present-but-EMPTY fields hit the explicit empty-field guard → error.
        assert!(
            source_from_params("acme\n", cfg(), limits, true).is_err(),
            "empty token must be an error"
        );
        assert!(
            source_from_params("\ntok", cfg(), limits, true).is_err(),
            "empty group must be an error"
        );
        // Two non-empty fields parse; endpoint defaults when the 3rd field is
        // absent OR present-but-empty (the `Some(_) if !empty` else-arm), not error.
        assert!(
            source_from_params("acme\ntok", cfg(), limits, true).is_ok(),
            "group + token parse successfully"
        );
        assert!(
            source_from_params("acme\ntok\n", cfg(), limits, true).is_ok(),
            "trailing empty endpoint line falls back to the default endpoint"
        );
        assert!(
            source_from_params(
                "acme\ntok\nhttps://gitlab.example.test",
                cfg(),
                limits,
                true
            )
            .is_ok(),
            "an explicit 3rd endpoint field parses"
        );
    }
}
