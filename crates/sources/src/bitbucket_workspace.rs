//! Bitbucket Cloud workspace source: clone and scan every repository in a workspace.

use std::thread;

use base64::Engine as _;
use keyhog_core::{Chunk, Source, SourceError};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION};
use serde::Deserialize;

use crate::hosted_git::{self, HostedRepo};

const DEFAULT_ENDPOINT: &str = "https://api.bitbucket.org/2.0";

/// Single owner of the missing-required-field diagnostic. `source_from_params`
/// reports the same shortfall from four branches (too few `\n`-separated fields,
/// or any of workspace/username/token empty); one const keeps the operator-facing
/// wording identical across every branch instead of pasting it inline four times.
const MISSING_REQUIRED_FIELDS_ERROR: &str =
    "bitbucket-workspace source requires workspace, username, and app password";

pub(crate) struct BitbucketWorkspaceSource {
    workspace: String,
    username: String,
    token: String,
    endpoint: String,
    http: crate::http::HttpClientConfig,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
}

impl BitbucketWorkspaceSource {
    pub(crate) fn new(workspace: String, username: String, token: String) -> Self {
        Self {
            workspace,
            username,
            token,
            endpoint: DEFAULT_ENDPOINT.into(),
            http: crate::http::HttpClientConfig {
                ua_suffix: Some("bitbucket-workspace".into()),
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

impl Source for BitbucketWorkspaceSource {
    fn name(&self) -> &str {
        "bitbucket-workspace"
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
                        collect_workspace_chunks(
                            &self.workspace,
                            &self.username,
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
                        "bitbucket-workspace fetch thread panicked".to_string(),
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
struct BitbucketPage {
    values: Vec<BitbucketRepo>,
    next: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BitbucketRepo {
    slug: String,
    links: BitbucketLinks,
}

#[derive(Debug, Deserialize)]
struct BitbucketLinks {
    clone: Vec<BitbucketCloneLink>,
}

#[derive(Debug, Deserialize)]
struct BitbucketCloneLink {
    name: String,
    href: String,
}

fn collect_workspace_chunks(
    workspace: &str,
    username: &str,
    token: &str,
    endpoint: &str,
    http: &crate::http::HttpClientConfig,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
) -> Result<Vec<Result<Chunk, SourceError>>, SourceError> {
    validate_workspace(workspace)?;
    validate_basic_auth(username, token)?;
    let api_root = hosted_git::validated_api_endpoint("bitbucket", endpoint)?;
    let client = build_client(username, token, http)?;
    let (repos, listing_errors) = list_repositories(
        &client,
        &api_root,
        workspace,
        limits.hosted_git_pages,
        limits.web_response_bytes,
    )?;
    let expected_clone_origin = hosted_git::ExpectedCloneOrigin::bitbucket(&api_root)?;
    let mut rows = hosted_git::scan_hosted_repos(
        "bitbucket",
        "bitbucket-workspace",
        Some(workspace),
        username,
        token,
        &expected_clone_origin,
        &repos,
        limits,
        respect_default_excludes,
    )?;
    rows.extend(listing_errors.into_iter().map(Err));
    Ok(rows)
}

fn build_client(
    username: &str,
    token: &str,
    http: &crate::http::HttpClientConfig,
) -> Result<Client, SourceError> {
    validate_basic_auth(username, token)?;
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{token}"));
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Basic {encoded}")).map_err(|e| {
            SourceError::Other(format!("invalid Bitbucket authorization header: {e}"))
        })?,
    );

    crate::http::blocking_client_builder(http)
        .map_err(SourceError::Other)?
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| SourceError::Other(format!("failed to build Bitbucket client: {e}")))
}

fn list_repositories(
    client: &Client,
    api_root: &reqwest::Url,
    workspace: &str,
    max_pages: usize,
    max_response_bytes: usize,
) -> Result<(Vec<HostedRepo>, Vec<SourceError>), SourceError> {
    let mut repos = Vec::new();
    let mut listing_errors = Vec::new();
    let mut url = api_root.clone();
    url.set_path(&format!(
        "{}/repositories/{workspace}",
        api_root.path().trim_end_matches('/')
    ));
    url.set_query(Some("pagelen=100"));

    for _page in 1..=max_pages {
        let response = client.get(url.clone()).send().map_err(|e| {
            hosted_git::api_unreadable_error(format!("Bitbucket API request failed: {e}"))
        })?;
        if !response.status().is_success() {
            return Err(hosted_git::api_unreadable_error(format!(
                "Bitbucket API returned {} while listing repositories for workspace {workspace}",
                response.status()
            )));
        }

        let page: BitbucketPage =
            hosted_git::read_api_json(response, "Bitbucket API response", max_response_bytes)?;
        for repo in page.values {
            let slug = repo.slug.clone();
            let clone_url = match repo_https_clone_url(repo) {
                Ok(clone_url) => clone_url,
                Err(error) => {
                    listing_errors.push(hosted_git::repo_listing_unreadable_error(
                        "bitbucket",
                        &slug,
                        error,
                    ));
                    continue;
                }
            };
            repos.push(HostedRepo {
                clone_dir_name: format!("repo-{}", repos.len()),
                display_path: slug,
                clone_url,
            });
        }

        let Some(next) = page.next else {
            return Ok((repos, listing_errors));
        };
        let next_url = reqwest::Url::parse(&next).map_err(|e| {
            hosted_git::api_unreadable_error(format!("bitbucket: invalid next page URL: {e}"))
        })?;
        hosted_git::require_same_api_origin("bitbucket", api_root, &next_url)?;
        url = next_url;
    }

    Err(hosted_git::listing_truncated_error(
        "Bitbucket",
        "workspace",
        workspace,
        repos.len() + listing_errors.len(),
        max_pages,
    ))
}

fn repo_https_clone_url(repo: BitbucketRepo) -> Result<String, SourceError> {
    let slug = repo.slug;
    repo.links
        .clone
        .into_iter()
        .find(|link| link.name == "https")
        .map(|link| link.href)
        .ok_or_else(|| {
            SourceError::Other(format!(
                "bitbucket: repository {:?} did not include an HTTPS clone link",
                slug
            ))
        })
}

pub(crate) fn validate_workspace(workspace: &str) -> Result<(), SourceError> {
    hosted_git::validate_repo_name("bitbucket", workspace)
}

fn validate_basic_auth(username: &str, token: &str) -> Result<(), SourceError> {
    if username.is_empty()
        || token.is_empty()
        || username.contains(':')
        || username.chars().any(char::is_control)
        || token.chars().any(char::is_control)
    {
        return Err(SourceError::Other(
            "bitbucket username/app-password contains unsafe characters".into(),
        ));
    }
    Ok(())
}

pub(crate) fn source_from_params(
    params: &str,
    http: crate::http::HttpClientConfig,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
) -> Result<BitbucketWorkspaceSource, SourceError> {
    let mut parts = params.splitn(4, '\n');
    let Some(workspace) = parts.next() else {
        return Err(SourceError::Other(MISSING_REQUIRED_FIELDS_ERROR.into()));
    };
    let Some(username) = parts.next() else {
        return Err(SourceError::Other(MISSING_REQUIRED_FIELDS_ERROR.into()));
    };
    let Some(token) = parts.next() else {
        return Err(SourceError::Other(MISSING_REQUIRED_FIELDS_ERROR.into()));
    };
    let endpoint = match parts.next() {
        Some(endpoint) if !endpoint.is_empty() => endpoint,
        Some(_) | None => DEFAULT_ENDPOINT,
    };
    if workspace.is_empty() || username.is_empty() || token.is_empty() {
        return Err(SourceError::Other(MISSING_REQUIRED_FIELDS_ERROR.into()));
    }
    Ok(BitbucketWorkspaceSource::new(
        workspace.to_string(),
        username.to_string(),
        token.to_string(),
    )
    .with_endpoint(endpoint.to_string())
    .with_http_config(http)
    .with_limits(limits)
    .with_default_excludes(respect_default_excludes))
}

pub(crate) fn listing_truncated_error_for_test(
    workspace: &str,
    repo_count: usize,
    max_pages: usize,
) -> SourceError {
    hosted_git::listing_truncated_error("Bitbucket", "workspace", workspace, repo_count, max_pages)
}

#[cfg(test)]
#[path = "../tests/unit/bitbucket_workspace.rs"]
mod tests;
