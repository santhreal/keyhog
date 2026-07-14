//! Bounded GitHub issue, pull request, discussion, wiki, and gist source.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::Arc;

use keyhog_core::{
    Chunk, ChunkMetadata, SensitiveString, Source, SourceCoverageGapKind, SourceError,
};
use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION};
use serde::{de::DeserializeOwned, Deserialize};

const SOURCE_NAME: &str = "github-collaboration";
const API_PAGE_SIZE: usize = 100;
const MAX_RATE_LIMIT_ATTEMPTS: usize = 4;
const MAX_RATE_LIMIT_SLEEP_SECS: u64 = 60;

/// Independently selected GitHub collaboration surfaces.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GitHubCollaborationSelection {
    pub issues: bool,
    pub pull_requests: bool,
    pub discussions: bool,
    pub wiki: bool,
    pub gists: bool,
}

impl GitHubCollaborationSelection {
    pub fn is_empty(self) -> bool {
        !(self.issues || self.pull_requests || self.discussions || self.wiki || self.gists)
    }
}

/// Scans explicitly selected GitHub collaboration surfaces for one repository.
pub struct GitHubCollaborationSource {
    owner: String,
    repo: String,
    token: String,
    selection: GitHubCollaborationSelection,
    endpoint: String,
    http: crate::http::HttpClientConfig,
    limits: crate::SourceLimits,
}

impl GitHubCollaborationSource {
    pub fn new(
        repository: impl AsRef<str>,
        token: impl Into<String>,
        selection: GitHubCollaborationSelection,
    ) -> Result<Self, SourceError> {
        let (owner, repo) = parse_repository(repository.as_ref())?;
        if selection.is_empty() {
            return Err(SourceError::Other(
                "github-collaboration requires at least one selected surface".into(),
            ));
        }
        Ok(Self {
            owner,
            repo,
            token: token.into(),
            selection,
            endpoint: "https://api.github.com".into(),
            http: crate::http::HttpClientConfig {
                ua_suffix: Some(SOURCE_NAME.into()),
                ..Default::default()
            },
            limits: crate::SourceLimits::default(),
        })
    }

    pub fn with_http_config(mut self, http: crate::http::HttpClientConfig) -> Self {
        self.http = http;
        self
    }

    pub fn with_limits(mut self, limits: crate::SourceLimits) -> Self {
        self.limits = limits;
        self
    }

    pub(crate) fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into().trim_end_matches('/').to_string();
        self
    }

    fn collect_chunks(&self) -> Result<Vec<Result<Chunk, SourceError>>, SourceError> {
        let client = build_client(&self.token, &self.http)?;
        let mut api = GitHubApi::new(
            client,
            &self.endpoint,
            self.limits.hosted_git_pages,
            self.limits.web_response_bytes,
        );
        let mut output = Vec::new();
        let mut budget = ContentBudget::new(self.limits);
        let mut seen = HashSet::new();

        if self.selection.issues {
            collect_surface("issues", &mut output, |chunks| {
                self.collect_issues(&mut api, &mut budget, &mut seen, chunks)
            });
        }
        if self.selection.pull_requests {
            collect_surface("pull-requests", &mut output, |chunks| {
                self.collect_pull_requests(&mut api, &mut budget, &mut seen, chunks)
            });
        }
        if self.selection.discussions {
            collect_surface("discussions", &mut output, |chunks| {
                self.collect_discussions(&mut api, &mut budget, &mut seen, chunks)
            });
        }
        if self.selection.wiki {
            collect_surface("wiki", &mut output, |chunks| {
                self.collect_wiki(&mut api, &mut budget, &mut seen, chunks)
            });
        }
        if self.selection.gists {
            collect_surface("gists", &mut output, |chunks| {
                self.collect_gists(&mut api, &mut budget, &mut seen, chunks)
            });
        }
        Ok(output)
    }

    fn collect_issues(
        &self,
        api: &mut GitHubApi<'_>,
        budget: &mut ContentBudget,
        seen: &mut HashSet<String>,
        chunks: &mut Vec<Chunk>,
    ) -> Result<(), GitHubGap> {
        let path = format!("/repos/{}/{}/issues", self.owner, self.repo);
        let (issues, page_gap): (Vec<Issue>, _) =
            api.pages("issues", &path, "state=all&filter=all");
        for issue in issues
            .into_iter()
            .filter(|item| item.pull_request.is_none())
        {
            let revision = revision_identity(&issue.node_id, &issue.updated_at);
            push_text_chunk(
                chunks,
                seen,
                budget,
                "issues",
                format!("issue:{revision}"),
                self.provenance(&format!("issues/{}", issue.number)),
                &revision,
                issue.user.as_ref().map(|actor| actor.login.as_str()),
                &issue.updated_at,
                join_title_body(&issue.title, issue.body.as_deref()),
            )?;
            let comments_path = format!(
                "/repos/{}/{}/issues/{}/comments",
                self.owner, self.repo, issue.number
            );
            let (comments, comments_gap): (Vec<Comment>, _) =
                api.pages("issues", &comments_path, "");
            append_comments(
                chunks,
                seen,
                budget,
                "issues",
                &self.provenance(&format!("issues/{}", issue.number)),
                comments,
            )?;
            if let Some(gap) = comments_gap {
                return Err(gap);
            }
        }
        if let Some(gap) = page_gap {
            return Err(gap);
        }
        Ok(())
    }

    fn collect_pull_requests(
        &self,
        api: &mut GitHubApi<'_>,
        budget: &mut ContentBudget,
        seen: &mut HashSet<String>,
        chunks: &mut Vec<Chunk>,
    ) -> Result<(), GitHubGap> {
        let path = format!("/repos/{}/{}/pulls", self.owner, self.repo);
        let (pulls, page_gap): (Vec<PullRequest>, _) =
            api.pages("pull-requests", &path, "state=all");
        for pull in pulls {
            let revision = revision_identity(&pull.node_id, &pull.updated_at);
            push_text_chunk(
                chunks,
                seen,
                budget,
                "pull-requests",
                format!("pull:{revision}"),
                self.provenance(&format!("pulls/{}", pull.number)),
                &revision,
                pull.user.as_ref().map(|actor| actor.login.as_str()),
                &pull.updated_at,
                join_title_body(&pull.title, pull.body.as_deref()),
            )?;
            for (kind, endpoint) in [("comments", "issues"), ("review-comments", "pulls")] {
                let comments_path = format!(
                    "/repos/{}/{}/{}/{}/comments",
                    self.owner, self.repo, endpoint, pull.number
                );
                let (comments, comments_gap): (Vec<Comment>, _) =
                    api.pages("pull-requests", &comments_path, "");
                append_comments(
                    chunks,
                    seen,
                    budget,
                    "pull-requests",
                    &self.provenance(&format!("pulls/{}/{kind}", pull.number)),
                    comments,
                )?;
                if let Some(gap) = comments_gap {
                    return Err(gap);
                }
            }
            let reviews_path = format!(
                "/repos/{}/{}/pulls/{}/reviews",
                self.owner, self.repo, pull.number
            );
            let (reviews, reviews_gap): (Vec<PullRequestReview>, _) =
                api.pages("pull-requests", &reviews_path, "");
            for review in reviews {
                let revision_time = review.submitted_at.as_deref().unwrap_or(&review.commit_id);
                let revision = revision_identity(&review.node_id, revision_time);
                push_text_chunk(
                    chunks,
                    seen,
                    budget,
                    "pull-requests",
                    format!("review:{revision}"),
                    self.provenance(&format!("pulls/{}/reviews/{}", pull.number, review.id)),
                    &revision,
                    review.user.as_ref().map(|actor| actor.login.as_str()),
                    review.submitted_at.as_deref().unwrap_or(""),
                    review.body.unwrap_or_default(),
                )?;
            }
            if let Some(gap) = reviews_gap {
                return Err(gap);
            }
        }
        if let Some(gap) = page_gap {
            return Err(gap);
        }
        Ok(())
    }

    fn collect_discussions(
        &self,
        api: &mut GitHubApi<'_>,
        budget: &mut ContentBudget,
        seen: &mut HashSet<String>,
        chunks: &mut Vec<Chunk>,
    ) -> Result<(), GitHubGap> {
        let mut cursor: Option<String> = None;
        loop {
            let response: DiscussionListData = api.graphql(
                "discussions",
                serde_json::json!({
                    "query": DISCUSSIONS_QUERY,
                    "variables": {"owner": self.owner, "repo": self.repo, "cursor": cursor}
                }),
            )?;
            let repository = response.repository.ok_or_else(|| {
                GitHubGap::inaccessible(
                    "discussions",
                    self.repository(),
                    "GitHub did not return the selected repository",
                )
            })?;
            for discussion in repository.discussions.nodes {
                let revision = revision_identity(&discussion.id, &discussion.updated_at);
                push_text_chunk(
                    chunks,
                    seen,
                    budget,
                    "discussions",
                    format!("discussion:{revision}"),
                    self.provenance(&format!("discussions/{}", discussion.number)),
                    &revision,
                    discussion.author.as_ref().map(|actor| actor.login.as_str()),
                    &discussion.updated_at,
                    join_title_body(&discussion.title, Some(&discussion.body)),
                )?;
                self.collect_discussion_comments(api, budget, seen, chunks, discussion.number)?;
            }
            if !repository.discussions.page_info.has_next_page {
                break;
            }
            cursor = repository.discussions.page_info.end_cursor;
            if cursor.is_none() {
                return Err(GitHubGap::inaccessible(
                    "discussions",
                    self.repository(),
                    "GitHub discussion pagination omitted its next cursor",
                ));
            }
        }
        Ok(())
    }

    fn collect_discussion_comments(
        &self,
        api: &mut GitHubApi<'_>,
        budget: &mut ContentBudget,
        seen: &mut HashSet<String>,
        chunks: &mut Vec<Chunk>,
        number: u64,
    ) -> Result<(), GitHubGap> {
        let mut cursor: Option<String> = None;
        loop {
            let response: DiscussionCommentsData = api.graphql(
                "discussions",
                serde_json::json!({
                    "query": DISCUSSION_COMMENTS_QUERY,
                    "variables": {
                        "owner": self.owner,
                        "repo": self.repo,
                        "number": number,
                        "cursor": cursor
                    }
                }),
            )?;
            let discussion = response
                .repository
                .and_then(|repository| repository.discussion)
                .ok_or_else(|| {
                    GitHubGap::inaccessible(
                        "discussions",
                        self.repository(),
                        format!("GitHub discussion {number} became inaccessible"),
                    )
                })?;
            for comment in discussion.comments.nodes {
                let revision = revision_identity(&comment.id, &comment.updated_at);
                push_text_chunk(
                    chunks,
                    seen,
                    budget,
                    "discussions",
                    format!("discussion-comment:{revision}"),
                    self.provenance(&format!("discussions/{number}/comments/{}", comment.id)),
                    &revision,
                    comment.author.as_ref().map(|actor| actor.login.as_str()),
                    &comment.updated_at,
                    comment.body,
                )?;
                for reply in comment.replies.nodes {
                    let revision = revision_identity(&reply.id, &reply.updated_at);
                    push_text_chunk(
                        chunks,
                        seen,
                        budget,
                        "discussions",
                        format!("discussion-reply:{revision}"),
                        self.provenance(&format!(
                            "discussions/{number}/comments/{}/replies/{}",
                            comment.id, reply.id
                        )),
                        &revision,
                        reply.author.as_ref().map(|actor| actor.login.as_str()),
                        &reply.updated_at,
                        reply.body,
                    )?;
                }
                if comment.replies.page_info.has_next_page {
                    return Err(GitHubGap::truncated(
                        "discussions",
                        self.repository(),
                        format!(
                            "discussion comment {} has more than {API_PAGE_SIZE} replies",
                            comment.id
                        ),
                    ));
                }
            }
            if !discussion.comments.page_info.has_next_page {
                return Ok(());
            }
            cursor = discussion.comments.page_info.end_cursor;
            if cursor.is_none() {
                return Err(GitHubGap::inaccessible(
                    "discussions",
                    self.repository(),
                    "GitHub discussion-comment pagination omitted its next cursor",
                ));
            }
        }
    }

    fn collect_wiki(
        &self,
        _api: &mut GitHubApi<'_>,
        budget: &mut ContentBudget,
        seen: &mut HashSet<String>,
        chunks: &mut Vec<Chunk>,
    ) -> Result<(), GitHubGap> {
        let temp = tempfile::tempdir().map_err(|_| {
            GitHubGap::inaccessible(
                "wiki",
                self.repository(),
                "could not create wiki clone directory",
            )
        })?;
        let clone_path = temp.path().join("wiki");
        let clone_url = format!("https://github.com/{}/{}.wiki.git", self.owner, self.repo);
        crate::hosted_git::clone_authenticated_history(
            "github",
            &format!("{}/{}.wiki", self.owner, self.repo),
            &clone_url,
            "x-access-token",
            &self.token,
            &clone_path,
            self.limits,
        )
        .map_err(|error| match error {
            SourceError::Coverage { kind, detail, .. } => GitHubGap {
                surface: "wiki",
                target: self.repository(),
                kind,
                detail,
            },
            _ => GitHubGap::inaccessible(
                "wiki",
                self.repository(),
                "GitHub wiki repository was unavailable or unreadable",
            ),
        })?;
        self.collect_wiki_repo(&clone_path, budget, seen, chunks)
    }

    fn collect_wiki_repo(
        &self,
        clone_path: &std::path::Path,
        budget: &mut ContentBudget,
        seen: &mut HashSet<String>,
        chunks: &mut Vec<Chunk>,
    ) -> Result<(), GitHubGap> {
        let source = crate::GitSource::new(clone_path.to_path_buf()).with_limits(self.limits);
        for row in source.chunks() {
            let mut chunk = row.map_err(|error| match error {
                SourceError::Coverage { kind, detail, .. } => GitHubGap {
                    surface: "wiki",
                    target: self.repository(),
                    kind,
                    detail,
                },
                _ => GitHubGap::inaccessible(
                    "wiki",
                    self.repository(),
                    "a GitHub wiki revision could not be decoded",
                ),
            })?;
            let path = chunk.metadata.path.as_deref().unwrap_or("unknown");
            let revision = chunk.metadata.commit.as_deref().unwrap_or("unreachable");
            let identity = format!("wiki:{revision}:{path}");
            if !seen.insert(identity) {
                continue;
            }
            budget.consume("wiki", chunk.data.len())?;
            chunk.metadata.source_type = Arc::from(SOURCE_NAME);
            chunk.metadata.path = Some(Arc::from(self.provenance(&format!(
                "wiki/{}@{}",
                percent_encode_path(path),
                revision
            ))));
            chunks.push(chunk);
        }
        Ok(())
    }

    fn collect_gists(
        &self,
        api: &mut GitHubApi<'_>,
        budget: &mut ContentBudget,
        seen: &mut HashSet<String>,
        chunks: &mut Vec<Chunk>,
    ) -> Result<(), GitHubGap> {
        let list_path = format!("/users/{}/gists", self.owner);
        let (summaries, page_gap): (Vec<GistSummary>, _) = api.pages("gists", &list_path, "");
        for summary in summaries {
            validate_hex_id("gists", "gist id", &summary.id)?;
            let revisions_path = format!("/gists/{}/commits", summary.id);
            let (revisions, revisions_gap): (Vec<GistRevision>, _) =
                api.pages("gists", &revisions_path, "");
            for revision in revisions {
                validate_hex_id("gists", "gist revision", &revision.version)?;
                let revision_path = format!("/gists/{}/{}", summary.id, revision.version);
                let revision_gist: Gist = api.one("gists", &revision_path, "")?;
                if revision_gist.id != summary.id {
                    return Err(GitHubGap::inaccessible(
                        "gists",
                        self.repository(),
                        "GitHub returned a different gist identity for a requested revision",
                    ));
                }
                for (name, file) in revision_gist.files {
                    let encoded_name = percent_encode_path(&name);
                    if file.truncated {
                        return Err(GitHubGap::truncated(
                            "gists",
                            self.repository(),
                            format!("GitHub truncated gist file {encoded_name}"),
                        ));
                    }
                    let Some(content) = file.content else {
                        continue;
                    };
                    push_text_chunk(
                        chunks,
                        seen,
                        budget,
                        "gists",
                        format!("gist:{}:{}:{}", summary.id, revision.version, encoded_name),
                        format!(
                            "github://gists/{}/{encoded_name}@{}",
                            summary.id, revision.version
                        ),
                        &revision.version,
                        revision.user.as_ref().map(|actor| actor.login.as_str()),
                        &revision.committed_at,
                        content,
                    )?;
                }
            }
            if let Some(gap) = revisions_gap {
                return Err(gap);
            }
            let comments_path = format!("/gists/{}/comments", summary.id);
            let (comments, comments_gap): (Vec<Comment>, _) =
                api.pages("gists", &comments_path, "");
            append_comments(
                chunks,
                seen,
                budget,
                "gists",
                &format!("github://gists/{}", summary.id),
                comments,
            )?;
            if let Some(gap) = comments_gap {
                return Err(gap);
            }
        }
        if let Some(gap) = page_gap {
            return Err(gap);
        }
        Ok(())
    }

    fn provenance(&self, suffix: &str) -> String {
        format!("github://{}/{}/{suffix}", self.owner, self.repo)
    }

    fn repository(&self) -> String {
        format!("{}/{}", self.owner, self.repo)
    }
}

pub(crate) fn collect_wiki_repo_for_test(
    clone_path: &std::path::Path,
    limits: crate::SourceLimits,
) -> Result<Vec<Chunk>, SourceError> {
    let source = GitHubCollaborationSource::new(
        "acme/rocket",
        "test-token",
        GitHubCollaborationSelection {
            wiki: true,
            ..Default::default()
        },
    )?
    .with_limits(limits);
    let mut budget = ContentBudget::new(limits);
    let mut seen = HashSet::new();
    let mut chunks = Vec::new();
    source
        .collect_wiki_repo(clone_path, &mut budget, &mut seen, &mut chunks)
        .map_err(GitHubGap::into_source_error)?;
    Ok(chunks)
}

impl Source for GitHubCollaborationSource {
    fn name(&self) -> &str {
        SOURCE_NAME
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        crate::gate_scan(|| {
            match crate::blocking_thread::collect_on_blocking_thread(SOURCE_NAME, || {
                self.collect_chunks()
            }) {
                Ok(rows) => Box::new(rows.into_iter()),
                Err(error) => Box::new(std::iter::once(Err(error))),
            }
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn collect_surface<F>(
    surface: &'static str,
    output: &mut Vec<Result<Chunk, SourceError>>,
    collect: F,
) where
    F: FnOnce(&mut Vec<Chunk>) -> Result<(), GitHubGap>,
{
    let mut chunks = Vec::new();
    let result = collect(&mut chunks);
    output.extend(chunks.into_iter().map(Ok));
    if let Err(gap) = result {
        if gap.kind == SourceCoverageGapKind::Truncated {
            let _recorded = crate::record_skip_event(crate::SourceSkipEvent::SourceTruncated);
        }
        debug_assert_eq!(surface, gap.surface);
        output.push(Err(gap.into_source_error()));
    }
}

#[derive(Debug)]
struct GitHubGap {
    surface: &'static str,
    target: String,
    kind: SourceCoverageGapKind,
    detail: String,
}

impl GitHubGap {
    fn inaccessible(
        surface: &'static str,
        target: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            surface,
            target: target.into(),
            kind: SourceCoverageGapKind::Inaccessible,
            detail: detail.into(),
        }
    }

    fn truncated(
        surface: &'static str,
        target: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            surface,
            target: target.into(),
            kind: SourceCoverageGapKind::Truncated,
            detail: detail.into(),
        }
    }

    fn into_source_error(self) -> SourceError {
        SourceError::Coverage {
            adapter: SOURCE_NAME.into(),
            surface: self.surface.into(),
            target: self.target,
            kind: self.kind,
            detail: self.detail,
        }
    }
}

struct ContentBudget {
    bytes_remaining: usize,
    chunks_remaining: usize,
}

impl ContentBudget {
    fn new(limits: crate::SourceLimits) -> Self {
        Self {
            bytes_remaining: limits.git_total_bytes,
            chunks_remaining: limits.git_chunk_count,
        }
    }

    fn consume(&mut self, surface: &'static str, bytes: usize) -> Result<(), GitHubGap> {
        if self.chunks_remaining == 0 || bytes > self.bytes_remaining {
            return Err(GitHubGap::truncated(
                surface,
                "selected GitHub collaboration input",
                "collaboration content exceeded the configured aggregate byte or chunk limit",
            ));
        }
        self.chunks_remaining -= 1;
        self.bytes_remaining -= bytes;
        Ok(())
    }
}

struct GitHubApi<'a> {
    client: Client,
    endpoint: &'a str,
    requests_remaining: usize,
    max_response_bytes: usize,
}

impl<'a> GitHubApi<'a> {
    fn new(
        client: Client,
        endpoint: &'a str,
        request_limit: usize,
        max_response_bytes: usize,
    ) -> Self {
        Self {
            client,
            endpoint,
            requests_remaining: request_limit,
            max_response_bytes,
        }
    }

    fn pages<T: DeserializeOwned>(
        &mut self,
        surface: &'static str,
        path: &str,
        extra_query: &str,
    ) -> (Vec<T>, Option<GitHubGap>) {
        let mut items = Vec::new();
        let mut page = 1;
        loop {
            let query = if extra_query.is_empty() {
                format!("per_page={API_PAGE_SIZE}&page={page}")
            } else {
                format!("{extra_query}&per_page={API_PAGE_SIZE}&page={page}")
            };
            let page_items: Vec<T> = match self.request_json(surface, path, &query) {
                Ok(page_items) => page_items,
                Err(gap) => return (items, Some(gap)),
            };
            let count = page_items.len();
            items.extend(page_items);
            if count < API_PAGE_SIZE {
                return (items, None);
            }
            page += 1;
        }
    }

    fn one<T: DeserializeOwned>(
        &mut self,
        surface: &'static str,
        path: &str,
        query: &str,
    ) -> Result<T, GitHubGap> {
        self.request_json(surface, path, query)
    }

    fn graphql<T: DeserializeOwned>(
        &mut self,
        surface: &'static str,
        request: serde_json::Value,
    ) -> Result<T, GitHubGap> {
        for attempt in 0..MAX_RATE_LIMIT_ATTEMPTS {
            if self.requests_remaining == 0 {
                return Err(GitHubGap::truncated(
                    surface,
                    "/graphql",
                    "GitHub collaboration request limit was exhausted",
                ));
            }
            self.requests_remaining -= 1;
            let response = self
                .client
                .post(format!("{}/graphql", self.endpoint))
                .json(&request)
                .send()
                .map_err(|_| {
                    GitHubGap::inaccessible(surface, "/graphql", "GitHub GraphQL request failed")
                })?;
            let status = response.status();
            let rate_limited = status.as_u16() == 429
                || (status.as_u16() == 403
                    && response
                        .headers()
                        .get("x-ratelimit-remaining")
                        .and_then(|value| value.to_str().ok())
                        == Some("0"));
            if rate_limited && attempt + 1 < MAX_RATE_LIMIT_ATTEMPTS {
                let seconds = response
                    .headers()
                    .get("retry-after")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or((attempt + 1) as u64)
                    .min(MAX_RATE_LIMIT_SLEEP_SECS);
                std::thread::sleep(std::time::Duration::from_secs(seconds));
                continue;
            }
            if !status.is_success() {
                return Err(GitHubGap::inaccessible(
                    surface,
                    "/graphql",
                    format!("GitHub GraphQL returned HTTP {status}"),
                ));
            }
            let envelope: GraphQlEnvelope<T> = read_bounded_json(response, self.max_response_bytes)
                .map_err(|error| error.into_gap(surface, "/graphql"))?;
            if envelope.errors.is_some() {
                return Err(GitHubGap::inaccessible(
                    surface,
                    "/graphql",
                    "GitHub GraphQL returned an error for the selected surface",
                ));
            }
            return envelope.data.ok_or_else(|| {
                GitHubGap::inaccessible(surface, "/graphql", "GitHub GraphQL response omitted data")
            });
        }
        Err(GitHubGap::inaccessible(
            surface,
            "/graphql",
            "GitHub GraphQL rate limit retry budget was exhausted",
        ))
    }

    fn request_json<T: DeserializeOwned>(
        &mut self,
        surface: &'static str,
        path: &str,
        query: &str,
    ) -> Result<T, GitHubGap> {
        for attempt in 0..MAX_RATE_LIMIT_ATTEMPTS {
            if self.requests_remaining == 0 {
                return Err(GitHubGap::truncated(
                    surface,
                    path,
                    "GitHub collaboration request limit was exhausted",
                ));
            }
            self.requests_remaining -= 1;
            let mut url = format!("{}{path}", self.endpoint);
            if !query.is_empty() {
                url.push('?');
                url.push_str(query);
            }
            let response =
                self.client.get(url).send().map_err(|_| {
                    GitHubGap::inaccessible(surface, path, "GitHub API request failed")
                })?;
            let status = response.status();
            let rate_limited = status.as_u16() == 429
                || (status.as_u16() == 403
                    && response
                        .headers()
                        .get("x-ratelimit-remaining")
                        .and_then(|value| value.to_str().ok())
                        == Some("0"));
            if rate_limited && attempt + 1 < MAX_RATE_LIMIT_ATTEMPTS {
                let seconds = response
                    .headers()
                    .get("retry-after")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or((attempt + 1) as u64)
                    .min(MAX_RATE_LIMIT_SLEEP_SECS);
                std::thread::sleep(std::time::Duration::from_secs(seconds));
                continue;
            }
            if !status.is_success() {
                return Err(GitHubGap::inaccessible(
                    surface,
                    path,
                    format!("GitHub API returned HTTP {status}"),
                ));
            }
            return read_bounded_json(response, self.max_response_bytes)
                .map_err(|error| error.into_gap(surface, path));
        }
        Err(GitHubGap::inaccessible(
            surface,
            path,
            "GitHub API rate limit retry budget was exhausted",
        ))
    }
}

fn read_bounded_json<T: DeserializeOwned>(
    response: Response,
    max_bytes: usize,
) -> Result<T, BoundedJsonError> {
    let mut body = Vec::with_capacity(max_bytes.min(64 * 1024));
    response
        .take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut body)
        .map_err(|_| BoundedJsonError::Inaccessible("failed to read GitHub API response".into()))?;
    if body.len() > max_bytes {
        return Err(BoundedJsonError::Truncated(format!(
            "GitHub API response exceeded the configured {max_bytes}-byte limit"
        )));
    }
    serde_json::from_slice(&body)
        .map_err(|_| BoundedJsonError::Inaccessible("GitHub API returned invalid JSON".into()))
}

enum BoundedJsonError {
    Inaccessible(String),
    Truncated(String),
}

impl BoundedJsonError {
    fn into_gap(self, surface: &'static str, target: &str) -> GitHubGap {
        match self {
            Self::Inaccessible(detail) => GitHubGap::inaccessible(surface, target, detail),
            Self::Truncated(detail) => GitHubGap::truncated(surface, target, detail),
        }
    }
}

fn build_client(token: &str, http: &crate::http::HttpClientConfig) -> Result<Client, SourceError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/vnd.github+json"),
    );
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| SourceError::Other("invalid GitHub authorization header".into()))?,
    );
    crate::http::blocking_client_builder(http)
        .map_err(SourceError::Other)?
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| SourceError::Other("failed to build GitHub collaboration client".into()))
}

fn parse_repository(repository: &str) -> Result<(String, String), SourceError> {
    let Some((owner, repo)) = repository.split_once('/') else {
        return Err(SourceError::Other(
            "github-collaboration repository must be OWNER/REPO".into(),
        ));
    };
    if repo.contains('/') {
        return Err(SourceError::Other(
            "github-collaboration repository must contain exactly one slash".into(),
        ));
    }
    validate_name("owner", owner, 39, false)?;
    validate_name("repository", repo, 100, true)?;
    Ok((owner.into(), repo.into()))
}

fn validate_name(
    kind: &str,
    value: &str,
    max_len: usize,
    allow_leading_dot: bool,
) -> Result<(), SourceError> {
    if value.is_empty()
        || value.len() > max_len
        || value.starts_with('-')
        || (!allow_leading_dot && value.starts_with('.'))
        || value.ends_with(['-', '.'])
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(SourceError::Other(format!(
            "github-collaboration {kind} contains unsafe characters"
        )));
    }
    Ok(())
}

fn validate_hex_id(surface: &'static str, kind: &str, value: &str) -> Result<(), GitHubGap> {
    if value.is_empty() || value.len() > 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(GitHubGap::inaccessible(
            surface,
            kind,
            format!("GitHub returned an invalid {kind}"),
        ));
    }
    Ok(())
}

fn push_text_chunk(
    output: &mut Vec<Chunk>,
    seen: &mut HashSet<String>,
    budget: &mut ContentBudget,
    surface: &'static str,
    identity: String,
    path: String,
    revision: &str,
    author: Option<&str>,
    date: &str,
    data: String,
) -> Result<(), GitHubGap> {
    if data.is_empty() || !seen.insert(identity) {
        return Ok(());
    }
    let data_len = data.len();
    budget.consume(surface, data_len)?;
    output.push(Chunk {
        data: SensitiveString::from(data),
        metadata: ChunkMetadata {
            source_type: Arc::from(SOURCE_NAME),
            path: Some(Arc::from(path)),
            commit: Some(Arc::from(revision.to_owned())),
            author: author.map(|actor| Arc::from(actor.to_owned())),
            date: (!date.is_empty()).then(|| Arc::from(date.to_owned())),
            size_bytes: Some(data_len as u64),
            ..Default::default()
        },
    });
    Ok(())
}

fn append_comments(
    output: &mut Vec<Chunk>,
    seen: &mut HashSet<String>,
    budget: &mut ContentBudget,
    surface: &'static str,
    parent_path: &str,
    comments: Vec<Comment>,
) -> Result<(), GitHubGap> {
    for comment in comments {
        let revision = revision_identity(&comment.node_id, &comment.updated_at);
        push_text_chunk(
            output,
            seen,
            budget,
            surface,
            format!("comment:{revision}"),
            format!("{parent_path}/comments/{}", comment.id),
            &revision,
            comment.user.as_ref().map(|actor| actor.login.as_str()),
            &comment.updated_at,
            comment.body,
        )?;
    }
    Ok(())
}

fn join_title_body(title: &str, body: Option<&str>) -> String {
    match body.filter(|body| !body.is_empty()) {
        Some(body) => format!("{title}\n{body}"),
        None => title.to_owned(),
    }
}

fn revision_identity(node_id: &str, updated_at: &str) -> String {
    format!("{node_id}@{updated_at}")
}

fn percent_encode_path(path: &str) -> String {
    let mut encoded = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

#[derive(Debug, Deserialize)]
struct Actor {
    login: String,
}

#[derive(Debug, Deserialize)]
struct Issue {
    node_id: String,
    number: u64,
    title: String,
    body: Option<String>,
    user: Option<Actor>,
    updated_at: String,
    pull_request: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct PullRequest {
    node_id: String,
    number: u64,
    title: String,
    body: Option<String>,
    user: Option<Actor>,
    updated_at: String,
}

#[derive(Debug, Deserialize)]
struct PullRequestReview {
    id: u64,
    node_id: String,
    body: Option<String>,
    user: Option<Actor>,
    submitted_at: Option<String>,
    commit_id: String,
}

const DISCUSSIONS_QUERY: &str = "query($owner:String!,$repo:String!,$cursor:String){repository(owner:$owner,name:$repo){discussions(first:100,after:$cursor){nodes{id number title body updatedAt author{login}} pageInfo{hasNextPage endCursor}}}}";
const DISCUSSION_COMMENTS_QUERY: &str = "query($owner:String!,$repo:String!,$number:Int!,$cursor:String){repository(owner:$owner,name:$repo){discussion(number:$number){comments(first:100,after:$cursor){nodes{id body updatedAt author{login} replies(first:100){nodes{id body updatedAt author{login}} pageInfo{hasNextPage endCursor}}} pageInfo{hasNextPage endCursor}}}}}";

#[derive(Debug, Deserialize)]
struct GraphQlEnvelope<T> {
    data: Option<T>,
    errors: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct DiscussionListData {
    repository: Option<DiscussionRepository>,
}

#[derive(Debug, Deserialize)]
struct DiscussionRepository {
    discussions: DiscussionConnection,
}

#[derive(Debug, Deserialize)]
struct DiscussionConnection {
    nodes: Vec<DiscussionNode>,
    #[serde(rename = "pageInfo")]
    page_info: PageInfo,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DiscussionNode {
    id: String,
    number: u64,
    title: String,
    body: String,
    updated_at: String,
    author: Option<Actor>,
}

#[derive(Debug, Deserialize)]
struct DiscussionCommentsData {
    repository: Option<DiscussionCommentsRepository>,
}

#[derive(Debug, Deserialize)]
struct DiscussionCommentsRepository {
    discussion: Option<DiscussionWithComments>,
}

#[derive(Debug, Deserialize)]
struct DiscussionWithComments {
    comments: DiscussionCommentConnection,
}

#[derive(Debug, Deserialize)]
struct DiscussionCommentConnection {
    nodes: Vec<DiscussionComment>,
    #[serde(rename = "pageInfo")]
    page_info: PageInfo,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DiscussionComment {
    id: String,
    body: String,
    updated_at: String,
    author: Option<Actor>,
    replies: DiscussionReplyConnection,
}

#[derive(Debug, Deserialize)]
struct DiscussionReplyConnection {
    nodes: Vec<DiscussionReply>,
    #[serde(rename = "pageInfo")]
    page_info: PageInfo,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DiscussionReply {
    id: String,
    body: String,
    updated_at: String,
    author: Option<Actor>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PageInfo {
    has_next_page: bool,
    end_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Comment {
    id: u64,
    node_id: String,
    body: String,
    user: Option<Actor>,
    updated_at: String,
}

#[derive(Debug, Deserialize)]
struct GistSummary {
    id: String,
}

#[derive(Debug, Deserialize)]
struct Gist {
    id: String,
    #[serde(default)]
    files: HashMap<String, GistFile>,
}

#[derive(Debug, Deserialize)]
struct GistRevision {
    version: String,
    committed_at: String,
    user: Option<Actor>,
}

#[derive(Debug, Deserialize)]
struct GistFile {
    content: Option<String>,
    #[serde(default)]
    truncated: bool,
}
