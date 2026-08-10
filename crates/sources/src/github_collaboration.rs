//! Bounded GitHub issue, pull request, discussion, wiki, gist, and release source.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::Arc;

use keyhog_core::{
    Chunk, ChunkMetadata, SensitiveString, Source, SourceCoverageGapKind, SourceError,
};
use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION};
use reqwest::StatusCode;
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
    pub releases: bool,
}

impl GitHubCollaborationSelection {
    pub fn is_empty(self) -> bool {
        !(self.issues
            || self.pull_requests
            || self.discussions
            || self.wiki
            || self.gists
            || self.releases)
    }
}

/// Scans explicitly selected GitHub collaboration surfaces for one repository.
#[derive(Clone)]
pub struct GitHubCollaborationSource {
    owner: String,
    repo: String,
    token: Arc<str>,
    selection: GitHubCollaborationSelection,
    endpoint: String,
    wiki_clone_url: Option<String>,
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
            token: Arc::from(token.into()),
            selection,
            endpoint: "https://api.github.com".into(),
            wiki_clone_url: None,
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

    /// Use an explicit GitHub-compatible API endpoint.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into().trim_end_matches('/').to_string();
        self
    }

    /// Use an explicit clone URL for the selected wiki repository.
    pub fn with_wiki_clone_url(mut self, url: impl Into<String>) -> Self {
        self.wiki_clone_url = Some(url.into());
        self
    }

    fn stream_chunks(
        &self,
        mut emit: impl FnMut(Result<Chunk, SourceError>) -> bool,
    ) -> Result<(), SourceError> {
        let _acquire = crate::profile::acquire_span();
        // Same pre-connect SSRF screen gitlab-group / bitbucket-workspace use.
        // CLI wires `--github-api-endpoint` through `with_endpoint` without the
        // factory path, so validation must happen here before the bearer token
        // leaves the process.
        let (api_root, screened) = crate::hosted_git::validated_api_endpoint(
            "github",
            &self.endpoint,
            self.http.allow_private_endpoint,
        )?;
        let endpoint = api_root.as_str().trim_end_matches('/').to_string();
        let client = build_client(self.token.as_ref(), &self.http, screened.as_ref())?;
        let mut api = GitHubApi::new(
            client,
            &endpoint,
            self.limits.hosted_git_pages,
            self.limits.web_response_bytes,
        );
        let mut budget = ContentBudget::new(self.limits);
        let mut seen = HashSet::new();

        if self.selection.issues
            && !stream_surface("issues", &mut emit, |chunks| {
                self.collect_issues(&mut api, &mut budget, &mut seen, chunks)
            })
        {
            return Ok(());
        }
        if self.selection.pull_requests
            && !stream_surface("pull-requests", &mut emit, |chunks| {
                self.collect_pull_requests(&mut api, &mut budget, &mut seen, chunks)
            })
        {
            return Ok(());
        }
        if self.selection.discussions
            && !stream_surface("discussions", &mut emit, |chunks| {
                self.collect_discussions(&mut api, &mut budget, &mut seen, chunks)
            })
        {
            return Ok(());
        }
        if self.selection.wiki
            && !stream_surface("wiki", &mut emit, |chunks| {
                self.collect_wiki(&mut api, &mut budget, &mut seen, chunks)
            })
        {
            return Ok(());
        }
        if self.selection.gists
            && !stream_surface("gists", &mut emit, |chunks| {
                self.collect_gists(&mut api, &mut budget, &mut seen, chunks)
            })
        {
            return Ok(());
        }
        if self.selection.releases
            && !stream_surface("releases", &mut emit, |chunks| {
                self.collect_releases(&mut api, &mut budget, &mut seen, chunks)
            })
        {
            return Ok(());
        }
        Ok(())
    }

    fn collect_issues(
        &self,
        api: &mut GitHubApi<'_>,
        budget: &mut ContentBudget,
        seen: &mut HashSet<String>,
        chunks: &mut ChunkOutput<'_>,
    ) -> Result<(), GitHubGap> {
        let path = format!("/repos/{}/{}/issues", self.owner, self.repo);
        api.pages_each(
            "issues",
            &path,
            "state=all&filter=all",
            |api, issues: Vec<Issue>| {
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
                    api.pages_each(
                        "issues",
                        &comments_path,
                        "",
                        |_api, comments: Vec<Comment>| {
                            append_comments(
                                chunks,
                                seen,
                                budget,
                                "issues",
                                &self.provenance(&format!("issues/{}", issue.number)),
                                comments,
                            )
                        },
                    )?;
                }
                Ok(())
            },
        )
    }

    fn collect_pull_requests(
        &self,
        api: &mut GitHubApi<'_>,
        budget: &mut ContentBudget,
        seen: &mut HashSet<String>,
        chunks: &mut ChunkOutput<'_>,
    ) -> Result<(), GitHubGap> {
        let path = format!("/repos/{}/{}/pulls", self.owner, self.repo);
        api.pages_each(
            "pull-requests",
            &path,
            "state=all",
            |api, pulls: Vec<PullRequest>| {
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
                        api.pages_each(
                            "pull-requests",
                            &comments_path,
                            "",
                            |_api, comments: Vec<Comment>| {
                                append_comments(
                                    chunks,
                                    seen,
                                    budget,
                                    "pull-requests",
                                    &self.provenance(&format!("pulls/{}/{kind}", pull.number)),
                                    comments,
                                )
                            },
                        )?;
                    }
                    let reviews_path = format!(
                        "/repos/{}/{}/pulls/{}/reviews",
                        self.owner, self.repo, pull.number
                    );
                    api.pages_each(
                        "pull-requests",
                        &reviews_path,
                        "",
                        |_api, reviews: Vec<PullRequestReview>| {
                            for review in reviews {
                                let revision_time =
                                    review.submitted_at.as_deref().unwrap_or(&review.commit_id); // LAW10: absent optional review timestamp uses the immutable commit ID only for revision identity; review text is still scanned.
                                let revision = revision_identity(&review.node_id, revision_time);
                                push_text_chunk(
                                    chunks,
                                    seen,
                                    budget,
                                    "pull-requests",
                                    format!("review:{revision}"),
                                    self.provenance(&format!(
                                        "pulls/{}/reviews/{}",
                                        pull.number, review.id
                                    )),
                                    &revision,
                                    review.user.as_ref().map(|actor| actor.login.as_str()),
                                    review.submitted_at.as_deref().unwrap_or(""), // LAW10: absent optional timestamp renders an empty metadata field; review content remains scanned.
                                    review.body.unwrap_or_default(), // LAW10: a review without optional body text has no text payload to scan; its metadata chunk is still emitted.
                                )?;
                            }
                            Ok(())
                        },
                    )?;
                }
                Ok(())
            },
        )
    }

    fn collect_discussions(
        &self,
        api: &mut GitHubApi<'_>,
        budget: &mut ContentBudget,
        seen: &mut HashSet<String>,
        chunks: &mut ChunkOutput<'_>,
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
        chunks: &mut ChunkOutput<'_>,
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
        chunks: &mut ChunkOutput<'_>,
    ) -> Result<(), GitHubGap> {
        let temp = tempfile::tempdir().map_err(|_| {
            GitHubGap::inaccessible(
                "wiki",
                self.repository(),
                "could not create wiki clone directory",
            )
        })?;
        let clone_path = temp.path().join("wiki");
        let default_clone_url;
        let clone_url = if let Some(url) = self.wiki_clone_url.as_deref() {
            url
        } else {
            default_clone_url = format!("https://github.com/{}/{}.wiki.git", self.owner, self.repo);
            &default_clone_url
        };
        crate::hosted_git::clone_authenticated_history(
            "github",
            &format!("{}/{}.wiki", self.owner, self.repo),
            clone_url,
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
        chunks: &mut ChunkOutput<'_>,
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
            let path = chunk.metadata.path.as_deref().ok_or_else(|| {
                GitHubGap::inaccessible(
                    "wiki",
                    self.repository(),
                    "a GitHub wiki revision omitted its file path; the revision was not scanned",
                )
            })?;
            let revision = chunk.metadata.commit.as_deref().ok_or_else(|| {
                GitHubGap::inaccessible(
                    "wiki",
                    self.repository(),
                    "a GitHub wiki revision omitted its commit identity; the revision was not scanned",
                )
            })?;
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
        chunks: &mut ChunkOutput<'_>,
    ) -> Result<(), GitHubGap> {
        let list_path = format!("/users/{}/gists", self.owner);
        api.pages_each("gists", &list_path, "", |api, summaries: Vec<GistSummary>| {
            for summary in summaries {
                validate_hex_id("gists", "gist id", &summary.id)?;
                let revisions_path = format!("/gists/{}/commits", summary.id);
                api.pages_each(
                    "gists",
                    &revisions_path,
                    "",
                    |api, revisions: Vec<GistRevision>| {
                        for revision in revisions {
                            validate_hex_id("gists", "gist revision", &revision.version)?;
                            let revision_path =
                                format!("/gists/{}/{}", summary.id, revision.version);
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
                                    format!(
                                        "gist:{}:{}:{}",
                                        summary.id, revision.version, encoded_name
                                    ),
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
                        Ok(())
                    },
                )?;
                let comments_path = format!("/gists/{}/comments", summary.id);
                api.pages_each(
                    "gists",
                    &comments_path,
                    "",
                    |_api, comments: Vec<Comment>| {
                        append_comments(
                            chunks,
                            seen,
                            budget,
                            "gists",
                            &format!("github://gists/{}", summary.id),
                            comments,
                        )
                    },
                )?;
            }
            Ok(())
        })
    }

    /// Release notes are operator-authored free text on the same footing as an
    /// issue body, and the "upgrade steps" section of a release is a documented
    /// place for a real credential to be pasted. A DRAFT release is not present
    /// in the repository tree at all, so no clone-based source can ever see it;
    /// `/releases` returns drafts and prereleases to an authenticated caller,
    /// which is exactly the unpolished text worth scanning.
    ///
    /// SCOPE: release asset BYTES are not fetched. `/releases/assets/{id}`
    /// answers with a 302 to a `*.githubusercontent.com` origin and this client
    /// runs `redirect: none` by policy, so following it would carry the
    /// operator's GitHub token to a different origin. Each asset's name and
    /// label are appended to the release text instead, so an asset is never
    /// absent from the scanned record; its payload is outside this surface's
    /// contract rather than an enumerated input that was silently dropped.
    fn collect_releases(
        &self,
        api: &mut GitHubApi<'_>,
        budget: &mut ContentBudget,
        seen: &mut HashSet<String>,
        chunks: &mut ChunkOutput<'_>,
    ) -> Result<(), GitHubGap> {
        let path = format!("/repos/{}/{}/releases", self.owner, self.repo);
        api.pages_each("releases", &path, "", |_api, releases: Vec<Release>| {
            for release in releases {
                let revision_time = release
                    .published_at
                    .as_deref()
                    .unwrap_or(&release.created_at); // LAW10: absent optional publish time uses required creation time only for revision identity; release text is still scanned.
                let revision = revision_identity(&release.node_id, revision_time);
                let title = release.name.as_deref().unwrap_or(&release.tag_name); // LAW10: absent optional release name uses the required tag while preserving all release body and asset text.
                let mut text = join_title_body(title, release.body.as_deref());
                for asset in &release.assets {
                    text.push('\n');
                    text.push_str(&asset.name);
                    if let Some(label) = asset.label.as_deref().filter(|label| !label.is_empty()) {
                        text.push('\n');
                        text.push_str(label);
                    }
                }
                push_text_chunk(
                    chunks,
                    seen,
                    budget,
                    "releases",
                    format!("release:{revision}"),
                    self.provenance(&format!("releases/{}", release.id)),
                    &revision,
                    release.author.as_ref().map(|actor| actor.login.as_str()),
                    revision_time,
                    text,
                )?;
            }
            Ok(())
        })
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
    let mut rows = Vec::new();
    let mut emit = |row| {
        rows.push(row);
        true
    };
    let mut output = ChunkOutput::new(&mut emit);
    source
        .collect_wiki_repo(clone_path, &mut budget, &mut seen, &mut output)
        .map_err(GitHubGap::into_source_error)?;
    rows.into_iter().collect()
}

impl Source for GitHubCollaborationSource {
    fn name(&self) -> &str {
        SOURCE_NAME
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        let lease = crate::acquire_scan_read_lease();
        let source = self.clone();
        let worker_lease = lease.clone();
        let profile_runtime = crate::profile::current_runtime();
        let stream = crate::parallel_fetch::RemoteChunkStream::spawn(
            "keyhog-github-collaboration",
            SOURCE_NAME,
            worker_lease,
            move |sender, worker_lease| {
                let _attributed = worker_lease.enter();
                let _profile_guard = profile_runtime.as_ref().map(|runtime| runtime.enter());
                let result = source.stream_chunks(|row| sender.send(row).is_ok());
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

struct ChunkOutput<'a> {
    emit: &'a mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
    accepted: bool,
}

impl<'a> ChunkOutput<'a> {
    fn new(emit: &'a mut dyn FnMut(Result<Chunk, SourceError>) -> bool) -> Self {
        Self {
            emit,
            accepted: true,
        }
    }

    fn push(&mut self, chunk: Chunk) {
        if self.accepted {
            self.accepted = (self.emit)(Ok(chunk));
        }
    }
}

fn stream_surface<F>(
    surface: &'static str,
    emit: &mut impl FnMut(Result<Chunk, SourceError>) -> bool,
    collect: F,
) -> bool
where
    F: FnOnce(&mut ChunkOutput<'_>) -> Result<(), GitHubGap>,
{
    let mut output = ChunkOutput::new(emit);
    let result = collect(&mut output);
    if !output.accepted {
        return false;
    }
    if let Err(gap) = result {
        if gap.kind == SourceCoverageGapKind::Truncated {
            let _recorded = crate::record_skip_event(crate::SourceSkipEvent::SourceTruncated);
        }
        debug_assert_eq!(surface, gap.surface);
        return (output.emit)(Err(gap.into_source_error()));
    }
    true
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

    fn pages_each<T: DeserializeOwned>(
        &mut self,
        surface: &'static str,
        path: &str,
        extra_query: &str,
        mut consume: impl FnMut(&mut Self, Vec<T>) -> Result<(), GitHubGap>,
    ) -> Result<(), GitHubGap> {
        let mut page = 1;
        loop {
            let _page_span = crate::profile::walk_span();
            let query = if extra_query.is_empty() {
                format!("per_page={API_PAGE_SIZE}&page={page}")
            } else {
                format!("{extra_query}&per_page={API_PAGE_SIZE}&page={page}")
            };
            let page_items: Vec<T> = self.request_json(surface, path, &query)?;
            let count = page_items.len();
            consume(self, page_items)?;
            if count < API_PAGE_SIZE {
                return Ok(());
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
            let rate_limited = response_is_rate_limited(status, response.headers());
            if rate_limited && attempt + 1 < MAX_RATE_LIMIT_ATTEMPTS {
                // Record the retry with its 1-based attempt number.
                crate::profile::record_retry(attempt as u64 + 1);
                let seconds = rate_limit_backoff_seconds(response.headers(), attempt);
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
            let rate_limited = response_is_rate_limited(status, response.headers());
            if rate_limited && attempt + 1 < MAX_RATE_LIMIT_ATTEMPTS {
                // Record the retry with its 1-based attempt number.
                crate::profile::record_retry(attempt as u64 + 1);
                let seconds = rate_limit_backoff_seconds(response.headers(), attempt);
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

fn response_is_rate_limited(status: StatusCode, headers: &HeaderMap) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS
        || status == StatusCode::FORBIDDEN
            && headers
                .get("x-ratelimit-remaining")
                .is_some_and(|value| value.to_str().is_ok_and(|remaining| remaining == "0"))
}

fn rate_limit_backoff_seconds(headers: &HeaderMap, attempt: usize) -> u64 {
    let default = (attempt + 1) as u64;
    let Some(value) = headers.get("retry-after") else {
        return default;
    };
    let Ok(value) = value.to_str() else {
        return default;
    };
    let Ok(seconds) = value.parse::<u64>() else {
        return default;
    };
    seconds.min(MAX_RATE_LIMIT_SLEEP_SECS)
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
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| SourceError::Other("invalid GitHub authorization header".into()))?,
    );
    let builder = crate::http::blocking_client_builder(http)
        .map_err(SourceError::Other)?
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::none());
    crate::endpoint_screen::pin_screened_addrs(builder, screened, http.proxy.is_some())
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
    output: &mut ChunkOutput<'_>,
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
    // Real collaboration content counts at the single emission sink (after
    // dedup on `seen`, so re-fetched revisions are not double counted).
    crate::profile::add_input_units(1);
    crate::profile::add_input_bytes(data_len as u64);
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
    output: &mut ChunkOutput<'_>,
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
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
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
struct Release {
    id: u64,
    node_id: String,
    tag_name: String,
    name: Option<String>,
    body: Option<String>,
    author: Option<Actor>,
    created_at: String,
    published_at: Option<String>,
    #[serde(default)]
    assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct ReleaseAsset {
    name: String,
    label: Option<String>,
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
