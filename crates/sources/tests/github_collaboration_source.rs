#![cfg(feature = "github")]

use httpmock::{Method, MockServer};
use keyhog_core::{Source, SourceCoverageGapKind, SourceError};
use keyhog_sources::testing::{SourceTestApi as _, TestApi};
use keyhog_sources::{GitHubCollaborationSelection, SourceLimits};

fn limits(requests: usize) -> SourceLimits {
    SourceLimits {
        hosted_git_pages: requests,
        web_response_bytes: 128 * 1024,
        git_total_bytes: 128 * 1024,
        git_chunk_count: 100,
        ..Default::default()
    }
}

#[test]
fn issue_selection_fetches_only_issues_and_deduplicates_comment_identity() {
    let server = MockServer::start();
    let issues = server.mock(|when, then| {
        when.method(Method::GET)
            .path("/repos/acme/rocket/issues")
            .query_param("state", "all")
            .query_param("per_page", "100")
            .query_param("page", "1")
            .header("authorization", "Bearer test-token");
        then.status(200).json_body(serde_json::json!([{
            "node_id":"I_immutable","number":7,"title":"deployment",
            "body":"TOKEN=issue-secret","user":{"login":"alice"},
            "updated_at":"2026-07-13T00:00:00Z"
        }]));
    });
    let comments = server.mock(|when, then| {
        when.method(Method::GET)
            .path("/repos/acme/rocket/issues/7/comments")
            .query_param("per_page", "100")
            .query_param("page", "1");
        then.status(200).json_body(serde_json::json!([
            {"id":91,"node_id":"IC_same","body":"TOKEN=comment-secret","user":{"login":"bob"},"updated_at":"2026-07-13T01:00:00Z"},
            {"id":91,"node_id":"IC_same","body":"TOKEN=comment-secret","user":{"login":"bob"},"updated_at":"2026-07-13T01:00:00Z"}
        ]));
    });
    let pulls = server.mock(|when, then| {
        when.method(Method::GET).path("/repos/acme/rocket/pulls");
        then.status(500);
    });
    let graphql = server.mock(|when, then| {
        when.method(Method::POST).path("/graphql");
        then.status(500);
    });
    let gists = server.mock(|when, then| {
        when.method(Method::GET).path("/users/acme/gists");
        then.status(500);
    });

    let source = TestApi
        .github_collaboration_source_with_endpoint(
            "acme/rocket",
            &server.url(""),
            GitHubCollaborationSelection {
                issues: true,
                ..Default::default()
            },
            limits(10),
        )
        .expect("valid source");
    let rows: Vec<_> = source.chunks().collect();
    let chunks: Vec<_> = rows.iter().filter_map(|row| row.as_ref().ok()).collect();

    assert_eq!(chunks.len(), 2, "issue plus one immutable comment");
    assert_eq!(
        chunks[0].metadata.source_type.as_ref(),
        "github-collaboration"
    );
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some("github://acme/rocket/issues/7")
    );
    assert_eq!(
        chunks[0].metadata.commit.as_deref(),
        Some("I_immutable@2026-07-13T00:00:00Z")
    );
    assert_eq!(chunks[0].metadata.author.as_deref(), Some("alice"));
    assert_eq!(
        chunks[1].metadata.path.as_deref(),
        Some("github://acme/rocket/issues/7/comments/91")
    );
    issues.assert_calls(1);
    comments.assert_calls(1);
    pulls.assert_calls(0);
    graphql.assert_calls(0);
    gists.assert_calls(0);
}

#[test]
fn pull_request_text_and_both_comment_classes_reach_chunks() {
    let server = MockServer::start();
    let pulls = server.mock(|when, then| {
        when.method(Method::GET).path("/repos/acme/rocket/pulls");
        then.status(200).json_body(serde_json::json!([{
            "node_id":"PR_node","number":3,"title":"rotate",
            "body":"TOKEN=pr-secret","user":{"login":"alice"},
            "updated_at":"2026-07-13T00:00:00Z"
        }]));
    });
    let issue_comments = server.mock(|when, then| {
        when.method(Method::GET)
            .path("/repos/acme/rocket/issues/3/comments");
        then.status(200).json_body(serde_json::json!([{
            "id":10,"node_id":"PIC_node","body":"TOKEN=conversation-secret",
            "user":{"login":"bob"},"updated_at":"2026-07-13T01:00:00Z"
        }]));
    });
    let review_comments = server.mock(|when, then| {
        when.method(Method::GET)
            .path("/repos/acme/rocket/pulls/3/comments");
        then.status(200).json_body(serde_json::json!([{
            "id":11,"node_id":"PRC_node","body":"TOKEN=review-secret",
            "user":{"login":"carol"},"updated_at":"2026-07-13T02:00:00Z"
        }]));
    });
    let source = TestApi
        .github_collaboration_source_with_endpoint(
            "acme/rocket",
            &server.url(""),
            GitHubCollaborationSelection {
                pull_requests: true,
                ..Default::default()
            },
            limits(10),
        )
        .expect("valid source");
    let chunks: Vec<_> = source
        .chunks()
        .collect::<Vec<_>>()
        .into_iter()
        .collect::<Result<_, _>>()
        .expect("complete pull-request surface");
    assert_eq!(chunks.len(), 3);
    assert!(chunks.iter().any(|chunk| chunk.data.contains("pr-secret")));
    assert!(chunks
        .iter()
        .any(|chunk| chunk.data.contains("conversation-secret")));
    assert!(chunks
        .iter()
        .any(|chunk| chunk.data.contains("review-secret")));
    pulls.assert_calls(1);
    issue_comments.assert_calls(1);
    review_comments.assert_calls(1);
}

#[test]
fn discussions_use_graphql_cursor_boundary_for_text_and_comments() {
    let server = MockServer::start();
    let list = server.mock(|when, then| {
        when.method(Method::POST)
            .path("/graphql")
            .body_includes("discussions(first:100");
        then.status(200).json_body(serde_json::json!({"data":{"repository":{"discussions":{
            "nodes":[{"id":"D_node","number":5,"title":"ops","body":"TOKEN=discussion-secret","updatedAt":"2026-07-13T00:00:00Z","author":{"login":"alice"}}],
            "pageInfo":{"hasNextPage":false,"endCursor":null}
        }}}}));
    });
    let comments = server.mock(|when, then| {
        when.method(Method::POST)
            .path("/graphql")
            .body_includes("discussion(number:$number)");
        then.status(200).json_body(serde_json::json!({"data":{"repository":{"discussion":{"comments":{
            "nodes":[{"id":"DC_node","body":"TOKEN=discussion-comment","updatedAt":"2026-07-13T01:00:00Z","author":{"login":"bob"},"replies":{
                "nodes":[{"id":"DR_node","body":"TOKEN=discussion-reply","updatedAt":"2026-07-13T02:00:00Z","author":{"login":"carol"}}],
                "pageInfo":{"hasNextPage":false,"endCursor":null}
            }}],
            "pageInfo":{"hasNextPage":false,"endCursor":null}
        }}}}}));
    });
    let source = TestApi
        .github_collaboration_source_with_endpoint(
            "acme/rocket",
            &server.url(""),
            GitHubCollaborationSelection {
                discussions: true,
                ..Default::default()
            },
            limits(10),
        )
        .expect("valid source");
    let chunks: Vec<_> = source
        .chunks()
        .collect::<Vec<_>>()
        .into_iter()
        .collect::<Result<_, _>>()
        .expect("complete discussion surface");
    assert_eq!(chunks.len(), 3);
    assert_eq!(
        chunks[1].metadata.path.as_deref(),
        Some("github://acme/rocket/discussions/5/comments/DC_node")
    );
    assert_eq!(
        chunks[2].metadata.path.as_deref(),
        Some("github://acme/rocket/discussions/5/comments/DC_node/replies/DR_node")
    );
    list.assert_calls(1);
    comments.assert_calls(1);
}

#[test]
fn gist_revisions_and_comments_have_stable_provenance() {
    let server = MockServer::start();
    let _list = server.mock(|when, then| {
        when.method(Method::GET).path("/users/acme/gists");
        then.status(200)
            .json_body(serde_json::json!([{"id":"abc123"}]));
    });
    let _gist = server.mock(|when, then| {
        when.method(Method::GET).path("/gists/abc123");
        then.status(200).json_body(serde_json::json!({
            "id":"abc123","files":{},
            "history":[{"version":"0123456789abcdef","committed_at":"2026-07-13T00:00:00Z","user":{"login":"alice"}}]
        }));
    });
    let _revision = server.mock(|when, then| {
        when.method(Method::GET)
            .path("/gists/abc123/0123456789abcdef");
        then.status(200).json_body(serde_json::json!({
            "id":"abc123","history":[],
            "files":{"config?token#name.env":{"content":"TOKEN=gist-secret","truncated":false}}
        }));
    });
    let _comments = server.mock(|when, then| {
        when.method(Method::GET).path("/gists/abc123/comments");
        then.status(200).json_body(serde_json::json!([{
            "id":17,"node_id":"GC_node","body":"TOKEN=gist-comment",
            "user":{"login":"bob"},"updated_at":"2026-07-13T01:00:00Z"
        }]));
    });
    let source = TestApi
        .github_collaboration_source_with_endpoint(
            "acme/rocket",
            &server.url(""),
            GitHubCollaborationSelection {
                gists: true,
                ..Default::default()
            },
            limits(10),
        )
        .expect("valid source");
    let chunks: Vec<_> = source
        .chunks()
        .collect::<Vec<_>>()
        .into_iter()
        .collect::<Result<_, _>>()
        .expect("complete gist surface");
    assert_eq!(chunks.len(), 2);
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some("github://gists/abc123/config%3Ftoken%23name.env@0123456789abcdef")
    );
    assert_eq!(
        chunks[0].metadata.commit.as_deref(),
        Some("0123456789abcdef")
    );
    assert_eq!(
        chunks[1].metadata.path.as_deref(),
        Some("github://gists/abc123/comments/17")
    );
}

#[test]
fn wiki_history_scans_content_replaced_by_a_later_revision() {
    let temp = tempfile::tempdir().expect("temp repository");
    let repo = temp.path();
    run_git(repo, &["init", "-b", "main"]);
    run_git(repo, &["config", "user.name", "Wiki Author"]);
    run_git(repo, &["config", "user.email", "wiki@example.invalid"]);

    std::fs::write(repo.join("Home.md"), "TOKEN=old-wiki-secret\n").expect("first wiki page");
    run_git(repo, &["add", "Home.md"]);
    run_git(repo, &["commit", "-m", "first revision"]);
    std::fs::write(repo.join("Home.md"), "TOKEN=new-wiki-secret\n").expect("second wiki page");
    run_git(repo, &["add", "Home.md"]);
    run_git(repo, &["commit", "-m", "second revision"]);

    let chunks = TestApi
        .github_collaboration_wiki_chunks_from_repo(repo, limits(20))
        .expect("reachable wiki history");
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.contains("old-wiki-secret")),
        "replaced revision content must remain scanned: {chunks:?}"
    );
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.contains("new-wiki-secret")),
        "current revision content must be scanned: {chunks:?}"
    );
    assert!(chunks.iter().all(|chunk| {
        chunk.metadata.source_type.as_ref() == "github-collaboration"
            && chunk
                .metadata
                .path
                .as_deref()
                .is_some_and(|path| path.starts_with("github://acme/rocket/wiki/"))
            && chunk.metadata.commit.is_some()
    }));
}

fn run_git(repo: &std::path::Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .current_dir(repo)
        .args(args)
        .status()
        .unwrap_or_else(|error| panic!("git {args:?} failed to start: {error}"));
    assert!(status.success(), "git {args:?} failed with {status}");
}

#[test]
fn inaccessible_and_request_limit_gaps_remain_typed() {
    let inaccessible_server = MockServer::start();
    let _issues = inaccessible_server.mock(|when, then| {
        when.method(Method::GET).path("/repos/acme/rocket/issues");
        then.status(403)
            .body("credential must never enter diagnostics");
    });
    let source = TestApi
        .github_collaboration_source_with_endpoint(
            "acme/rocket",
            &inaccessible_server.url(""),
            GitHubCollaborationSelection {
                issues: true,
                ..Default::default()
            },
            limits(10),
        )
        .expect("valid source");
    let error = source
        .chunks()
        .next()
        .expect("coverage row")
        .expect_err("403 must be incomplete coverage");
    assert!(matches!(
        error,
        SourceError::Coverage {
            kind: SourceCoverageGapKind::Inaccessible,
            ..
        }
    ));
    assert!(!error.to_string().contains("credential must never"));
    assert!(!error.to_string().contains("test-token"));

    let truncated_server = MockServer::start();
    let _issues = truncated_server.mock(|when, then| {
        when.method(Method::GET).path("/repos/acme/rocket/issues");
        then.status(200).json_body(serde_json::json!([{
            "node_id":"I_node","number":7,"title":"title","body":"body",
            "user":null,"updated_at":"2026-07-13T00:00:00Z"
        }]));
    });
    let source = TestApi
        .github_collaboration_source_with_endpoint(
            "acme/rocket",
            &truncated_server.url(""),
            GitHubCollaborationSelection {
                issues: true,
                ..Default::default()
            },
            limits(1),
        )
        .expect("valid source");
    let rows: Vec<_> = source.chunks().collect();
    assert!(
        rows.iter()
            .any(|row| row.as_ref().is_ok_and(|chunk| chunk.data.contains("body"))),
        "content fetched before the request cap must still be scanned: {rows:?}"
    );
    assert!(rows.iter().any(|row| matches!(
        row,
        Err(SourceError::Coverage {
            kind: SourceCoverageGapKind::Truncated,
            ..
        })
    )));

    let response_server = MockServer::start();
    let _issues = response_server.mock(|when, then| {
        when.method(Method::GET).path("/repos/acme/rocket/issues");
        then.status(200).body("[12345678901234567890]");
    });
    let mut response_limits = limits(10);
    response_limits.web_response_bytes = 8;
    let source = TestApi
        .github_collaboration_source_with_endpoint(
            "acme/rocket",
            &response_server.url(""),
            GitHubCollaborationSelection {
                issues: true,
                ..Default::default()
            },
            response_limits,
        )
        .expect("valid source");
    let error = source
        .chunks()
        .next()
        .expect("response-cap row")
        .expect_err("oversized response must be incomplete coverage");
    assert!(matches!(
        error,
        SourceError::Coverage {
            kind: SourceCoverageGapKind::Truncated,
            ..
        }
    ));
}

#[test]
fn completed_listing_pages_survive_a_later_page_budget_failure() {
    let server = MockServer::start();
    let first_page: Vec<_> = (1..=100)
        .map(|number| {
            serde_json::json!({
                "node_id": format!("I_{number}"),
                "number": number,
                "title": format!("issue {number}"),
                "body": format!("TOKEN=page-one-{number}"),
                "user": null,
                "updated_at": "2026-07-13T00:00:00Z"
            })
        })
        .collect();
    let page_one = server.mock(|when, then| {
        when.method(Method::GET)
            .path("/repos/acme/rocket/issues")
            .query_param("page", "1");
        then.status(200)
            .json_body(serde_json::Value::Array(first_page));
    });

    let source = TestApi
        .github_collaboration_source_with_endpoint(
            "acme/rocket",
            &server.url(""),
            GitHubCollaborationSelection {
                issues: true,
                ..Default::default()
            },
            limits(1),
        )
        .expect("valid source");
    let rows: Vec<_> = source.chunks().collect();

    assert!(rows.iter().any(|row| {
        row.as_ref()
            .is_ok_and(|chunk| chunk.data.contains("TOKEN=page-one-1"))
    }));
    assert!(rows.iter().any(|row| matches!(
        row,
        Err(SourceError::Coverage {
            kind: SourceCoverageGapKind::Truncated,
            ..
        })
    )));
    page_one.assert_calls(1);
}
