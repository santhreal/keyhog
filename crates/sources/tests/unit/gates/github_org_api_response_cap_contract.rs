//! Gate `github_org`: API listing bodies use the shared response-size cap.

#[test]
fn github_org_listing_uses_shared_api_response_cap() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/github_org.rs"))
        .expect("github_org.rs readable");

    let collect = src
        .split("fn collect_org_chunks(")
        .nth(1)
        .and_then(|body| body.split("fn build_client(").next())
        .expect("collect_org_chunks body present");
    assert!(
        collect.contains("limits.web_response_bytes")
            && collect.contains("list_repos(\n        &client,\n        org,\n        limits.hosted_git_pages,\n        limits.web_response_bytes,\n    )"),
        "github-org must thread SourceLimits::web_response_bytes into repository listing"
    );

    let list_repos = src
        .split("fn list_repos(")
        .nth(1)
        .and_then(|body| body.split("fn github_listing_truncated_error(").next())
        .expect("list_repos body present");
    assert!(
        list_repos.contains("max_response_bytes: usize")
            && list_repos.contains(
                "hosted_git::read_api_json(response, \"GitHub API response\", max_response_bytes)?"
            )
            && !list_repos.contains(".json()"),
        "github-org API listing must parse through hosted_git::read_api_json with the configured cap, never reqwest::Response::json"
    );
}
