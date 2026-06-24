#[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
fn unused_proxy_url(label: &str) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|error| panic!("bind unused {label} proxy port: {error}"));
    let proxy = format!(
        "http://{}",
        listener
            .local_addr()
            .unwrap_or_else(|error| panic!("read unused {label} proxy address: {error}"))
    );
    drop(listener);
    proxy
}

#[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
fn http_with_unused_proxy(label: &str) -> keyhog_sources::http::HttpClientConfig {
    keyhog_sources::http::HttpClientConfig {
        proxy: Some(unused_proxy_url(label)),
        ..Default::default()
    }
}

#[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
fn assert_one_unreadable_error(
    source: Box<dyn keyhog_core::Source>,
    before: keyhog_sources::SkipCounts,
    expected: &str,
) {
    let rows: Vec<_> = source.chunks().collect();
    assert_eq!(
        rows.len(),
        1,
        "hosted Git API transport failure must produce one visible source error"
    );
    let error = rows[0]
        .as_ref()
        .expect_err("hosted Git API transport failure must be an error row");
    assert!(
        error.to_string().contains(expected),
        "error should contain {expected:?}, got {error}"
    );
    let after = keyhog_sources::skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "hosted Git API transport failure must bump SKIPPED_UNREADABLE"
    );
}

#[cfg(feature = "github")]
#[test]
fn github_api_transport_error_is_counted_unreadable() {
    use keyhog_sources::testing::{SourceTestApi, TestApi};

    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let before = keyhog_sources::skip_counts();
    let source = keyhog_sources::create_source_with_http_config(
        "github-org",
        Some("acme\nghp_testtoken"),
        http_with_unused_proxy("GitHub"),
    )
    .expect("github-org source can be constructed");

    assert_one_unreadable_error(source, before, "GitHub API request failed");
}

#[cfg(feature = "gitlab")]
#[test]
fn gitlab_api_transport_error_is_counted_unreadable() {
    use keyhog_sources::testing::{SourceTestApi, TestApi};

    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let before = keyhog_sources::skip_counts();
    let source = keyhog_sources::create_source_with_http_config(
        "gitlab-group",
        Some("acme\nglt_testtoken"),
        http_with_unused_proxy("GitLab"),
    )
    .expect("gitlab-group source can be constructed");

    assert_one_unreadable_error(source, before, "GitLab API request failed");
}

#[cfg(feature = "bitbucket")]
#[test]
fn bitbucket_api_transport_error_is_counted_unreadable() {
    use keyhog_sources::testing::{SourceTestApi, TestApi};

    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let before = keyhog_sources::skip_counts();
    let source = keyhog_sources::create_source_with_http_config(
        "bitbucket-workspace",
        Some("acme\nuser\napp-password"),
        http_with_unused_proxy("Bitbucket"),
    )
    .expect("bitbucket-workspace source can be constructed");

    assert_one_unreadable_error(source, before, "Bitbucket API request failed");
}

#[cfg(not(any(feature = "github", feature = "gitlab", feature = "bitbucket")))]
#[test]
fn hosted_git_api_transport_error_is_counted_unreadable() {
    assert!(!cfg!(any(
        feature = "github",
        feature = "gitlab",
        feature = "bitbucket"
    )));
}
