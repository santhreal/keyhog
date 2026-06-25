#[cfg(feature = "slack")]
#[test]
fn slack_transport_error_is_counted_unreadable() {
    use keyhog_sources::http::HttpClientConfig;
    use keyhog_sources::testing::{SourceTestApi, TestApi};
    use keyhog_sources::{create_source_with_http_config, skip_counts};
    use std::net::TcpListener;

    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind unused Slack proxy port");
    let proxy = format!(
        "http://{}",
        listener.local_addr().expect("unused Slack proxy address")
    );
    drop(listener);

    let source = create_source_with_http_config(
        "slack",
        Some("xoxb-test-token"),
        HttpClientConfig {
            proxy: Some(proxy),
            ..Default::default()
        },
    )
    .expect("slack source can be constructed");

    let rows: Vec<_> = source.chunks().collect();
    assert_eq!(
        rows.len(),
        1,
        "Slack transport failure must produce one visible source error"
    );
    let error = rows[0]
        .as_ref()
        .expect_err("Slack transport failure must be an error row");
    assert!(
        error
            .to_string()
            .contains("Slack API conversations.list request failed"),
        "error should name the failed Slack list request, got {error}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "Slack transport failures must bump SKIPPED_UNREADABLE"
    );
}

#[cfg(feature = "slack")]
#[test]
fn slack_api_error_is_counted_unreadable() {
    use keyhog_core::Source;
    use keyhog_sources::skip_counts;
    use keyhog_sources::testing::{SourceTestApi, TestApi};

    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.list")
            .query_param("types", "public_channel,private_channel")
            .query_param("limit", "1000");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"ok":false,"error":"not_authed"}"#);
    });

    let rows: Vec<_> = TestApi
        .slack_source_with_endpoint("xoxb-test-token", server.url(""))
        .chunks()
        .collect();
    assert_eq!(
        rows.len(),
        1,
        "Slack semantic API failure must produce one visible source error"
    );
    let error = rows[0]
        .as_ref()
        .expect_err("Slack semantic API failure must be an error row");
    assert!(
        error
            .to_string()
            .contains("Slack API conversations.list error: not_authed"),
        "error should preserve Slack API endpoint and code, got {error}"
    );
    assert_eq!(list.calls(), 1, "Slack channel list request count");

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "Slack semantic API failures must bump SKIPPED_UNREADABLE"
    );
}

#[cfg(not(feature = "slack"))]
#[test]
fn slack_transport_error_is_counted_unreadable() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn slack_api_error_is_counted_unreadable() {
    assert!(!cfg!(feature = "slack"));
}
