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

#[cfg(feature = "slack")]
#[test]
fn slack_channel_failure_preserves_sibling_chunks() {
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
            .body(
                r#"{"ok":true,"channels":[{"id":"C1","name":"alpha"},{"id":"C2","name":"beta"}]}"#,
            );
    });
    let alpha_history = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.history")
            .query_param("channel", "C1")
            .query_param("limit", "1000");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ok":true,"messages":[{"user":"U1","text":"alpha page ghp_slackSiblingToken1234567890","ts":"1.0"}],"has_more":false}"#,
            );
    });
    let beta_history = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.history")
            .query_param("channel", "C2")
            .query_param("limit", "1000");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"ok":false,"error":"channel_not_found"}"#);
    });

    let rows: Vec<_> = TestApi
        .slack_source_with_endpoint("xoxb-test-token", server.url(""))
        .chunks()
        .collect();
    assert_eq!(list.calls(), 1, "Slack channel list request count");
    assert_eq!(
        alpha_history.calls(),
        1,
        "healthy channel history request count"
    );
    assert_eq!(
        beta_history.calls(),
        1,
        "failing channel history request count"
    );
    assert!(
        rows.iter().any(|row| row
            .as_ref()
            .is_ok_and(|chunk| chunk.data.contains("ghp_slackSiblingToken1234567890"))),
        "healthy sibling channel chunk must survive failed channel: {rows:?}"
    );
    assert!(
        rows.iter().any(|row| row
            .as_ref()
            .is_err_and(|error| error.to_string().contains("channel_not_found"))),
        "failed sibling channel must remain visible as an error row: {rows:?}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "one failed Slack channel must bump SKIPPED_UNREADABLE once"
    );
}

#[cfg(feature = "slack")]
#[test]
fn slack_late_history_failure_preserves_prior_channel_chunks() {
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
            .body(r#"{"ok":true,"channels":[{"id":"C1","name":"alpha"}]}"#);
    });
    let first_history_page = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.history")
            .query_param("channel", "C1")
            .query_param("limit", "3")
            .query_param_missing("cursor");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ok":true,"messages":[{"user":"U1","text":"alpha first page ghp_slackLateFailureToken1234567890","ts":"1.0"}],"has_more":true,"response_metadata":{"next_cursor":"hist-c1-2"}}"#,
            );
    });
    let failing_history_page = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.history")
            .query_param("channel", "C1")
            .query_param("limit", "2")
            .query_param("cursor", "hist-c1-2");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"ok":false,"error":"ratelimited"}"#);
    });

    let rows: Vec<_> = TestApi
        .slack_source_with_endpoint_and_lookback("xoxb-test-token", server.url(""), 3)
        .chunks()
        .collect();

    assert_eq!(list.calls(), 1, "Slack channel list request count");
    assert_eq!(
        first_history_page.calls(),
        1,
        "first channel history page request count"
    );
    assert_eq!(
        failing_history_page.calls(),
        1,
        "failing channel history page request count"
    );
    assert!(
        rows.iter().any(|row| row.as_ref().is_ok_and(|chunk| {
            chunk.data.contains("ghp_slackLateFailureToken1234567890")
                && chunk.metadata.path.as_deref() == Some("slack://#alpha")
        })),
        "messages fetched before a later page failure must still be scanned: {rows:?}"
    );
    assert!(
        rows.iter().any(|row| row
            .as_ref()
            .is_err_and(|error| error.to_string().contains("ratelimited"))),
        "late history failure must remain visible as an error row: {rows:?}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "one late Slack history failure must bump SKIPPED_UNREADABLE once"
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

#[cfg(not(feature = "slack"))]
#[test]
fn slack_channel_failure_preserves_sibling_chunks() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn slack_late_history_failure_preserves_prior_channel_chunks() {
    assert!(!cfg!(feature = "slack"));
}
