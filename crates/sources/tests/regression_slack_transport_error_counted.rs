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

#[cfg(not(feature = "slack"))]
#[test]
fn slack_transport_error_is_counted_unreadable() {
    assert!(!cfg!(feature = "slack"));
}
