#[cfg(feature = "slack")]
use keyhog_core::Source;
#[cfg(feature = "slack")]
use keyhog_sources::testing::{SourceTestApi, TestApi};

#[cfg(feature = "slack")]
#[test]
fn slack_channel_and_history_cursors_are_scanned() {
    let server = httpmock::MockServer::start();

    let list_page_1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.list")
            .query_param("types", "public_channel,private_channel")
            .query_param("limit", "1000")
            .query_param_missing("cursor");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ok":true,"channels":[{"id":"C1","name":"alpha"}],"response_metadata":{"next_cursor":"list-2"}}"#,
            );
    });
    let list_page_2 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.list")
            .query_param("types", "public_channel,private_channel")
            .query_param("limit", "1000")
            .query_param("cursor", "list-2");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"ok":true,"channels":[{"id":"C2","name":"beta"}]}"#);
    });

    let history_c1_page_1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.history")
            .query_param("channel", "C1")
            .query_param("limit", "1000")
            .query_param_missing("cursor");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ok":true,"messages":[{"user":"U1","text":"alpha first AKIAQYLPMN5HFIQR7XYA","ts":"1.0"}],"has_more":true,"response_metadata":{"next_cursor":"hist-c1-2"}}"#,
            );
    });
    let history_c1_page_2 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.history")
            .query_param("channel", "C1")
            .query_param("limit", "1000")
            .query_param("cursor", "hist-c1-2");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ok":true,"messages":[{"user":"U2","text":"alpha second ghp_slackSecondPageToken1234567890","ts":"2.0"}],"has_more":false}"#,
            );
    });
    let history_c2_page_1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.history")
            .query_param("channel", "C2")
            .query_param("limit", "1000")
            .query_param_missing("cursor");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ok":true,"messages":[{"user":"U3","text":"beta page ghp_slackBetaToken1234567890","ts":"3.0"}],"has_more":false}"#,
            );
    });

    let chunks = TestApi
        .slack_source_with_endpoint("xoxb-test-token", server.url(""))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("mock Slack pagination scan");
    let body = chunks
        .iter()
        .map(|chunk| chunk.data.as_ref())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        body.contains("alpha first AKIAQYLPMN5HFIQR7XYA"),
        "first channel first history page must be scanned, got {body:?}"
    );
    assert!(
        body.contains("alpha second ghp_slackSecondPageToken1234567890"),
        "first channel second history page must be scanned, got {body:?}"
    );
    assert!(
        body.contains("beta page ghp_slackBetaToken1234567890"),
        "second channel from channel-list cursor page must be scanned, got {body:?}"
    );

    assert_eq!(list_page_1.calls(), 1, "first channel list page");
    assert_eq!(list_page_2.calls(), 1, "second channel list page");
    assert_eq!(history_c1_page_1.calls(), 1, "first C1 history page");
    assert_eq!(history_c1_page_2.calls(), 1, "second C1 history page");
    assert_eq!(history_c2_page_1.calls(), 1, "C2 history page");
}

#[cfg(not(feature = "slack"))]
#[test]
fn slack_channel_and_history_cursors_are_scanned() {
    assert!(!cfg!(feature = "slack"));
}
