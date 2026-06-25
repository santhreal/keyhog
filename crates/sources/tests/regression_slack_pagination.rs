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
            .query_param("limit", "999")
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

#[cfg(feature = "slack")]
#[test]
fn slack_history_lookback_is_total_cap() {
    let server = httpmock::MockServer::start();

    let list_page = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.list")
            .query_param("types", "public_channel,private_channel")
            .query_param("limit", "1000")
            .query_param_missing("cursor");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"ok":true,"channels":[{"id":"C1","name":"alpha"}]}"#);
    });
    let history_page_1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.history")
            .query_param("channel", "C1")
            .query_param("limit", "3")
            .query_param_missing("cursor");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ok":true,"messages":[{"user":"U1","text":"lookback one AKIAQYLPMN5HFIQR7XYA","ts":"1.0"},{"user":"U2","text":"lookback two ghp_slackLookbackTwo1234567890","ts":"2.0"}],"has_more":true,"response_metadata":{"next_cursor":"hist-c1-2"}}"#,
            );
    });
    let history_page_2 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.history")
            .query_param("channel", "C1")
            .query_param("limit", "1")
            .query_param("cursor", "hist-c1-2");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ok":true,"messages":[{"user":"U3","text":"lookback three ghp_slackLookbackThree1234567890","ts":"3.0"},{"user":"U4","text":"lookback four must not be scanned","ts":"4.0"}],"has_more":true,"response_metadata":{"next_cursor":"hist-c1-3"}}"#,
            );
    });
    let history_page_3 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.history")
            .query_param("channel", "C1")
            .query_param("cursor", "hist-c1-3");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ok":true,"messages":[{"user":"U5","text":"lookback five must not be requested","ts":"5.0"}],"has_more":false}"#,
            );
    });

    let chunks = TestApi
        .slack_source_with_endpoint_and_lookback("xoxb-test-token", server.url(""), 3)
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("mock Slack lookback scan");
    let body = chunks
        .iter()
        .map(|chunk| chunk.data.as_ref())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        body.contains("lookback one AKIAQYLPMN5HFIQR7XYA"),
        "first message must be scanned, got {body:?}"
    );
    assert!(
        body.contains("lookback two ghp_slackLookbackTwo1234567890"),
        "second message must be scanned, got {body:?}"
    );
    assert!(
        body.contains("lookback three ghp_slackLookbackThree1234567890"),
        "third message must be scanned, got {body:?}"
    );
    assert!(
        !body.contains("lookback four must not be scanned"),
        "over-returned fourth message must not exceed lookback cap, got {body:?}"
    );
    assert!(
        !body.contains("lookback five must not be requested"),
        "source must stop once total lookback cap is reached, got {body:?}"
    );

    assert_eq!(list_page.calls(), 1, "channel list page");
    assert_eq!(history_page_1.calls(), 1, "first history page");
    assert_eq!(history_page_2.calls(), 1, "second history page");
    assert_eq!(
        history_page_3.calls(),
        0,
        "history pagination must stop at the total lookback cap"
    );
}

#[cfg(feature = "slack")]
#[test]
fn slack_history_zero_lookback_skips_history_requests() {
    let server = httpmock::MockServer::start();

    let list_page = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.list")
            .query_param("types", "public_channel,private_channel")
            .query_param("limit", "1000")
            .query_param_missing("cursor");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"ok":true,"channels":[{"id":"C1","name":"alpha"}]}"#);
    });
    let history_page = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.history")
            .query_param("channel", "C1");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ok":true,"messages":[{"user":"U1","text":"zero lookback must not request history","ts":"1.0"}],"has_more":false}"#,
            );
    });

    let chunks = TestApi
        .slack_source_with_endpoint_and_lookback("xoxb-test-token", server.url(""), 0)
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("mock Slack zero-lookback scan");

    assert!(
        chunks.is_empty(),
        "zero lookback should not emit Slack history chunks, got {chunks:?}"
    );
    assert_eq!(list_page.calls(), 1, "channel list page");
    assert_eq!(
        history_page.calls(),
        0,
        "zero lookback must not make conversations.history requests"
    );
}

#[cfg(not(feature = "slack"))]
#[test]
fn slack_channel_and_history_cursors_are_scanned() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn slack_history_lookback_is_total_cap() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn slack_history_zero_lookback_skips_history_requests() {
    assert!(!cfg!(feature = "slack"));
}
