#[cfg(feature = "slack")]
use keyhog_core::Source;
#[cfg(feature = "slack")]
use keyhog_sources::testing::{SourceTestApi, TestApi};
#[cfg(feature = "slack")]
use keyhog_sources::{skip_counts, SourceLimits};

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
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

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

    let rows: Vec<_> = TestApi
        .slack_source_with_endpoint_and_lookback("xoxb-test-token", server.url(""), 3)
        .chunks()
        .collect();
    let body = rows
        .iter()
        .filter_map(|row| row.as_ref().ok())
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
    assert!(
        rows.iter().any(|row| row.as_ref().is_err_and(|error| {
            error
                .to_string()
                .contains("Slack API conversations.history history for channel C1 reached the 3-message lookback cap")
        })),
        "lookback cap must surface an explicit source-truncation row: {rows:?}"
    );

    let after = skip_counts();
    assert_eq!(
        after.source_truncated - before.source_truncated,
        1,
        "Slack lookback cap with remaining history must bump SOURCE_TRUNCATED once"
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
    assert_eq!(
        list_page.calls(),
        0,
        "zero lookback must not list Slack channels"
    );
    assert_eq!(
        history_page.calls(),
        0,
        "zero lookback must not make conversations.history requests"
    );
}

#[cfg(feature = "slack")]
#[test]
fn slack_channel_list_page_cap_is_counted_source_truncated() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let list_page = server.mock(|when, then| {
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
    let history_page = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.history")
            .query_param("channel", "C1")
            .query_param("limit", "1000")
            .query_param_missing("cursor");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ok":true,"messages":[{"user":"U1","text":"list cap preserves listed channel ghp_slackListCapToken1234567890","ts":"1.0"}],"has_more":false}"#,
            );
    });
    let limits = SourceLimits {
        hosted_git_pages: 1,
        ..Default::default()
    };

    let rows: Vec<_> = TestApi
        .slack_source_with_endpoint_and_limits("xoxb-test-token", server.url(""), limits)
        .chunks()
        .collect();

    assert_eq!(list_page.calls(), 1, "first channel list page");
    assert_eq!(history_page.calls(), 1, "listed channel history page");
    assert_eq!(
        rows.iter().filter(|row| row.is_err()).count(),
        1,
        "truncated channel listing must produce one visible error row: {rows:?}"
    );
    assert!(
        rows.iter().any(|row| row.as_ref().is_ok_and(|chunk| {
            chunk.data.contains("ghp_slackListCapToken1234567890")
                && chunk.metadata.path.as_deref() == Some("slack://#alpha")
        })),
        "first listed channel must remain scan-visible when listing is truncated: {rows:?}"
    );
    assert!(
        rows.iter().any(|row| row.as_ref().is_err_and(|error| {
            error
                .to_string()
                .contains("Slack API conversations.list channel listing exceeded 1 pages")
        })),
        "error must describe Slack channel listing truncation: {rows:?}"
    );

    let after = skip_counts();
    assert_eq!(
        after.source_truncated - before.source_truncated,
        1,
        "Slack channel-list page cap must bump SOURCE_TRUNCATED once"
    );
}

#[cfg(feature = "slack")]
#[test]
fn slack_history_page_cap_preserves_page_and_counts_source_truncated() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

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
            .query_param("channel", "C1")
            .query_param("limit", "1000")
            .query_param_missing("cursor");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ok":true,"messages":[{"user":"U1","text":"history cap keeps first page ghp_slackHistoryCapToken1234567890","ts":"1.0"}],"has_more":true,"response_metadata":{"next_cursor":"hist-c1-2"}}"#,
            );
    });
    let second_history_page = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.history")
            .query_param("channel", "C1")
            .query_param("cursor", "hist-c1-2");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ok":true,"messages":[{"user":"U2","text":"history cap must not request second page","ts":"2.0"}],"has_more":false}"#,
            );
    });
    let limits = SourceLimits {
        hosted_git_pages: 1,
        ..Default::default()
    };

    let rows: Vec<_> = TestApi
        .slack_source_with_endpoint_and_limits("xoxb-test-token", server.url(""), limits)
        .chunks()
        .collect();

    assert_eq!(list_page.calls(), 1, "channel list page");
    assert_eq!(history_page.calls(), 1, "first history page");
    assert_eq!(
        second_history_page.calls(),
        0,
        "history page cap must stop before the next cursor request"
    );
    assert!(
        rows.iter().any(|row| row
            .as_ref()
            .is_ok_and(|chunk| { chunk.data.contains("ghp_slackHistoryCapToken1234567890") })),
        "first history page must remain scan-visible when later pages are truncated: {rows:?}"
    );
    assert!(
        rows.iter().any(|row| row.as_ref().is_err_and(|error| {
            error
                .to_string()
                .contains("Slack API conversations.history history for channel C1 exceeded 1 pages")
        })),
        "history page cap must surface a visible truncation error: {rows:?}"
    );

    let after = skip_counts();
    assert_eq!(
        after.source_truncated - before.source_truncated,
        1,
        "Slack history page cap must bump SOURCE_TRUNCATED once"
    );
}

#[cfg(feature = "slack")]
#[test]
fn slack_history_cursor_with_has_more_false_stops_without_extra_request() {
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
            .query_param("channel", "C1")
            .query_param("limit", "1000")
            .query_param_missing("cursor");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ok":true,"messages":[{"user":"U1","text":"cursor false stop ghp_slackCursorFalseToken1234567890","ts":"1.0"}],"has_more":false,"response_metadata":{"next_cursor":"ignored-cursor"}}"#,
            );
    });
    let redundant_history_page = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.history")
            .query_param("channel", "C1")
            .query_param("cursor", "ignored-cursor");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ok":true,"messages":[{"user":"U2","text":"has_more false cursor must not be requested","ts":"2.0"}],"has_more":false}"#,
            );
    });

    let rows: Vec<_> = TestApi
        .slack_source_with_endpoint("xoxb-test-token", server.url(""))
        .chunks()
        .collect();

    assert_eq!(list_page.calls(), 1, "channel list page");
    assert_eq!(history_page.calls(), 1, "first history page");
    assert_eq!(
        redundant_history_page.calls(),
        0,
        "has_more=false must stop history pagination even if Slack sends a cursor"
    );
    assert!(
        rows.iter().all(Result::is_ok),
        "has_more=false with a cursor must not emit an error row: {rows:?}"
    );
    assert!(
        rows.iter().any(|row| row.as_ref().is_ok_and(|chunk| {
            chunk.data.contains("ghp_slackCursorFalseToken1234567890")
                && chunk.metadata.path.as_deref() == Some("slack://#alpha")
        })),
        "first page must remain scan-visible: {rows:?}"
    );
}

#[cfg(feature = "slack")]
#[test]
fn slack_history_has_more_without_cursor_preserves_page_and_counts_source_truncated() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

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
            .query_param("channel", "C1")
            .query_param("limit", "1000")
            .query_param_missing("cursor");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ok":true,"messages":[{"user":"U1","text":"missing cursor keeps page ghp_slackMissingCursorToken1234567890","ts":"1.0"}],"has_more":true}"#,
            );
    });

    let rows: Vec<_> = TestApi
        .slack_source_with_endpoint("xoxb-test-token", server.url(""))
        .chunks()
        .collect();

    assert_eq!(list_page.calls(), 1, "channel list page");
    assert_eq!(history_page.calls(), 1, "history page");
    assert!(
        rows.iter().any(|row| row.as_ref().is_ok_and(|chunk| {
            chunk.data.contains("ghp_slackMissingCursorToken1234567890")
                && chunk.metadata.path.as_deref() == Some("slack://#alpha")
        })),
        "history page must remain scan-visible when Slack omits the next cursor: {rows:?}"
    );
    assert!(
        rows.iter().any(|row| row.as_ref().is_err_and(|error| {
            error.to_string().contains(
                "Slack API conversations.history history for channel C1 indicated more pages without a next cursor",
            )
        })),
        "missing cursor must emit the specific truncation error: {rows:?}"
    );

    let after = skip_counts();
    assert_eq!(
        after.source_truncated - before.source_truncated,
        1,
        "missing Slack history cursor must bump SOURCE_TRUNCATED once"
    );
}

#[cfg(feature = "slack")]
#[test]
fn slack_multiple_history_truncations_count_source_truncated_once() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let list_page = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.list")
            .query_param("types", "public_channel,private_channel")
            .query_param("limit", "1000")
            .query_param_missing("cursor");
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
            .query_param("limit", "1000")
            .query_param_missing("cursor");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ok":true,"messages":[{"user":"U1","text":"alpha truncated ghp_slackAlphaTruncatedToken1234567890","ts":"1.0"}],"has_more":true}"#,
            );
    });
    let beta_history = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.history")
            .query_param("channel", "C2")
            .query_param("limit", "1000")
            .query_param_missing("cursor");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ok":true,"messages":[{"user":"U2","text":"beta truncated ghp_slackBetaTruncatedToken1234567890","ts":"2.0"}],"has_more":true}"#,
            );
    });

    let rows: Vec<_> = TestApi
        .slack_source_with_endpoint("xoxb-test-token", server.url(""))
        .chunks()
        .collect();

    assert_eq!(list_page.calls(), 1, "channel list page");
    assert_eq!(alpha_history.calls(), 1, "alpha history page");
    assert_eq!(beta_history.calls(), 1, "beta history page");
    assert!(
        rows.iter().any(|row| row.as_ref().is_ok_and(|chunk| {
            chunk
                .data
                .contains("ghp_slackAlphaTruncatedToken1234567890")
                && chunk.metadata.path.as_deref() == Some("slack://#alpha")
        })),
        "alpha partial page must remain scan-visible: {rows:?}"
    );
    assert!(
        rows.iter().any(|row| row.as_ref().is_ok_and(|chunk| {
            chunk.data.contains("ghp_slackBetaTruncatedToken1234567890")
                && chunk.metadata.path.as_deref() == Some("slack://#beta")
        })),
        "beta partial page must remain scan-visible: {rows:?}"
    );
    assert_eq!(
        rows.iter()
            .filter(|row| row.as_ref().is_err_and(|error| {
                error
                    .to_string()
                    .contains("indicated more pages without a next cursor")
            }))
            .count(),
        2,
        "each truncated channel must keep its own visible error row: {rows:?}"
    );

    let after = skip_counts();
    assert_eq!(
        after.source_truncated - before.source_truncated,
        1,
        "multiple Slack history truncations in one source must bump SOURCE_TRUNCATED once"
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

#[cfg(not(feature = "slack"))]
#[test]
fn slack_channel_list_page_cap_is_counted_source_truncated() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn slack_history_page_cap_preserves_page_and_counts_source_truncated() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn slack_history_cursor_with_has_more_false_stops_without_extra_request() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn slack_history_has_more_without_cursor_preserves_page_and_counts_source_truncated() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn slack_multiple_history_truncations_count_source_truncated_once() {
    assert!(!cfg!(feature = "slack"));
}
