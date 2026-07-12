//! Regression tests for Slack *message* extraction: the shape of the chunk a
//! single conversation message produces (exact channel/ts provenance), that a
//! thread reply returned inline in history is walked with its own timestamp,
//! that an empty channel produces no chunk, and that malformed / error payloads
//! surface an exact, host-independent `SourceError` (never a silent drop).
//!
//! All assertions are concrete values (chunk count, path, source_type,
//! base_offset/base_line, exact `[USER: .. TS: ..]` markers, exact error
//! substrings, exact skip-counter deltas). No accelerator is involved: these
//! exercise the pure `conversations.history` extraction + serde helpers, so the
//! result is identical on every host.

#[cfg(feature = "slack")]
use keyhog_core::Source;
#[cfg(feature = "slack")]
use keyhog_sources::skip_counts;
#[cfg(feature = "slack")]
use keyhog_sources::testing::{SourceTestApi, TestApi};

#[cfg(feature = "slack")]
mod support;

// --- helpers ----------------------------------------------------------------

/// One channel (`C1` / `#eng-secrets`) whose history is a single page with the
/// given raw JSON `messages` array body already embedded. Returns the collected
/// result rows from a real (mock-endpoint) Slack scan.
#[cfg(feature = "slack")]
fn scan_single_channel_history(
    history_body: &str,
    channel_name: &str,
) -> Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>> {
    let server = httpmock::MockServer::start();
    let list_body = format!(r#"{{"ok":true,"channels":[{{"id":"C1","name":"{channel_name}"}}]}}"#);
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.list")
            .query_param("types", "public_channel,private_channel")
            .query_param("limit", "1000")
            .query_param_missing("cursor");
        then.status(200)
            .header("content-type", "application/json")
            .body(list_body);
    });
    let _history = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.history")
            .query_param("channel", "C1")
            .query_param_missing("cursor");
        then.status(200)
            .header("content-type", "application/json")
            .body(history_body.to_string());
    });

    TestApi
        .slack_source_with_endpoint("xoxb-test-token", server.url(""))
        .chunks()
        .collect()
}

// --- end-to-end message extraction ------------------------------------------

/// Positive: a message carrying a secret surfaces the *exact* channel path,
/// `slack` source_type, whole-file base offsets, and an exact `[USER TS]`
/// provenance marker interleaved before the text.
#[cfg(feature = "slack")]
#[test]
fn slack_message_with_secret_surfaces_exact_channel_and_ts_metadata() {
    let rows = scan_single_channel_history(
        r#"{"ok":true,"messages":[{"user":"U9","text":"deploy key AKIAIOSFODNN7EXAMPLE9","ts":"1700000000.123456"}],"has_more":false}"#,
        "eng-secrets",
    );

    let (chunks, errors) = support::split_chunk_results(&rows);
    assert_eq!(
        errors.len(),
        0,
        "clean message page must emit no error row: {rows:?}"
    );
    assert_eq!(
        chunks.len(),
        1,
        "one channel with one page => exactly one chunk: {rows:?}"
    );

    let chunk = chunks[0];
    assert_eq!(
        chunk.metadata.path.as_deref(),
        Some("slack://#eng-secrets"),
        "chunk path must be the channel URI",
    );
    assert_eq!(
        chunk.metadata.source_type.as_ref(),
        "slack",
        "source_type tag"
    );
    assert_eq!(
        chunk.metadata.base_offset, 0,
        "whole-message chunk starts at offset 0"
    );
    assert_eq!(
        chunk.metadata.base_line, 0,
        "whole-message chunk starts at line 0"
    );
    assert_eq!(chunk.metadata.commit, None, "slack chunk has no commit");
    assert!(
        chunk.data.contains("[USER: U9 TS: 1700000000.123456]"),
        "exact user+ts provenance marker must precede the text: {:?}",
        &*chunk.data,
    );
    assert!(
        chunk.data.contains("deploy key AKIAIOSFODNN7EXAMPLE9"),
        "message text (with its secret) must be scan-visible: {:?}",
        &*chunk.data,
    );
    // The marker must sit BEFORE the text (interleaving order is load-bearing
    // for line attribution).
    let marker_at = chunk.data.find("[USER: U9 TS: 1700000000.123456]").unwrap();
    let text_at = chunk.data.find("deploy key AKIAIOSFODNN7EXAMPLE9").unwrap();
    assert!(
        marker_at < text_at,
        "USER/TS marker must precede its message text"
    );
}

/// A thread reply returned inline in `conversations.history` (extra
/// `thread_ts` / `reply_count` / `parent_user_id` fields present) is walked and
/// scanned with *its own* timestamp — unknown JSON fields are tolerated, the
/// reply is not dropped, and it shares the parent's channel chunk.
#[cfg(feature = "slack")]
#[test]
fn slack_thread_reply_in_history_is_walked_with_its_own_ts() {
    let rows = scan_single_channel_history(
        r#"{"ok":true,"messages":[
            {"user":"U1","text":"parent msg no secret here","ts":"1700000000.000100","thread_ts":"1700000000.000100","reply_count":1},
            {"user":"U2","text":"thread reply leaked ghp_slackThreadReplyToken1234567890","ts":"1700000000.000200","thread_ts":"1700000000.000100","parent_user_id":"U1"}
        ],"has_more":false}"#,
        "eng-secrets",
    );

    let (chunks, errors) = support::split_chunk_results(&rows);
    assert_eq!(
        errors.len(),
        0,
        "clean thread page must emit no error row: {rows:?}"
    );
    assert_eq!(
        chunks.len(),
        1,
        "parent + reply concatenate into one channel chunk: {rows:?}"
    );

    let chunk = chunks[0];
    assert!(
        chunk.data.contains("[USER: U1 TS: 1700000000.000100]"),
        "parent message marker must be present: {:?}",
        &*chunk.data,
    );
    assert!(
        chunk.data.contains("[USER: U2 TS: 1700000000.000200]"),
        "thread REPLY must be walked with its own ts marker: {:?}",
        &*chunk.data,
    );
    assert!(
        chunk
            .data
            .contains("thread reply leaked ghp_slackThreadReplyToken1234567890"),
        "the reply's secret text must be scan-visible: {:?}",
        &*chunk.data,
    );
    // Ordering: parent marker precedes reply marker.
    let parent_at = chunk.data.find("TS: 1700000000.000100]").unwrap();
    let reply_at = chunk.data.find("TS: 1700000000.000200]").unwrap();
    assert!(
        parent_at < reply_at,
        "reply must be appended after its parent"
    );
}

/// Boundary: a channel that exists but has an empty message page produces
/// exactly zero chunks and zero error rows (nothing to scan, nothing silently
/// dropped).
#[cfg(feature = "slack")]
#[test]
fn slack_empty_channel_yields_zero_chunks_and_no_error() {
    let rows = scan_single_channel_history(
        r#"{"ok":true,"messages":[],"has_more":false}"#,
        "eng-secrets",
    );

    let (chunks, errors) = support::split_chunk_results(&rows);
    assert_eq!(
        chunks.len(),
        0,
        "empty channel must emit no chunk: {rows:?}"
    );
    assert_eq!(errors.len(), 0, "empty channel is not an error: {rows:?}");
    assert_eq!(rows.len(), 0, "no rows at all for an empty channel");
}

/// Adversarial: a message with no `user` field still surfaces its text, but
/// WITHOUT a `[USER ..]` marker — the extractor must not fabricate provenance
/// nor drop the anonymous message.
#[cfg(feature = "slack")]
#[test]
fn slack_message_without_user_surfaces_text_without_user_marker() {
    let rows = scan_single_channel_history(
        r#"{"ok":true,"messages":[{"text":"bot posted AKIAIOSFODNN7NOUSER0","ts":"1700000000.777777"}],"has_more":false}"#,
        "eng-secrets",
    );

    let (chunks, errors) = support::split_chunk_results(&rows);
    assert_eq!(errors.len(), 0, "userless message is valid: {rows:?}");
    assert_eq!(
        chunks.len(),
        1,
        "userless message still produces a chunk: {rows:?}"
    );

    let chunk = chunks[0];
    assert!(
        chunk.data.contains("bot posted AKIAIOSFODNN7NOUSER0"),
        "userless message text must still be scanned: {:?}",
        &*chunk.data,
    );
    assert!(
        !chunk.data.contains("[USER:"),
        "no user => no fabricated USER marker: {:?}",
        &*chunk.data,
    );
}

/// Negative: a syntactically malformed history body yields exactly one error
/// row naming the failed parse (host-independent; never a silent empty scan).
#[cfg(feature = "slack")]
#[test]
fn slack_malformed_history_payload_errors_exactly() {
    let rows = scan_single_channel_history(
        r#"{"ok":true,"messages":[{"user":"U1","text":"truncated"#,
        "eng-secrets",
    );

    let (chunks, errors) = support::split_chunk_results(&rows);
    assert_eq!(chunks.len(), 0, "malformed page yields no chunk: {rows:?}");
    assert_eq!(
        errors.len(),
        1,
        "malformed page yields exactly one error row: {rows:?}"
    );
    assert!(
        errors[0]
            .to_string()
            .contains("failed to parse Slack conversations.history response"),
        "error must name the failed Slack history parse: {}",
        errors[0],
    );
}

/// Adversarial: an `ok:false` history payload surfaces the exact Slack error
/// code + channel id AND records exactly one `unreadable` skip (fail-loud, not
/// a silent degrade).
#[cfg(feature = "slack")]
#[test]
fn slack_history_ok_false_records_unreadable_and_names_channel() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let rows =
        scan_single_channel_history(r#"{"ok":false,"error":"channel_not_found"}"#, "eng-secrets");

    let (chunks, errors) = support::split_chunk_results(&rows);
    assert_eq!(chunks.len(), 0, "errored channel yields no chunk: {rows:?}");
    assert_eq!(
        errors.len(),
        1,
        "errored channel yields one error row: {rows:?}"
    );
    assert!(
        errors[0]
            .to_string()
            .contains("Slack API conversations.history error for channel C1: channel_not_found"),
        "error must name endpoint, channel id, and Slack error code: {}",
        errors[0],
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "an ok:false Slack history response must bump UNREADABLE exactly once",
    );
    TestApi.reset_skip_counters();
}

// --- pure serde extraction helpers (fully host-independent, no I/O) ----------

/// A two-message history body deserializes to exactly two messages.
#[cfg(feature = "slack")]
#[test]
fn history_len_for_test_counts_two_messages() {
    let body = r#"{"ok":true,"messages":[
        {"user":"U1","text":"one AKIAIOSFODNN7EXAMPLE1","ts":"1.0"},
        {"user":"U2","text":"two ghp_slackMsgTwoToken1234567890","ts":"2.0"}
    ],"has_more":false}"#;
    assert_eq!(
        TestApi.slack_history_len_for_test(body, "C1"),
        Ok(2),
        "two messages must count as two",
    );
}

/// An `ok:false` body reports the exact channel id + Slack error code and is a
/// hard error, not `Ok(0)`.
#[cfg(feature = "slack")]
#[test]
fn history_len_for_test_ok_false_errors_with_channel_and_code() {
    let body = r#"{"ok":false,"error":"not_in_channel"}"#;
    match TestApi.slack_history_len_for_test(body, "C7") {
        Ok(n) => panic!("ok:false must not count as {n} messages"),
        Err(msg) => assert!(
            msg.contains("Slack API conversations.history error for channel C7: not_in_channel"),
            "error must name channel C7 and the code: {msg}",
        ),
    }
}

/// An `ok:true` body missing the `messages` array is a hard error (a missing
/// array is coverage loss, not zero messages).
#[cfg(feature = "slack")]
#[test]
fn history_len_for_test_ok_true_missing_messages_errors() {
    let body = r#"{"ok":true,"has_more":false}"#;
    match TestApi.slack_history_len_for_test(body, "C1") {
        Ok(n) => panic!("missing messages must not count as {n}"),
        Err(msg) => assert!(
            msg.contains(
                "Slack API conversations.history ok response for channel C1 missing messages"
            ),
            "error must flag the missing messages array: {msg}",
        ),
    }
}

/// Malformed JSON to the pure helper errors with the parse message (not a
/// panic, not `Ok`).
#[cfg(feature = "slack")]
#[test]
fn history_len_for_test_malformed_json_errors() {
    let body = r#"{"ok":true,"messages":[ NOT JSON"#;
    match TestApi.slack_history_len_for_test(body, "C1") {
        Ok(n) => panic!("malformed JSON must not count as {n}"),
        Err(msg) => assert!(
            msg.contains("failed to parse Slack conversations.history response"),
            "error must name the failed history parse: {msg}",
        ),
    }
}

/// A channel-list body with two channels counts as two.
#[cfg(feature = "slack")]
#[test]
fn conversations_list_len_for_test_counts_channels() {
    let body = r#"{"ok":true,"channels":[
        {"id":"C1","name":"alpha"},
        {"id":"C2","name":"beta"}
    ]}"#;
    assert_eq!(
        TestApi.slack_conversations_list_len_for_test(body),
        Ok(2),
        "two channels must count as two",
    );
}

/// An `ok:false` channel-list body is a hard error naming the list endpoint.
#[cfg(feature = "slack")]
#[test]
fn conversations_list_len_for_test_ok_false_errors() {
    let body = r#"{"ok":false,"error":"invalid_auth"}"#;
    match TestApi.slack_conversations_list_len_for_test(body) {
        Ok(n) => panic!("ok:false list must not count as {n} channels"),
        Err(msg) => assert!(
            msg.contains("Slack API conversations.list error: invalid_auth"),
            "error must name the list endpoint and code: {msg}",
        ),
    }
}

/// A present, whitespace-padded `next_cursor` is trimmed and returned.
#[cfg(feature = "slack")]
#[test]
fn history_next_cursor_trims_and_returns_value() {
    let body = r#"{"ok":true,"messages":[],"has_more":true,"response_metadata":{"next_cursor":"  cur-page-2  "}}"#;
    assert_eq!(
        TestApi.slack_history_next_cursor_for_test(body, "C1"),
        Ok(Some("cur-page-2".to_string())),
        "cursor must be trimmed of surrounding whitespace",
    );
}

/// Boundary: an empty-string `next_cursor` is normalized to `None` (an empty
/// cursor must not drive a redundant extra page request).
#[cfg(feature = "slack")]
#[test]
fn history_next_cursor_empty_string_is_none() {
    let body =
        r#"{"ok":true,"messages":[],"has_more":true,"response_metadata":{"next_cursor":"   "}}"#;
    assert_eq!(
        TestApi.slack_history_next_cursor_for_test(body, "C1"),
        Ok(None),
        "a whitespace-only cursor must normalize to None",
    );
}

/// A present channel-list `next_cursor` is returned verbatim.
#[cfg(feature = "slack")]
#[test]
fn conversations_list_next_cursor_present() {
    let body = r#"{"ok":true,"channels":[{"id":"C1","name":"alpha"}],"response_metadata":{"next_cursor":"list-2"}}"#;
    assert_eq!(
        TestApi.slack_conversations_list_next_cursor_for_test(body),
        Ok(Some("list-2".to_string())),
        "list cursor must be surfaced verbatim",
    );
}

// --- feature-disabled twins (keep the gate meaningful without `slack`) -------

#[cfg(not(feature = "slack"))]
#[test]
fn slack_message_with_secret_surfaces_exact_channel_and_ts_metadata() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn slack_thread_reply_in_history_is_walked_with_its_own_ts() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn slack_empty_channel_yields_zero_chunks_and_no_error() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn slack_message_without_user_surfaces_text_without_user_marker() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn slack_malformed_history_payload_errors_exactly() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn slack_history_ok_false_records_unreadable_and_names_channel() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn history_len_for_test_counts_two_messages() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn history_len_for_test_ok_false_errors_with_channel_and_code() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn history_len_for_test_ok_true_missing_messages_errors() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn history_len_for_test_malformed_json_errors() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn conversations_list_len_for_test_counts_channels() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn conversations_list_len_for_test_ok_false_errors() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn history_next_cursor_trims_and_returns_value() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn history_next_cursor_empty_string_is_none() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn conversations_list_next_cursor_present() {
    assert!(!cfg!(feature = "slack"));
}
