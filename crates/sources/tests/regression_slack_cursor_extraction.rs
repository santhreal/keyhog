//! Pure-parse Slack cursor-extraction regressions.
//!
//! `regression_slack_pagination.rs` drives the full multi-page fetch loop over
//! an httpmock server; `regression_slack_message.rs` covers message/channel
//! counting plus the happy-path cursor cases. This file locks the remaining
//! pure `slack_*_next_cursor_for_test` / `slack_*_len_for_test` edges with NO
//! network: endpoint twins that existed for only one side, absent
//! `response_metadata`, malformed-JSON error strings, ok=false error-code
//! normalization, and the fact that cursor extraction is independent of the
//! `has_more` stop signal.
//!
//! `SlackSource::Other(msg).to_string()` wraps the inner reason as
//! `failed to read source: {msg}. Fix: ...`, so every error assertion checks the
//! inner reason with `.contains`, never a whole-string `==`.

#[cfg(feature = "slack")]
use keyhog_sources::testing::{SourceTestApi, TestApi};

// --- boundary: empty / whitespace-only cursor normalizes to None -------------

/// Twin of the history empty-cursor case for the channel-list endpoint: a
/// whitespace-only `next_cursor` must normalize to `None` so it never drives a
/// redundant extra channel-list page.
#[cfg(feature = "slack")]
#[test]
fn list_next_cursor_whitespace_only_is_none() {
    let body = r#"{"ok":true,"channels":[{"id":"C1","name":"alpha"}],"response_metadata":{"next_cursor":"   "}}"#;
    assert_eq!(
        TestApi.slack_conversations_list_next_cursor_for_test(body),
        Ok(None),
        "a whitespace-only channel-list cursor must normalize to None",
    );
}

/// An entirely absent `response_metadata` object on the channel list yields no
/// cursor (`None`), not an error.
#[cfg(feature = "slack")]
#[test]
fn list_next_cursor_absent_metadata_is_none() {
    let body = r#"{"ok":true,"channels":[{"id":"C1","name":"alpha"}]}"#;
    assert_eq!(
        TestApi.slack_conversations_list_next_cursor_for_test(body),
        Ok(None),
        "no response_metadata must mean no channel-list cursor",
    );
}

/// An entirely absent `response_metadata` object on history yields `None`.
#[cfg(feature = "slack")]
#[test]
fn history_next_cursor_absent_metadata_is_none() {
    let body = r#"{"ok":true,"messages":[{"user":"U1","text":"hi","ts":"1.0"}],"has_more":true}"#;
    assert_eq!(
        TestApi.slack_history_next_cursor_for_test(body, "C1"),
        Ok(None),
        "history without response_metadata must yield no cursor",
    );
}

// --- adversarial: tab / newline padding is trimmed ---------------------------

/// Only space padding was covered before; assert tab + newline padding is also
/// stripped by the `.trim()` normalization to the bare cursor value.
#[cfg(feature = "slack")]
#[test]
fn history_next_cursor_trims_tab_and_newline_padding() {
    let body = "{\"ok\":true,\"messages\":[],\"has_more\":true,\"response_metadata\":{\"next_cursor\":\"\\t\\ncur-tabnl\\n \"}}";
    assert_eq!(
        TestApi.slack_history_next_cursor_for_test(body, "C1"),
        Ok(Some("cur-tabnl".to_string())),
        "tab/newline padding around a cursor must be trimmed to the bare value",
    );
}

// --- cursor extraction is independent of the has_more stop signal ------------

/// The pure cursor helper extracts `next_cursor` regardless of `has_more`: the
/// pagination-stop decision (has_more=false) lives in `fetch_history`, not in
/// cursor extraction. A body with `has_more:false` but a present cursor must
/// still surface that cursor verbatim from the parser.
#[cfg(feature = "slack")]
#[test]
fn history_next_cursor_present_even_when_has_more_false() {
    let body = r#"{"ok":true,"messages":[{"user":"U1","text":"x","ts":"1.0"}],"has_more":false,"response_metadata":{"next_cursor":"ignored-cursor"}}"#;
    assert_eq!(
        TestApi.slack_history_next_cursor_for_test(body, "C1"),
        Ok(Some("ignored-cursor".to_string())),
        "cursor extraction must be independent of the has_more stop flag",
    );
}

/// Cursor extraction does not depend on how many channels the page carries: a
/// two-channel list with a cursor returns that cursor, and the sibling
/// len-helper counts exactly two channels for the same body.
#[cfg(feature = "slack")]
#[test]
fn list_next_cursor_returns_cursor_and_len_counts_two_channels() {
    let body = r#"{"ok":true,"channels":[{"id":"C1","name":"alpha"},{"id":"C2","name":"beta"}],"response_metadata":{"next_cursor":"list-99"}}"#;
    assert_eq!(
        TestApi.slack_conversations_list_next_cursor_for_test(body),
        Ok(Some("list-99".to_string())),
        "multi-channel list page must still surface its cursor",
    );
    assert_eq!(
        TestApi.slack_conversations_list_len_for_test(body),
        Ok(2),
        "the same body must count exactly two channels",
    );
}

// --- error paths: ok=false surfaces the endpoint-specific error code ----------

/// Channel-list ok=false through the cursor helper surfaces the list endpoint
/// name and the verbatim error code (wrapped by SourceError::Other Display).
#[cfg(feature = "slack")]
#[test]
fn list_next_cursor_ok_false_names_list_endpoint_and_code() {
    let body = r#"{"ok":false,"error":"invalid_auth"}"#;
    match TestApi.slack_conversations_list_next_cursor_for_test(body) {
        Ok(other) => panic!("ok=false must error, got Ok({other:?})"),
        Err(message) => {
            assert!(
                message.contains("Slack API conversations.list error: invalid_auth"),
                "list error must name the endpoint and code: {message:?}",
            );
        }
    }
}

/// History ok=false through the cursor helper names the channel id and the code.
#[cfg(feature = "slack")]
#[test]
fn history_next_cursor_ok_false_names_channel_and_code() {
    let body = r#"{"ok":false,"error":"channel_not_found"}"#;
    match TestApi.slack_history_next_cursor_for_test(body, "C42") {
        Ok(other) => panic!("ok=false must error, got Ok({other:?})"),
        Err(message) => {
            assert!(
                message.contains(
                    "Slack API conversations.history error for channel C42: channel_not_found"
                ),
                "history error must name the channel and code: {message:?}",
            );
        }
    }
}

/// A whitespace-only `error` field on an ok=false response normalizes to the
/// `<no error field>` sentinel rather than surfacing blank whitespace.
#[cfg(feature = "slack")]
#[test]
fn list_next_cursor_ok_false_blank_error_normalizes_to_sentinel() {
    let body = r#"{"ok":false,"error":"   "}"#;
    match TestApi.slack_conversations_list_next_cursor_for_test(body) {
        Ok(other) => panic!("ok=false must error, got Ok({other:?})"),
        Err(message) => {
            assert!(
                message.contains("Slack API conversations.list error: <no error field>"),
                "blank error code must normalize to the <no error field> sentinel: {message:?}",
            );
        }
    }
}

// --- error paths: ok=true but missing the payload array -----------------------

/// History ok=true with no `messages` array errors, naming the channel.
#[cfg(feature = "slack")]
#[test]
fn history_next_cursor_ok_true_missing_messages_errors() {
    let body = r#"{"ok":true,"has_more":true,"response_metadata":{"next_cursor":"c2"}}"#;
    match TestApi.slack_history_next_cursor_for_test(body, "C9") {
        Ok(other) => panic!("missing messages must error, got Ok({other:?})"),
        Err(message) => {
            assert!(
                message.contains(
                    "Slack API conversations.history ok response for channel C9 missing messages"
                ),
                "missing-messages error must name the channel: {message:?}",
            );
        }
    }
}

/// Channel-list ok=true with no `channels` array errors (the len-helper twin of
/// the history missing-messages case).
#[cfg(feature = "slack")]
#[test]
fn list_len_ok_true_missing_channels_errors() {
    let body = r#"{"ok":true,"response_metadata":{"next_cursor":"x"}}"#;
    match TestApi.slack_conversations_list_len_for_test(body) {
        Ok(count) => panic!("missing channels must error, got Ok({count})"),
        Err(message) => {
            assert!(
                message.contains("Slack API conversations.list ok response missing channels"),
                "missing-channels error must name the list endpoint: {message:?}",
            );
        }
    }
}

// --- error paths: malformed JSON surfaces the parse error per endpoint --------

/// Malformed JSON through the history cursor helper surfaces the history parse
/// error string.
#[cfg(feature = "slack")]
#[test]
fn history_next_cursor_malformed_json_names_history_parse() {
    let body = r#"{"ok":true,"messages":[{"user":"#; // truncated / invalid
    match TestApi.slack_history_next_cursor_for_test(body, "C1") {
        Ok(other) => panic!("malformed JSON must error, got Ok({other:?})"),
        Err(message) => {
            assert!(
                message.contains("failed to parse Slack conversations.history response"),
                "history parse error must name the history endpoint: {message:?}",
            );
        }
    }
}

/// Malformed JSON through the channel-list cursor helper surfaces the list
/// parse error string.
#[cfg(feature = "slack")]
#[test]
fn list_next_cursor_malformed_json_names_list_parse() {
    let body = r#"{not valid json"#;
    match TestApi.slack_conversations_list_next_cursor_for_test(body) {
        Ok(other) => panic!("malformed JSON must error, got Ok({other:?})"),
        Err(message) => {
            assert!(
                message.contains("failed to parse Slack conversations.list response"),
                "list parse error must name the list endpoint: {message:?}",
            );
        }
    }
}

// --- feature-disabled twins (keep the gate meaningful without `slack`) --------

#[cfg(not(feature = "slack"))]
#[test]
fn list_next_cursor_whitespace_only_is_none() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn list_next_cursor_absent_metadata_is_none() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn history_next_cursor_absent_metadata_is_none() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn history_next_cursor_trims_tab_and_newline_padding() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn history_next_cursor_present_even_when_has_more_false() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn list_next_cursor_returns_cursor_and_len_counts_two_channels() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn list_next_cursor_ok_false_names_list_endpoint_and_code() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn history_next_cursor_ok_false_names_channel_and_code() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn list_next_cursor_ok_false_blank_error_normalizes_to_sentinel() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn history_next_cursor_ok_true_missing_messages_errors() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn list_len_ok_true_missing_channels_errors() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn history_next_cursor_malformed_json_names_history_parse() {
    assert!(!cfg!(feature = "slack"));
}

#[cfg(not(feature = "slack"))]
#[test]
fn list_next_cursor_malformed_json_names_list_parse() {
    assert!(!cfg!(feature = "slack"));
}
