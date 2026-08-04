//! Source-instrumentation suite for the Slack adapter (workspace channel
//! enumeration, paginated history reads).
//!
//! WHY: Slack fetches run on a scoped thread and history on a rayon pool;
//! without the runtime propagation at both handoffs nothing would record.
//! This test pins the acquisition span, the channel-list walk span, the
//! history read span, and the real message content totals.

#![cfg(feature = "slack")]

mod support;

use keyhog_core::Source;
use keyhog_profile::Stage;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use support::profile::{run_with_profile, stage_calls};

/// One channel with one message records: 1 acquisition, 1 list-page walk, 1
/// history read, and the message chunk as the input totals.
///
/// Locks out: losing the scoped-thread runtime propagation (all counts fall
/// to zero) and the list pagination losing its per-page walk span.
#[test]
fn slack_records_enumeration_history_read_and_message_totals() {
    let server = httpmock::MockServer::start();
    let list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.list");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ok":true,"channels":[{"id":"C1","name":"general"}],"response_metadata":{"next_cursor":""}}"#,
            );
    });
    let history = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/conversations.history");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ok":true,"messages":[{"user":"U1","text":"token AKIASLACKFIXTURE001","ts":"1700000000.000001"}],"has_more":false,"response_metadata":{"next_cursor":""}}"#,
            );
    });

    let (profile, rows) = run_with_profile(|| {
        TestApi
            .slack_source_with_endpoint("xoxb-test-token", server.url(""))
            .chunks()
            .collect::<Vec<_>>()
    });

    let chunks: Vec<_> = rows.iter().filter_map(|row| row.as_ref().ok()).collect();
    assert_eq!(chunks.len(), 1, "one message yields one chunk: {rows:?}");
    assert!(chunks[0].data.contains("AKIASLACKFIXTURE001"));
    assert_eq!(list.calls(), 1);
    assert_eq!(history.calls(), 1);

    assert_eq!(stage_calls(&profile, Stage::SourceAcquire), 1);
    assert_eq!(stage_calls(&profile, Stage::SourceWalk), 1);
    assert_eq!(stage_calls(&profile, Stage::SourceRead), 1);
    assert_eq!(profile.input_units, 1);
    assert_eq!(profile.input_bytes, chunks[0].data.len() as u64);
    assert!(profile.input_bytes > 0);
}
