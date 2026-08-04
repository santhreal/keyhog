//! Source-instrumentation suite for the web adapter (HTTP wire capture and
//! endpoint body streaming).
//!
//! WHY: WebSource fetches run on a scoped blocking thread; without explicit
//! runtime propagation nothing would record there. These tests pin the
//! acquisition span, the per-endpoint read span, and the real response byte
//! totals so a regression in the thread handoff or the fetch boundary is
//! caught by name.

#![cfg(feature = "web")]

mod support;

use keyhog_core::Source;
use keyhog_profile::Stage;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use support::profile::{run_with_profile, stage_calls};

/// One endpoint fetch records one acquisition, one wire-read span, and the
/// response body as one input unit with its exact byte length.
///
/// Locks out: losing the blocking-thread runtime propagation (every count
/// would fall to zero) and dropping the per-endpoint read span.
#[test]
fn web_fetch_records_acquire_read_and_response_totals() {
    let body = "const key = 'AKIAWEBFIXTURE000001';\n";
    let server = httpmock::MockServer::start();
    let app = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/app.js");
        then.status(200)
            .header("content-type", "application/javascript")
            .body(body);
    });

    let (profile, rows) = run_with_profile(|| {
        TestApi
            .web_source_with_autoroute_loopback_calibration(vec![server.url("/app.js")], true)
            .chunks()
            .collect::<Vec<_>>()
    });

    let (chunks, errors) = support::split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "a healthy fixture must not report coverage errors: {errors:?}"
    );
    assert_eq!(chunks.len(), 1, "one endpoint yields one chunk: {rows:?}");
    assert!(chunks[0].data.contains("AKIAWEBFIXTURE000001"));
    assert_eq!(app.calls(), 1);

    assert_eq!(stage_calls(&profile, Stage::SourceAcquire), 1);
    assert_eq!(stage_calls(&profile, Stage::SourceRead), 1);
    assert_eq!(profile.input_units, 1);
    assert_eq!(profile.input_bytes, chunks[0].data.len() as u64);
    assert!(profile.input_bytes > 0);
}

/// Two endpoints record one shared acquisition and one read span per
/// endpoint, with units and bytes summed across both responses.
///
/// Locks out: per-endpoint instrumentation that only fires for the first URL
/// in the list (a loop-scoped span mistake).
#[test]
fn web_two_endpoints_record_one_span_each() {
    let first = "const a = 'first';\n";
    let second = "const b = 'second';\n";
    let server = httpmock::MockServer::start();
    let _one = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/one.js");
        then.status(200)
            .header("content-type", "application/javascript")
            .body(first);
    });
    let _two = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/two.js");
        then.status(200)
            .header("content-type", "application/javascript")
            .body(second);
    });

    let (profile, rows) = run_with_profile(|| {
        TestApi
            .web_source_with_autoroute_loopback_calibration(
                vec![server.url("/one.js"), server.url("/two.js")],
                true,
            )
            .chunks()
            .collect::<Vec<_>>()
    });

    let (chunks, errors) = support::split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "a healthy fixture must not report coverage errors: {errors:?}"
    );
    assert_eq!(chunks.len(), 2, "both endpoints yield chunks: {rows:?}");

    assert_eq!(stage_calls(&profile, Stage::SourceAcquire), 1);
    assert_eq!(stage_calls(&profile, Stage::SourceRead), 2);
    assert_eq!(profile.input_units, 2);
    let expected_bytes: u64 = chunks.iter().map(|chunk| chunk.data.len() as u64).sum();
    assert_eq!(profile.input_bytes, expected_bytes);
    assert!(expected_bytes > 0);
}
