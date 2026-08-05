//! Source-instrumentation suite for the GCS cloud adapter (bucket listing,
//! object download).
//!
//! WHY: GCS shares the cloud listing loop with S3 but has its own JSON
//! listing shape and media download path. This test pins the acquisition
//! span, the listing walk span, the download read span, and the real object
//! totals through the shared cloud sink.

#![cfg(feature = "gcs")]

mod support;

use keyhog_core::Source;
use keyhog_profile::Stage;
use keyhog_sources::testing::{TestApi};
use support::profile::{run_with_profile, stage_calls};

const BUCKET: &str = "profile-bucket";

/// A single-page listing with one text object records 1 acquisition, 1 walk,
/// 1 read, 1 unit, and the exact object body bytes.
///
/// Locks out: the GCS loop drifting from the shared cloud accounting when its
/// page token handling changes.
#[test]
fn gcs_listing_records_walk_download_and_object_totals() {
    let body = "gcs_key = \"AKIAGCSFIXTURE0001\"\n"; // keyhog:ignore detector=aws-access-key
    let server = httpmock::MockServer::start();
    let list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json");
        then.status(200)
            .header("content-type", "application/json")
            .body(format!(
                r#"{{"items":[{{"name":"config.txt","size":"{}"}}]}}"#,
                body.len()
            ));
    });
    let object = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o/config.txt"))
            .query_param("alt", "media");
        then.status(200)
            .header("content-type", "text/plain")
            .body(body);
    });

    let (profile, rows) = run_with_profile(|| {
        TestApi
            .gcs_source_with_endpoint(BUCKET, server.url(""))
            .chunks()
            .collect::<Vec<_>>()
    });

    let (chunks, errors) = support::split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "a healthy fixture must not report coverage errors: {errors:?}"
    );
    assert_eq!(chunks.len(), 1, "the listed object scans: {rows:?}");
    assert!(chunks[0].data.contains("AKIAGCSFIXTURE0001"));
    assert_eq!(list.calls(), 1);
    assert_eq!(object.calls(), 1);

    assert_eq!(stage_calls(&profile, Stage::SourceAcquire), 1);
    assert_eq!(stage_calls(&profile, Stage::SourceWalk), 1);
    assert_eq!(stage_calls(&profile, Stage::SourceRead), 1);
    assert_eq!(profile.input_units, 1);
    assert_eq!(profile.input_bytes, body.len() as u64);
}
