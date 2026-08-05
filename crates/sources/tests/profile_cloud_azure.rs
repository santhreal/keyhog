//! Source-instrumentation suite for the Azure Blob cloud adapter (container
//! listing, blob download).
//!
//! WHY: Azure shares the cloud listing loop with S3/GCS but has its own XML
//! listing shape and marker pagination. This test pins the acquisition span,
//! the listing walk span, the download read span, and the real blob totals
//! through the shared cloud sink.

#![cfg(feature = "azure")]

mod support;

use keyhog_core::Source;
use keyhog_profile::Stage;
use keyhog_sources::testing::{TestApi};
use support::profile::{run_with_profile, stage_calls};

/// A single-page listing with one text blob records 1 acquisition, 1 walk, 1
/// read, 1 unit, and the exact blob body bytes.
///
/// Locks out: the Azure loop drifting from the shared cloud accounting when
/// its marker pagination changes.
#[test]
fn azure_listing_records_walk_download_and_blob_totals() {
    let body = "azure_key = \"AKIAAZUREFIXTURE01\"\n";
    let server = httpmock::MockServer::start();
    let list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container")
            .query_param("restype", "container")
            .query_param("comp", "list");
        then.status(200)
            .header("content-type", "application/xml")
            .body(format!(
                r#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="{}" ContainerName="container">
  <Blobs><Blob><Name>config.txt</Name><Properties><Content-Length>{}</Content-Length><Content-Type>text/plain</Content-Type></Properties></Blob></Blobs>
  <NextMarker />
</EnumerationResults>"#,
                server.url(""),
                body.len()
            ));
    });
    let blob = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container/config.txt");
        then.status(200)
            .header("content-type", "text/plain")
            .body(body);
    });

    let container_url = format!("{}/container?sv=2024-11-04&sig=profile", server.url(""));
    let (profile, rows) = run_with_profile(|| {
        TestApi
            .azure_blob_source(container_url)
            .chunks()
            .collect::<Vec<_>>()
    });

    let (chunks, errors) = support::split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "a healthy fixture must not report coverage errors: {errors:?}"
    );
    assert_eq!(chunks.len(), 1, "the listed blob scans: {rows:?}");
    assert!(chunks[0].data.contains("AKIAAZUREFIXTURE01"));
    assert_eq!(list.calls(), 1);
    assert_eq!(blob.calls(), 1);

    assert_eq!(stage_calls(&profile, Stage::SourceAcquire), 1);
    assert_eq!(stage_calls(&profile, Stage::SourceWalk), 1);
    assert_eq!(stage_calls(&profile, Stage::SourceRead), 1);
    assert_eq!(profile.input_units, 1);
    assert_eq!(profile.input_bytes, body.len() as u64);
}
