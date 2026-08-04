//! Source-instrumentation suite for the S3 cloud adapter (bucket listing,
//! paginated enumeration, per-page object downloads).
//!
//! WHY: the cloud adapters share the listing/download loop shape, and S3 is
//! the one with full pagination mocks already pinned. These tests prove the
//! acquisition span fires once, the walk span fires once per listing page,
//! the read span fires once per download batch, and the shared cloud sink
//! records the real downloaded object counts and bytes.

#![cfg(feature = "s3")]

mod support;

use keyhog_core::Source;
use keyhog_profile::Stage;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use support::profile::{run_with_profile, stage_calls};

const BUCKET: &str = "profile-bucket";

fn contents(key: &str, size: u64) -> String {
    format!("<Contents><Key>{key}</Key><Size>{size}</Size></Contents>")
}

fn final_page(objects: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>{BUCKET}</Name>
  <IsTruncated>false</IsTruncated>
  {objects}
</ListBucketResult>"#
    )
}

fn truncated_page_with_token(objects: &str, token: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>{BUCKET}</Name>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>{token}</NextContinuationToken>
  {objects}
</ListBucketResult>"#
    )
}

/// A two-page listing with three text objects records: 1 acquisition, 2 page
/// walks, 2 download reads, 3 units, and the exact object body bytes.
///
/// Locks out: the pagination loop losing its per-page walk span, and the
/// shared `push_page_chunks` sink dropping or double counting objects.
#[test]
fn s3_paginated_listing_records_pages_downloads_and_object_totals() {
    let server = httpmock::MockServer::start();
    let page_one = truncated_page_with_token(
        &format!("{}{}", contents("a.txt", 6), contents("b.txt", 6)),
        "TOKEN-2",
    );
    let page_two = final_page(&contents("c.txt", 6));
    let list_one = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param_missing("continuation-token");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page_one);
    });
    let list_two = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param("continuation-token", "TOKEN-2");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page_two);
    });
    for (key, body) in [("a.txt", "alpha\n"), ("b.txt", "bravo\n"), ("c.txt", "charl\n")] {
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path_includes(key);
            then.status(200)
                .header("content-type", "text/plain")
                .body(body);
        });
    }

    let (profile, rows) = run_with_profile(|| {
        TestApi
            .s3_source_with_endpoint(BUCKET, server.url(""))
            .chunks()
            .collect::<Vec<_>>()
    });

    let (chunks, errors) = support::split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "a healthy fixture must not report coverage errors: {errors:?}"
    );
    assert_eq!(chunks.len(), 3, "all listed objects scan: {rows:?}");
    assert_eq!(list_one.calls(), 1);
    assert_eq!(list_two.calls(), 1);

    assert_eq!(stage_calls(&profile, Stage::SourceAcquire), 1);
    assert_eq!(stage_calls(&profile, Stage::SourceWalk), 2);
    assert_eq!(stage_calls(&profile, Stage::SourceRead), 2);
    assert_eq!(profile.input_units, 3);
    // Each mock body is exactly 6 bytes.
    assert_eq!(profile.input_bytes, 18);
}

/// A single-page listing records exactly one page walk and one download
/// batch, proving the spans are per-page rather than per-run constants.
///
/// Locks out: a loop-scoped span that fires once regardless of page count.
#[test]
fn s3_single_page_records_one_walk_and_one_read() {
    let server = httpmock::MockServer::start();
    let page = final_page(&contents("only.txt", 5));
    let list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param_missing("continuation-token");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page);
    });
    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path_includes("only.txt");
        then.status(200)
            .header("content-type", "text/plain")
            .body("five\n");
    });

    let (profile, rows) = run_with_profile(|| {
        TestApi
            .s3_source_with_endpoint(BUCKET, server.url(""))
            .chunks()
            .collect::<Vec<_>>()
    });

    let (chunks, errors) = support::split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "a healthy fixture must not report coverage errors: {errors:?}"
    );
    assert_eq!(chunks.len(), 1, "the one listed object scans: {rows:?}");
    assert_eq!(list.calls(), 1);

    assert_eq!(stage_calls(&profile, Stage::SourceAcquire), 1);
    assert_eq!(stage_calls(&profile, Stage::SourceWalk), 1);
    assert_eq!(stage_calls(&profile, Stage::SourceRead), 1);
    assert_eq!(profile.input_units, 1);
    assert_eq!(profile.input_bytes, 5);
}
