//! E2E: `--limit-web-response-bytes`, `--limit-gcs-object-bytes`,
//! `--limit-azure-blob-bytes`, and `--limit-cloud-max-objects` boundaries.
//!
//! KH-191 / KH-192 / KH-193 / KH-203. Every cap is driven through a real
//! process against a mock object store, at limit minus one, exactly at the
//! limit, and limit plus one. An object that a cap excludes must be reported
//! as a coverage gap; a cloud scan that quietly lists fewer objects than the
//! bucket holds is a false clean.
//!
//! The mock binds to loopback, which the cloud SSRF screen refuses by default,
//! so every scan here passes `--allow-private-cloud-endpoint` exactly as an
//! operator would for a self-hosted gateway.

#![cfg(any(feature = "gcs", feature = "azure"))]

use crate::e2e::support::binary;
use httpmock::prelude::*;
use std::process::{Command, Output};

/// A leak the default corpus reports. Object bodies are built from this so a
/// dropped object is visible as a missing finding, not just a missing byte.
fn object_body(index: usize) -> String {
    format!(
        "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZB{}\n",
        (b'A' + index as u8) as char
    )
}

const OBJECTS: usize = 4;

fn keys() -> Vec<String> {
    (0..OBJECTS).map(|i| format!("k{i}.env")).collect()
}

fn run(args: &[&str]) -> Output {
    let mut command = Command::new(binary());
    command
        .args([
            "scan",
            "--daemon=off",
            "--no-suppress-test-fixtures",
            "--allow-private-cloud-endpoint",
            "--format",
            "jsonl",
        ])
        .args(args)
        // An ambient AWS/GCS credential in the developer environment changes
        // which code path a cloud source takes; these runs must be anonymous.
        .env_remove("AWS_ACCESS_KEY_ID")
        .env_remove("AWS_SECRET_ACCESS_KEY")
        .env_remove("AWS_SESSION_TOKEN")
        .env_remove("GOOGLE_APPLICATION_CREDENTIALS");
    command.output().expect("spawn keyhog")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn findings(output: &Output) -> usize {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.starts_with('{'))
        .count()
}

// ── GCS ──────────────────────────────────────────────────────────────────────

fn gcs_listing() -> String {
    let items: Vec<String> = keys()
        .iter()
        .enumerate()
        .map(|(index, key)| {
            format!(
                r#"{{"name":"{key}","size":"{}"}}"#,
                object_body(index).len()
            )
        })
        .collect();
    format!(
        r#"{{"kind":"storage#objects","items":[{}]}}"#,
        items.join(",")
    )
}

/// Serve one GCS bucket: the JSON listing plus every object body.
fn gcs_server() -> MockServer {
    let server = MockServer::start();
    let listing = gcs_listing();
    server.mock(|when, then| {
        when.method(GET).path("/storage/v1/b/bucket/o");
        then.status(200)
            .header("content-type", "application/json")
            .body(listing);
    });
    for (index, key) in keys().iter().enumerate() {
        let body = object_body(index);
        server.mock(|when, then| {
            when.method(GET)
                .path(format!("/storage/v1/b/bucket/o/{key}"));
            then.status(200)
                .header("content-type", "text/plain")
                .body(body);
        });
    }
    server
}

fn scan_gcs(server: &MockServer, extra: &[&str]) -> Output {
    let endpoint = server.base_url();
    let mut args = vec!["--gcs-bucket", "bucket", "--gcs-endpoint", &endpoint];
    args.extend_from_slice(extra);
    run(&args)
}

/// KH-192. An object of exactly the cap is downloaded; one byte more is
/// skipped, and the skip is an operator-visible coverage gap.
#[cfg(feature = "gcs")]
#[test]
fn limit_gcs_object_bytes_admits_an_exactly_sized_object_and_surfaces_a_larger_one() {
    let server = gcs_server();
    let exact = object_body(0).len();

    let at_cap = scan_gcs(&server, &["--limit-gcs-object-bytes", &format!("{exact}B")]);
    assert_eq!(
        findings(&at_cap),
        OBJECTS,
        "objects of exactly {exact} bytes must fit a {exact}-byte cap; stderr={}",
        stderr_of(&at_cap)
    );
    assert!(
        !stderr_of(&at_cap).contains("per-object byte cap"),
        "nothing was skipped, so nothing may be reported skipped"
    );

    let over_cap = scan_gcs(
        &server,
        &["--limit-gcs-object-bytes", &format!("{}B", exact - 1)],
    );
    let over_stderr = stderr_of(&over_cap);
    assert_eq!(
        findings(&over_cap),
        0,
        "one byte under the object size drops every object; stderr={over_stderr}"
    );
    assert!(
        over_stderr.contains("per-object byte cap") && over_stderr.contains("not scanned"),
        "oversized objects must be SURFACED, never omitted from the listing \
         silently; stderr={over_stderr}"
    );
    assert_ne!(
        over_cap.status.code(),
        Some(0),
        "a cloud scan that read no object must not exit 0"
    );

    let under_cap = scan_gcs(
        &server,
        &["--limit-gcs-object-bytes", &format!("{}B", exact + 1)],
    );
    assert_eq!(
        findings(&under_cap),
        OBJECTS,
        "one byte of headroom behaves like the exact cap"
    );
}

/// KH-191. The response cap is checked against the listing's exact
/// `Content-Length`, and exceeding it fails the whole listing loudly rather
/// than scanning a truncated object set.
#[cfg(feature = "gcs")]
#[test]
fn limit_web_response_bytes_bounds_the_listing_response_exactly() {
    let server = gcs_server();
    let listing_bytes = gcs_listing().len();

    let at_cap = scan_gcs(
        &server,
        &["--limit-web-response-bytes", &format!("{listing_bytes}B")],
    );
    assert_eq!(
        findings(&at_cap),
        OBJECTS,
        "a listing of exactly {listing_bytes} bytes must fit a \
         {listing_bytes}-byte cap; stderr={}",
        stderr_of(&at_cap)
    );

    let over_cap = scan_gcs(
        &server,
        &[
            "--limit-web-response-bytes",
            &format!("{}B", listing_bytes - 1),
        ],
    );
    let over_stderr = stderr_of(&over_cap);
    assert!(
        over_stderr.contains("exceeds the web_response_bytes cap"),
        "an over-cap listing must name the cap and the actual length; \
         stderr={over_stderr}"
    );
    assert!(
        over_stderr.contains("were not scanned"),
        "a refused listing means the whole bucket is uncovered; \
         stderr={over_stderr}"
    );
    assert_ne!(
        over_cap.status.code(),
        Some(0),
        "refusing the listing must not be reported as a clean scan"
    );
}

/// KH-203. Exact, over-budget, and zero object budgets. The cutoff is
/// deterministic and the unscanned remainder is surfaced.
#[cfg(feature = "gcs")]
#[test]
fn limit_cloud_max_objects_cuts_the_listing_and_surfaces_the_remainder() {
    let server = gcs_server();

    let exact = scan_gcs(
        &server,
        &["--limit-cloud-max-objects", &OBJECTS.to_string()],
    );
    assert_eq!(
        findings(&exact),
        OBJECTS,
        "a budget equal to the object count scans every object; stderr={}",
        stderr_of(&exact)
    );
    assert!(
        !stderr_of(&exact).contains("max_objects limit reached"),
        "an exactly-sufficient budget must not invent a coverage gap"
    );

    let short = scan_gcs(
        &server,
        &["--limit-cloud-max-objects", &(OBJECTS - 1).to_string()],
    );
    let short_stderr = stderr_of(&short);
    assert_eq!(
        findings(&short),
        OBJECTS - 1,
        "the cutoff is exact; stderr={short_stderr}"
    );
    assert!(
        short_stderr.contains("max_objects limit reached")
            && short_stderr.contains("remaining objects were not scanned"),
        "a truncated listing is a coverage gap, not a smaller clean scan; \
         stderr={short_stderr}"
    );

    let zero = scan_gcs(&server, &["--limit-cloud-max-objects", "0"]);
    assert_ne!(
        zero.status.code(),
        Some(0),
        "a zero object budget can only produce a false clean and must fail \
         closed; stderr={}",
        stderr_of(&zero)
    );
}

// ── Azure ────────────────────────────────────────────────────────────────────

#[cfg(feature = "azure")]
fn azure_listing() -> String {
    let blobs: Vec<String> = keys()
        .iter()
        .enumerate()
        .map(|(index, key)| {
            format!(
                "<Blob><Name>{key}</Name><Properties><Content-Length>{}</Content-Length>\
                 </Properties></Blob>",
                object_body(index).len()
            )
        })
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ContainerName="container">
  <Blobs>{}</Blobs>
  <NextMarker />
</EnumerationResults>"#,
        blobs.join("")
    )
}

#[cfg(feature = "azure")]
fn azure_server() -> MockServer {
    let server = MockServer::start();
    let listing = azure_listing();
    server.mock(|when, then| {
        when.method(GET)
            .path("/container")
            .query_param("comp", "list");
        then.status(200)
            .header("content-type", "application/xml")
            .body(listing);
    });
    for (index, key) in keys().iter().enumerate() {
        let body = object_body(index);
        server.mock(|when, then| {
            when.method(GET).path(format!("/container/{key}"));
            then.status(200)
                .header("content-type", "text/plain")
                .body(body);
        });
    }
    server
}

/// KH-193. Exact inclusion at the bound plus an operator-visible oversize
/// state one byte below it.
#[cfg(feature = "azure")]
#[test]
fn limit_azure_blob_bytes_admits_an_exactly_sized_blob_and_surfaces_a_larger_one() {
    let server = azure_server();
    let container = server.url("/container");
    let exact = object_body(0).len();

    let at_cap = run(&[
        "--azure-container-url",
        &container,
        "--limit-azure-blob-bytes",
        &format!("{exact}B"),
    ]);
    assert_eq!(
        findings(&at_cap),
        OBJECTS,
        "a blob of exactly {exact} bytes must fit a {exact}-byte cap; stderr={}",
        stderr_of(&at_cap)
    );

    let over_cap = run(&[
        "--azure-container-url",
        &container,
        "--limit-azure-blob-bytes",
        &format!("{}B", exact - 1),
    ]);
    let over_stderr = stderr_of(&over_cap);
    assert_eq!(
        findings(&over_cap),
        0,
        "one byte under the blob size drops every blob; stderr={over_stderr}"
    );
    assert!(
        over_stderr.contains("per-blob byte cap") && over_stderr.contains("not scanned"),
        "an oversized blob must be surfaced as a coverage gap; \
         stderr={over_stderr}"
    );
    assert_ne!(
        over_cap.status.code(),
        Some(0),
        "reading no blob at all must not exit 0"
    );
}

/// KH-203, Azure half: the shared object budget cuts an Azure listing with the
/// same exactness and the same surfaced remainder as GCS.
#[cfg(feature = "azure")]
#[test]
fn limit_cloud_max_objects_applies_to_azure_listings_too() {
    let server = azure_server();
    let container = server.url("/container");

    let exact = run(&[
        "--azure-container-url",
        &container,
        "--limit-cloud-max-objects",
        &OBJECTS.to_string(),
    ]);
    assert_eq!(findings(&exact), OBJECTS, "stderr={}", stderr_of(&exact));
    assert!(!stderr_of(&exact).contains("max_objects limit reached"));

    let short = run(&[
        "--azure-container-url",
        &container,
        "--limit-cloud-max-objects",
        &(OBJECTS - 1).to_string(),
    ]);
    let short_stderr = stderr_of(&short);
    assert_eq!(findings(&short), OBJECTS - 1, "stderr={short_stderr}");
    assert!(
        short_stderr.contains("max_objects limit reached")
            && short_stderr.contains("remaining objects were not scanned"),
        "stderr={short_stderr}"
    );
}
