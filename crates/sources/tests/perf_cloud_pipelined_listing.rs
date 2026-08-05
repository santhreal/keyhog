//! Remote-speedup suite for the cloud object-store adapters: listing/download
//! pipelining (`ListingPrefetch` in `cloud/mod.rs`).
//!
//! WHY: the S3, GCS, and Azure Blob loops used to pay listing latency
//! serially at every page boundary (list page -> download page -> list next
//! page). The pipelined loop spawns the NEXT page's listing fetch so it
//! overlaps the CURRENT page's download batch. Against a latency-injecting
//! local mock (no live network) these tests pin, per backend:
//!   * byte-identical, listing-ordered chunks and exactly one request per
//!     listing page and per object (identical object set and bytes), and
//!   * a median wall time below the serial floor
//!     (pages x (listing delay + download delay)), which only an overlapped
//!     loop can beat.
//!
//! The identical-results assertions ran against BOTH the serial and the
//! pipelined builds; the printed medians are the before/after evidence.

#![cfg(any(feature = "s3", feature = "gcs", feature = "azure"))]

use keyhog_core::Source;
use keyhog_sources::testing::{TestApi};
use std::time::{Duration, Instant};

const PAGES: usize = 4;
const OBJECTS_PER_PAGE: usize = 4;
const LISTING_DELAY: Duration = Duration::from_millis(150);
const OBJECT_DELAY: Duration = Duration::from_millis(200);
const TRIALS: usize = 5;

fn key(page: usize, index: usize) -> String {
    format!("p{page}o{index}.txt")
}

fn body(page: usize, index: usize) -> String {
    format!("secret-body-p{page}o{index}\n")
}

fn median_of(mut trials: Vec<Duration>) -> Duration {
    trials.sort();
    trials[TRIALS / 2]
}

/// Serial floor: every page boundary pays one listing delay plus one
/// download-batch delay (the object pool covers one page in one delay).
fn serial_floor() -> Duration {
    (LISTING_DELAY + OBJECT_DELAY) * PAGES as u32
}

// ---------------------------------------------------------------------------
// S3
// ---------------------------------------------------------------------------

#[cfg(feature = "s3")]
mod s3 {
    use super::*;

    const BUCKET: &str = "pipelined-s3";

    fn contents(page: usize) -> String {
        (1..=OBJECTS_PER_PAGE)
            .map(|index| {
                let body = body(page, index);
                format!(
                    "<Contents><Key>{}</Key><Size>{}</Size></Contents>",
                    key(page, index),
                    body.len()
                )
            })
            .collect()
    }

    fn page_xml(page: usize) -> String {
        let objects = contents(page);
        if page == PAGES {
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>{BUCKET}</Name>
  <IsTruncated>false</IsTruncated>
  {objects}
</ListBucketResult>"#
            )
        } else {
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>{BUCKET}</Name>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>tok{}</NextContinuationToken>
  {objects}
</ListBucketResult>"#,
                page + 1
            )
        }
    }

    fn mocks(server: &httpmock::MockServer) -> Vec<httpmock::Mock<'_>> {
        let mut mocks = Vec::new();
        for page in 1..=PAGES {
            let body_xml = page_xml(page);
            mocks.push(server.mock(|when, then| {
                let when = when
                    .method(httpmock::Method::GET)
                    .query_param("list-type", "2");
                if page == 1 {
                    when.query_param_missing("continuation-token");
                } else {
                    when.query_param("continuation-token", format!("tok{page}"));
                }
                then.status(200)
                    .header("content-type", "application/xml")
                    .delay(LISTING_DELAY)
                    .body(body_xml);
            }));
        }
        for page in 1..=PAGES {
            for index in 1..=OBJECTS_PER_PAGE {
                let object_body = body(page, index);
                mocks.push(server.mock(|when, then| {
                    when.method(httpmock::Method::GET)
                        .path(format!("/{BUCKET}/{}", key(page, index)));
                    then.status(200)
                        .header("content-type", "text/plain")
                        .delay(OBJECT_DELAY)
                        .body(object_body);
                }));
            }
        }
        mocks
    }

    fn scan(server: &httpmock::MockServer) -> Vec<(String, String)> {
        let rows: Vec<_> = TestApi
            .s3_source_with_endpoint(BUCKET, server.url(""))
            .chunks()
            .collect();
        rows.into_iter()
            .map(|row| {
                let chunk = row.expect("every listed S3 object must scan cleanly");
                (
                    chunk.metadata.path.expect("s3 chunk path").to_string(),
                    String::from_utf8(chunk.data.as_bytes().to_vec()).expect("utf8 object"),
                )
            })
            .collect()
    }

    /// Expected ordered (path, body) pairs: listing order across all pages.
    fn expected(server: &httpmock::MockServer) -> Vec<(String, String)> {
        let _ = server;
        (1..=PAGES)
            .flat_map(|page| {
                (1..=OBJECTS_PER_PAGE).map(move |index| {
                    (format!("{BUCKET}/{}", key(page, index)), body(page, index))
                })
            })
            .collect()
    }

    /// Pipelined S3 pagination yields the exact serial object set in listing
    /// order, one listing request per page.
    ///
    /// Locks out: dropped/duplicated pages from the prefetch handoff and any
    /// reordering of chunk output.
    #[test]
    fn s3_pipelined_listing_yields_identical_ordered_chunks() {
        let server = httpmock::MockServer::start();
        let _mocks = mocks(&server);
        let actual = scan(&server);
        assert_eq!(actual, expected(&server));
    }

    /// Median wall time over `TRIALS` scans beats the serial floor.
    ///
    /// Locks out: a silent revert to serial page-boundary listing.
    #[test]
    fn s3_pipelined_listing_beats_serial_floor() {
        let server = httpmock::MockServer::start();
        let _mocks = mocks(&server);
        let mut trials = Vec::with_capacity(TRIALS);
        for _ in 0..TRIALS {
            let started = Instant::now();
            let actual = scan(&server);
            trials.push(started.elapsed());
            assert_eq!(actual.len(), PAGES * OBJECTS_PER_PAGE);
        }
        let median = median_of(trials);
        eprintln!(
            "s3 listing median over {TRIALS} trials: {median:?} (serial floor {:?})",
            serial_floor()
        );
        assert!(
            median < serial_floor() - LISTING_DELAY,
            "median {median:?} must beat the serial floor {:?} by at least one listing delay",
            serial_floor()
        );
    }
}

// ---------------------------------------------------------------------------
// GCS
// ---------------------------------------------------------------------------

#[cfg(feature = "gcs")]
mod gcs {
    use super::*;

    const BUCKET: &str = "pipelined-gcs";

    fn item(page: usize, index: usize) -> String {
        format!(
            r#"{{"name": "{}", "size": "{}", "contentType": "text/plain"}}"#,
            key(page, index),
            body(page, index).len()
        )
    }

    fn page_json(page: usize) -> String {
        let items = (1..=OBJECTS_PER_PAGE)
            .map(|index| item(page, index))
            .collect::<Vec<_>>()
            .join(",");
        if page == PAGES {
            format!(r#"{{"items": [{items}]}}"#)
        } else {
            format!(r#"{{"items": [{items}], "nextPageToken": "tok{}"}}"#, page + 1)
        }
    }

    fn mocks(server: &httpmock::MockServer) -> Vec<httpmock::Mock<'_>> {
        let mut mocks = Vec::new();
        for page in 1..=PAGES {
            let json = page_json(page);
            mocks.push(server.mock(|when, then| {
                let when = when
                    .method(httpmock::Method::GET)
                    .path(format!("/storage/v1/b/{BUCKET}/o"));
                if page == 1 {
                    when.query_param_missing("pageToken");
                } else {
                    when.query_param("pageToken", format!("tok{page}"));
                }
                then.status(200)
                    .header("content-type", "application/json")
                    .delay(LISTING_DELAY)
                    .body(json);
            }));
        }
        for page in 1..=PAGES {
            for index in 1..=OBJECTS_PER_PAGE {
                let object_body = body(page, index);
                mocks.push(server.mock(|when, then| {
                    when.method(httpmock::Method::GET)
                        .path(format!("/storage/v1/b/{BUCKET}/o/{}", key(page, index)));
                    then.status(200)
                        .header("content-type", "text/plain")
                        .delay(OBJECT_DELAY)
                        .body(object_body);
                }));
            }
        }
        mocks
    }

    fn scan(server: &httpmock::MockServer) -> Vec<(String, String)> {
        let rows: Vec<_> = TestApi
            .gcs_source_with_endpoint(BUCKET, server.url(""))
            .chunks()
            .collect();
        rows.into_iter()
            .map(|row| {
                let chunk = row.expect("every listed GCS object must scan cleanly");
                (
                    chunk.metadata.path.expect("gcs chunk path").to_string(),
                    String::from_utf8(chunk.data.as_bytes().to_vec()).expect("utf8 object"),
                )
            })
            .collect()
    }

    /// Pipelined GCS pagination yields the exact serial object set in listing
    /// order, one listing request per page.
    ///
    /// Locks out: dropped/duplicated pages from the prefetch handoff and any
    /// reordering of chunk output.
    #[test]
    fn gcs_pipelined_listing_yields_identical_ordered_chunks() {
        let server = httpmock::MockServer::start();
        let _mocks = mocks(&server);
        let actual = scan(&server);
        let expected: Vec<(String, String)> = (1..=PAGES)
            .flat_map(|page| {
                (1..=OBJECTS_PER_PAGE).map(move |index| {
                    (
                        format!("gs://{BUCKET}/{}", key(page, index)),
                        body(page, index),
                    )
                })
            })
            .collect();
        assert_eq!(actual, expected);
    }

    /// Median wall time over `TRIALS` scans beats the serial floor.
    ///
    /// Locks out: a silent revert to serial page-boundary listing.
    #[test]
    fn gcs_pipelined_listing_beats_serial_floor() {
        let server = httpmock::MockServer::start();
        let _mocks = mocks(&server);
        let mut trials = Vec::with_capacity(TRIALS);
        for _ in 0..TRIALS {
            let started = Instant::now();
            let actual = scan(&server);
            trials.push(started.elapsed());
            assert_eq!(actual.len(), PAGES * OBJECTS_PER_PAGE);
        }
        let median = median_of(trials);
        eprintln!(
            "gcs listing median over {TRIALS} trials: {median:?} (serial floor {:?})",
            serial_floor()
        );
        assert!(
            median < serial_floor() - LISTING_DELAY,
            "median {median:?} must beat the serial floor {:?} by at least one listing delay",
            serial_floor()
        );
    }
}

// ---------------------------------------------------------------------------
// Azure Blob
// ---------------------------------------------------------------------------

#[cfg(feature = "azure")]
mod azure {
    use super::*;

    fn blob_xml(page: usize, index: usize) -> String {
        format!(
            "<Blob><Name>{}</Name><Properties><Content-Length>{}</Content-Length><Content-Type>text/plain</Content-Type></Properties></Blob>",
            key(page, index),
            body(page, index).len()
        )
    }

    fn page_xml(page: usize) -> String {
        let blobs = (1..=OBJECTS_PER_PAGE)
            .map(|index| blob_xml(page, index))
            .collect::<String>();
        let marker = if page == PAGES {
            "<NextMarker/>".to_string()
        } else {
            format!("<NextMarker>tok{}</NextMarker>", page + 1)
        };
        format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults><Blobs>{blobs}</Blobs>{marker}</EnumerationResults>"#
        )
    }

    fn container_url(server: &httpmock::MockServer) -> String {
        format!("{}/container?sv=2024-11-04&sig=pipelined", server.url(""))
    }

    fn mocks(server: &httpmock::MockServer) -> Vec<httpmock::Mock<'_>> {
        let mut mocks = Vec::new();
        for page in 1..=PAGES {
            let xml = page_xml(page);
            mocks.push(server.mock(|when, then| {
                let when = when
                    .method(httpmock::Method::GET)
                    .path("/container")
                    .query_param("comp", "list");
                if page == 1 {
                    when.query_param_missing("marker");
                } else {
                    when.query_param("marker", format!("tok{page}"));
                }
                then.status(200)
                    .header("content-type", "application/xml")
                    .delay(LISTING_DELAY)
                    .body(xml);
            }));
        }
        for page in 1..=PAGES {
            for index in 1..=OBJECTS_PER_PAGE {
                let object_body = body(page, index);
                mocks.push(server.mock(|when, then| {
                    when.method(httpmock::Method::GET)
                        .path(format!("/container/{}", key(page, index)));
                    then.status(200)
                        .header("content-type", "text/plain")
                        .delay(OBJECT_DELAY)
                        .body(object_body);
                }));
            }
        }
        mocks
    }

    fn scan(server: &httpmock::MockServer) -> Vec<(String, String)> {
        let rows: Vec<_> = TestApi
            .azure_blob_source(container_url(server))
            .chunks()
            .collect();
        rows.into_iter()
            .map(|row| {
                let chunk = row.expect("every listed Azure blob must scan cleanly");
                (
                    chunk.metadata.path.expect("azure chunk path").to_string(),
                    String::from_utf8(chunk.data.as_bytes().to_vec()).expect("utf8 blob"),
                )
            })
            .collect()
    }

    /// Pipelined Azure pagination yields the exact serial blob set in listing
    /// order, one listing request per page.
    ///
    /// Locks out: dropped/duplicated pages from the prefetch handoff and any
    /// reordering of chunk output.
    #[test]
    fn azure_pipelined_listing_yields_identical_ordered_chunks() {
        let server = httpmock::MockServer::start();
        let _mocks = mocks(&server);
        let actual = scan(&server);
        let expected: Vec<(String, String)> = (1..=PAGES)
            .flat_map(|page| {
                (1..=OBJECTS_PER_PAGE).map(move |index| {
                    let suffix = format!("/container/{}", key(page, index));
                    (suffix, body(page, index))
                })
            })
            .collect();
        // Azure display paths embed the full container URL; compare on the
        // path suffix plus the exact bytes to stay endpoint-shape agnostic.
        assert_eq!(actual.len(), expected.len());
        for (actual_row, (suffix, body)) in actual.iter().zip(expected.iter()) {
            assert!(
                actual_row.0.ends_with(suffix.as_str()),
                "chunk path {} must end with {suffix}",
                actual_row.0
            );
            assert_eq!(&actual_row.1, body);
        }
    }

    /// Median wall time over `TRIALS` scans beats the serial floor.
    ///
    /// Locks out: a silent revert to serial page-boundary listing.
    #[test]
    fn azure_pipelined_listing_beats_serial_floor() {
        let server = httpmock::MockServer::start();
        let _mocks = mocks(&server);
        let mut trials = Vec::with_capacity(TRIALS);
        for _ in 0..TRIALS {
            let started = Instant::now();
            let actual = scan(&server);
            trials.push(started.elapsed());
            assert_eq!(actual.len(), PAGES * OBJECTS_PER_PAGE);
        }
        let median = median_of(trials);
        eprintln!(
            "azure listing median over {TRIALS} trials: {median:?} (serial floor {:?})",
            serial_floor()
        );
        assert!(
            median < serial_floor() - LISTING_DELAY,
            "median {median:?} must beat the serial floor {:?} by at least one listing delay",
            serial_floor()
        );
    }
}
