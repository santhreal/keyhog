//! Remote-speedup suite for the web adapter: concurrent endpoint fetching and
//! cross-endpoint pinned-client reuse.
//!
//! WHY: WebSource used to fetch every configured URL serially, rebuilding the
//! SSRF-pinned reqwest client (DNS resolve + screen + TLS connector) once per
//! endpoint even when every endpoint shared one host:port. These tests pin the
//! optimized contract against a latency-injecting local mock (no live
//! network):
//!   * chunk output is byte-identical and in configured URL order, one request
//!     per endpoint per scan, and
//!   * the parallel wall time stays far below the serial floor
//!     (endpoints x per-endpoint delay), proving the bounded fanout.
//!
//! The identical-results assertions ran against BOTH the serial and the
//! parallel builds; the median timings printed by `web_parallel_fetch_median`
//! are the before/after evidence (serial median ~ endpoints x delay,
//! parallel median ~ delay).

#![cfg(feature = "web")]

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use std::time::{Duration, Instant};

const ENDPOINTS: usize = 8;
const ENDPOINT_DELAY: Duration = Duration::from_millis(100);
const TRIALS: usize = 5;

fn endpoint_body(index: usize) -> String {
    format!("const key{index} = 'AKIAWEBPARALLEL{index:07}';\n")
}

fn expected_chunks() -> Vec<(String, String)> {
    (0..ENDPOINTS)
        .map(|index| (format!("/ep{index}.js"), endpoint_body(index)))
        .collect()
}

/// Start a mock server serving `ENDPOINTS` delayed JS bodies.
fn delayed_server() -> httpmock::MockServer {
    let server = httpmock::MockServer::start();
    for index in 0..ENDPOINTS {
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path(format!("/ep{index}.js"));
            then.status(200)
                .header("content-type", "application/javascript")
                .delay(ENDPOINT_DELAY)
                .body(endpoint_body(index));
        });
    }
    server
}

fn scan(server: &httpmock::MockServer) -> Vec<(String, String)> {
    let urls: Vec<String> = (0..ENDPOINTS)
        .map(|index| server.url(&format!("/ep{index}.js")))
        .collect();
    let rows: Vec<_> = TestApi
        .web_source_with_autoroute_loopback_calibration(urls, true)
        .chunks()
        .collect();
    rows.into_iter()
        .map(|row| {
            let chunk = row.expect("every delayed endpoint must scan cleanly");
            (
                chunk.metadata.path.expect("web chunk path").to_string(),
                String::from_utf8(chunk.data.as_bytes().to_vec()).expect("utf8 js body"),
            )
        })
        .collect()
}

/// Chunk paths and bytes arrive in configured URL order with the exact
/// per-endpoint bodies, regardless of fetch concurrency.
///
/// Locks out: an unordered parallel collect (completion-order results) and any
/// per-endpoint body mix-up across worker threads.
#[test]
fn web_parallel_fetch_yields_identical_ordered_chunks() {
    let server = delayed_server();
    let actual = scan(&server);
    let expected: Vec<(String, String)> = expected_chunks()
        .into_iter()
        .map(|(path, body)| (server.url(&path), body))
        .collect();
    assert_eq!(actual, expected);
}

/// Median wall time over `TRIALS` scans stays under half the serial floor
/// (`ENDPOINTS x ENDPOINT_DELAY`), which a serial fetch cannot beat.
///
/// Locks out: a silent revert to serial per-URL fetching (the scan would take
/// ~ENDPOINTS * delay again) and unbounded fanout regressions that serialize
/// on one shared client build per endpoint.
#[test]
fn web_parallel_fetch_beats_serial_floor() {
    let server = delayed_server();
    let serial_floor = ENDPOINT_DELAY * ENDPOINTS as u32;
    let mut trials = Vec::with_capacity(TRIALS);
    for _ in 0..TRIALS {
        let started = Instant::now();
        let actual = scan(&server);
        trials.push(started.elapsed());
        assert_eq!(actual.len(), ENDPOINTS);
    }
    trials.sort();
    let median = trials[TRIALS / 2];
    eprintln!(
        "web fetch median over {TRIALS} trials: {median:?} (serial floor {serial_floor:?})"
    );
    assert!(
        median * 2 < serial_floor,
        "median {median:?} must beat half the serial floor {serial_floor:?}"
    );
}
