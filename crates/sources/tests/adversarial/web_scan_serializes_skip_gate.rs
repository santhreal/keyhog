//! A foreign source scan that records a skip MUST serialize behind a
//! counter-asserting test's exclusive scope (it takes the scan read lease), so
//! it can never pollute the process-global skip counters another test is
//! mid-assertion on.
//!
//! Regression for `web`: its `chunks()` previously skipped the lease, so a
//! concurrent SSRF-blocked web scan's `Unreadable` increment intermittently
//! flipped a sibling coverage-gap assertion (the `zero_byte_gzip` test, which
//! asserts `skip_counts().unreadable == 1`) from 1 to 2 under parallel
//! `cargo test`: a false CI red whose production behavior was correct.
//!
//! The discriminator here is BLOCKING, not a global-counter read (which would
//! itself be contamination-prone and reintroduce the very flake under test):
//! while the exclusive scope is held, a *gated* web scan cannot finish (it is
//! parked on the read lease before it records); an *ungated* one records and
//! returns immediately. So this test FAILS while `web` is ungated and PASSES
//! once it takes the lease.

#[cfg(feature = "web")]
#[test]
fn web_scan_serializes_behind_exclusive_counter_scope() {
    use keyhog_core::Source;
    use keyhog_sources::testing::{SourceTestApi, TestApi};
    use std::sync::mpsc;
    use std::time::Duration;

    // Take the exclusive counter scope on THIS thread: arms the gate and holds
    // the write lease. Every gated foreign scan must now block until we drop it.
    let scope = TestApi.skip_counter_guard();

    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        // An SSRF-blocked link-local host (cloud-metadata IP) records exactly
        // one `Unreadable` and makes NO network call. A gated `chunks()` parks
        // on the read lease BEFORE that recording; an ungated one records and
        // returns at once. `allow=false` keeps the autoroute-loopback exception
        // off so the host is screened.
        let src = TestApi.web_source_with_autoroute_loopback_calibration(
            vec!["http://169.254.169.254/latest/meta-data/".to_string()],
            false,
        );
        let err_rows = src.chunks().filter(|row| row.is_err()).count();
        // Signal completion so the parent can detect whether the scan finished
        // while the exclusive scope was still held.
        let _ = tx.send(());
        err_rows
    });

    // The gated web scan must NOT finish while the exclusive scope is held.
    // (Ungated -> it records + returns in microseconds -> recv returns Ok ->
    //  FAIL: the contamination this gate exists to prevent is still possible.)
    assert!(
        rx.recv_timeout(Duration::from_secs(2)).is_err(),
        "web chunks() completed while a counter-asserting exclusive scope was held; it did \
         not take the scan read lease, so a concurrent web scan can still pollute another \
         test's skip counters"
    );

    // Release the scope; the previously-parked web scan now proceeds and does
    // its real work, proving the test did not pass on a no-op scan.
    drop(scope);
    let err_rows = worker.join().expect("web scan worker panicked");
    assert_eq!(
        err_rows, 1,
        "the unblocked SSRF-blocked web scan must emit exactly one coverage-gap error"
    );
}

#[cfg(not(feature = "web"))]
#[test]
fn web_scan_serializes_behind_exclusive_counter_scope() {}
