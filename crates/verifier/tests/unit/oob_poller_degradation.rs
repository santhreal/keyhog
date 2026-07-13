//! Re-homed from the former inline `poller_degradation_tests` in
//! `crates/verifier/src/oob/session.rs`: the `oob_session_no_inline_tests`
//! folder-contract gate forbids inline `#[cfg(test)]` there.
//!
//! Pins the OOB poller-degradation fail-closed SECURITY contract: once polls to
//! the interactsh collector fail `OOB_DEGRADED_ERROR_THRESHOLD` times in a row
//! the poller is "degraded", and a subsequent `wait_for` TIMEOUT must fail closed
//! (`Disabled`, a verification error) instead of a false `NotObserved`: which
//! would misreport a possibly-live secret as dead (Law 10). The private
//! `poller_is_degraded` / `elapsed_verdict` / degraded seam are exercised through
//! the `testing` facade accessors so they stay module-private.

use keyhog_verifier::oob::{OobAccept, OobConfig, OobObservation};
use keyhog_verifier::testing::{
    oob_degraded_error_threshold, oob_elapsed_verdict, oob_poller_is_degraded, TestApi,
    VerifierTestApi,
};
use std::sync::Arc;
use std::time::Duration;

#[test]
fn degraded_only_at_or_past_threshold() {
    let threshold = oob_degraded_error_threshold();
    // Below the threshold the poller is NOT degraded, a transient one- or
    // two-poll blip must never flip healthy `NotObserved` verdicts into
    // inconclusive `Disabled` ones.
    assert!(!oob_poller_is_degraded(0), "zero errors is healthy");
    for n in 1..threshold {
        assert!(
            !oob_poller_is_degraded(n),
            "{n} consecutive errors (< {threshold}) must stay healthy"
        );
    }
    // At and beyond the threshold the collector is treated as unreachable.
    assert!(oob_poller_is_degraded(threshold));
    assert!(oob_poller_is_degraded(threshold + 100));
}

#[test]
fn elapsed_verdict_fails_closed_only_when_degraded() {
    // Healthy poller: a timeout means the callback never fired -> NotObserved.
    assert!(
        matches!(oob_elapsed_verdict(false), OobObservation::NotObserved),
        "healthy timeout must be NotObserved, never a fabricated Disabled"
    );
    // Degraded poller: the timeout is untrustworthy -> fail closed Disabled (a
    // verification error), never a false "not observed" that would misreport a
    // live secret as dead.
    match oob_elapsed_verdict(true) {
        OobObservation::Disabled(reason) => assert!(
            reason.contains("unreachable") && reason.contains("inconclusive"),
            "Disabled reason must explain the OOB channel was down: {reason}"
        ),
        other => panic!("degraded poller must fail closed with Disabled, got {other:?}"),
    }
}

/// End-to-end: the REAL `wait_for` timeout path must read the degraded flag and
/// fail closed. Uses the network-free `for_test` seams (no poller, no
/// registration) so the only variable is the degraded bit.
#[tokio::test]
async fn wait_for_timeout_honours_degraded_flag() {
    let client = Arc::new(
        TestApi
            .interactsh_client_for_test("https://oast.fun")
            .expect("for_test client builds without network"),
    );
    let session = TestApi.oob_session_for_test(client, OobConfig::default());

    // Healthy: an empty wait that hits its tiny timeout is NotObserved, the
    // callback simply never fired.
    let healthy = session
        .wait_for("id-never-hit", OobAccept::Any, Duration::from_millis(10))
        .await;
    assert!(
        matches!(healthy, OobObservation::NotObserved),
        "healthy timeout must be NotObserved, got {healthy:?}"
    );

    // Degraded: the SAME empty-wait timeout must fail closed (Disabled), because
    // the channel that would deliver the callback is down. Reporting NotObserved
    // here would misclassify a possibly-live secret as dead.
    TestApi.oob_session_set_degraded_for_test(&session, true);
    let degraded = session
        .wait_for("id-never-hit", OobAccept::Any, Duration::from_millis(10))
        .await;
    match degraded {
        OobObservation::Disabled(reason) => assert!(
            reason.contains("unreachable"),
            "degraded timeout reason must cite the unreachable collector: {reason}"
        ),
        other => panic!("degraded wait timeout must fail closed, got {other:?}"),
    }
}
