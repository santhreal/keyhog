use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use std::time::Duration;

/// WHY: one OOB lifecycle may burst register, poll, and deregister, but every
/// later request must remain spaced at the configured sustained service rate.
#[test]
fn bounded_burst_preserves_sustained_rate() {
    let interval = Duration::from_millis(200);
    let waits = TestApi.rate_limiter_burst_waits(interval, 3, 5);
    assert_eq!(
        waits,
        vec![
            None,
            None,
            None,
            Some(Duration::from_millis(200)),
            Some(Duration::from_millis(400)),
        ]
    );

    let zero_burst = TestApi.rate_limiter_burst_waits(interval, 0, 3);
    assert_eq!(
        zero_burst,
        vec![
            None,
            Some(Duration::from_millis(200)),
            Some(Duration::from_millis(400)),
        ],
        "zero burst must clamp to the one-token safe default"
    );
}
