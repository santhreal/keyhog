use keyhog_verifier::rate_limit::RateLimiter;
use std::time::Duration;

#[tokio::test]
async fn rate_limit_error_backpressure_applies_without_slot_wait() {
    let limiter = RateLimiter::new(1_000_000.0);
    for _ in 0..51 {
        limiter.record_error();
    }

    let wait = tokio::time::timeout(Duration::from_millis(50), limiter.wait("fresh-service")).await;
    assert!(
        wait.is_err(),
        "global error backpressure must delay even when the service slot is already open"
    );
}
