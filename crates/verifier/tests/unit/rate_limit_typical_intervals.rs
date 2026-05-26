use keyhog_verifier::rate_limit::RateLimiter;
use std::time::Duration;

#[test]
fn rate_limit_typical_intervals() {
    assert_eq!(
        RateLimiter::new(1.0).default_interval(),
        Duration::from_secs(1)
    );
    assert_eq!(
        RateLimiter::new(5.0).default_interval(),
        Duration::from_millis(200)
    );
    assert_eq!(
        RateLimiter::new(100.0).default_interval(),
        Duration::from_millis(10)
    );
}
