use keyhog_verifier::rate_limit::RateLimiter;
use std::time::Duration;

#[test]
fn rate_limit_rps_to_nanos_clamps_invalid() {
    assert_eq!(RateLimiter::new(0.0).default_interval(), Duration::from_secs(1));
    assert_eq!(RateLimiter::new(-1.0).default_interval(), Duration::from_secs(1));
}
