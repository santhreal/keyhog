//! Boundary test: zero RPS must not produce a zero interval (infinite rate).
//! Asserts that rps_to_nanos clamps to 1.0 rps (1 second interval) as fallback.

use keyhog_verifier::rate_limit::RateLimiter;
use std::time::Duration;

#[test]
fn rate_limit_zero_rps_clamps_to_default() {
    // Zero RPS explicitly - should not produce zero interval
    let limiter = RateLimiter::new(0.0);
    let interval = limiter.default_interval();
    assert_eq!(
        interval,
        Duration::from_secs(1),
        "zero RPS must clamp to 1.0 rps (1 second interval), got {:?}",
        interval
    );
}

#[test]
fn rate_limit_negative_rps_clamps_to_default() {
    // Negative RPS - should not produce negative duration
    let limiter = RateLimiter::new(-42.0);
    let interval = limiter.default_interval();
    assert_eq!(
        interval,
        Duration::from_secs(1),
        "negative RPS must clamp to 1.0 rps (1 second interval), got {:?}",
        interval
    );
}

#[test]
fn rate_limit_subnormal_rps_clamps_to_default() {
    // Subnormal (very small but positive) - still clamped
    let limiter = RateLimiter::new(f64::MIN_POSITIVE);
    let interval = limiter.default_interval();
    // Should not be zero; should be huge but bounded by u64::MAX as nanos
    assert!(
        interval.as_nanos() > 0,
        "subnormal RPS must produce non-zero interval, got {:?}",
        interval
    );
    assert!(
        interval.as_secs() > 0,
        "subnormal RPS must produce second-scale interval, got {:?}",
        interval
    );
}
