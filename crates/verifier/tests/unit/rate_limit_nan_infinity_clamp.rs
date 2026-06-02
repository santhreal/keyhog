//! Boundary test: NaN and infinite RPS must not produce undefined intervals.
//! Asserts that rps_to_nanos() guards against non-finite values.

use keyhog_verifier::rate_limit::RateLimiter;
use std::time::Duration;

#[test]
fn rate_limit_nan_rps_clamps_to_default() {
    let limiter = RateLimiter::new(f64::NAN);
    let interval = limiter.default_interval();
    assert_eq!(
        interval,
        Duration::from_secs(1),
        "NaN RPS must clamp to 1.0 rps (1 second interval), got {:?}",
        interval
    );
}

#[test]
fn rate_limit_positive_infinity_clamps_to_default() {
    let limiter = RateLimiter::new(f64::INFINITY);
    let interval = limiter.default_interval();
    assert_eq!(
        interval,
        Duration::from_secs(1),
        "positive infinity RPS must clamp to 1.0 rps, got {:?}",
        interval
    );
}

#[test]
fn rate_limit_negative_infinity_clamps_to_default() {
    let limiter = RateLimiter::new(f64::NEG_INFINITY);
    let interval = limiter.default_interval();
    assert_eq!(
        interval,
        Duration::from_secs(1),
        "negative infinity RPS must clamp to 1.0 rps, got {:?}",
        interval
    );
}

#[test]
fn rate_limit_huge_rps_stays_bounded() {
    // Huge RPS (e.g., 1e100) should compute to nanos but stay within u64::MAX
    let limiter = RateLimiter::new(1e100);
    let interval = limiter.default_interval();
    // Should not panic or produce invalid duration; nanos cap is u64::MAX
    assert!(
        interval.as_nanos() > 0 && interval.as_nanos() <= u64::MAX as u128,
        "huge RPS must produce valid interval within u64::MAX, got {:?}",
        interval
    );
}
