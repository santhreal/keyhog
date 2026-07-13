use keyhog_verifier::rate_limit::RateLimiter;
use std::time::Duration;

#[test]
fn rate_limit_rps_to_nanos_clamps_invalid() {
    assert_eq!(
        RateLimiter::new(0.0).default_interval(),
        Duration::from_secs(1)
    );
    assert_eq!(
        RateLimiter::new(-1.0).default_interval(),
        Duration::from_secs(1)
    );
}

/// VALID-input overflow branch (distinct from the invalid-clamp above): a tiny
/// but *positive, finite* rps passes the `rps.is_finite() && rps > 0.0` guard
/// so it is NOT sent through the 1.0 fallback, and then the interval it implies
/// (`1e9 / 1e-20 = 1e29` ns) exceeds `u64::MAX`. `rps_to_nanos` must take its
/// final `else` arm and return exactly one second, never wrap/panic on the
/// `nanos as u64` cast. The clamp-invalid test cannot reach this arm because its
/// inputs never survive the first guard; this pins the second, independent guard.
#[test]
fn rate_limit_rps_to_nanos_tiny_positive_rate_overflows_to_one_second() {
    assert_eq!(
        RateLimiter::new(1e-20).default_interval(),
        Duration::from_secs(1),
        "a valid but unrepresentably-slow rps must clamp its interval to 1s, not overflow the u64 nanos cast"
    );
}

/// VALID-input underflow branch: an rps so fast that the implied interval rounds
/// below one nanosecond (`1e9 / 1e10 = 0.1 ns → round → 0`) must be floored to
/// the `1` ns minimum, never a zero-interval (= unbounded-rate) slot. Zero would
/// make `next_slot == last_request`, letting a service burst with no pacing at
/// all (a rate-limit-bypass bug. Pins the `nanos < 1.0 => 1` floor arm).
#[test]
fn rate_limit_rps_to_nanos_huge_rate_floors_to_one_nanosecond() {
    assert_eq!(
        RateLimiter::new(1e10).default_interval(),
        Duration::from_nanos(1),
        "an unrepresentably-fast rps must floor to a 1ns interval, never a zero-interval (unbounded-rate) slot"
    );
}
