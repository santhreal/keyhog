//! Property coverage for the verifier rate limiter's ZERO-interval guard
//! (6318 slice 2). A zero inter-request interval means an INFINITE effective
//! rate: the limiter would impose no spacing at all, defeating the back-pressure
//! it exists to provide (an abuse / self-DoS vector against the verified
//! endpoint). `rps_to_nanos` guards EVERY path, non-finite, non-positive,
//! absurdly large (interval rounds below 1ns), and overflowing `u64`: to a
//! strictly-positive interval. The existing `rate_limit_zero_rps_clamps_to_default`
//! unit test pins three fixed adversarial values (0.0, -42, NaN); this sweep
//! generalises the invariant to a DENSE stream of arbitrary `f64` bit patterns
//! covering ±inf, NaN, `f64::MAX`, subnormals, negatives, and every finite
//! magnitude. It uses the same hand-rolled LCG as the SSRF sweep (this crate
//! carries no `proptest` dev-dependency) so a failing `rps` is reproducible from
//! its seed.

use crate::common::lcg;
use keyhog_verifier::rate_limit::RateLimiter;
use std::time::Duration;

/// Draw a full-range `f64` from two LCG steps: every 64-bit pattern is a valid
/// `f64`, so this samples NaN, ±inf, subnormals, and the entire finite range
/// exactly the adversarial space `rps_to_nanos` must survive. Denser and more
/// hostile than `proptest`'s `any::<f64>()`, which biases toward "nice" values.
fn draw_f64(state: &mut u32) -> f64 {
    let hi = lcg(state) as u64;
    let lo = lcg(state) as u64;
    f64::from_bits((hi << 32) | lo)
}

const SAMPLES: usize = 100_000;

#[test]
fn rate_limiter_interval_is_never_zero_for_any_rps() {
    // A zero interval == infinite rate == no back-pressure. The guard must hold
    // for EVERY f64 through both the constructor and the runtime setter, and
    // neither may panic (a panic fails the test at that seed).
    let mut state = 0xC0FF_EE01;
    for _ in 0..SAMPLES {
        let rps = draw_f64(&mut state);

        let rl = RateLimiter::new(rps);
        assert!(
            rl.default_interval() > Duration::ZERO,
            "RateLimiter::new({rps}) [bits {:#018x}] produced a ZERO interval = infinite rate",
            rps.to_bits(),
        );

        // The runtime re-tune path shares the same guard.
        rl.set_default_rps(rps);
        assert!(
            rl.default_interval() > Duration::ZERO,
            "set_default_rps({rps}) [bits {:#018x}] produced a ZERO interval = infinite rate",
            rps.to_bits(),
        );
        // No tight UPPER bound is asserted on purpose: a low rate (rps = 0.5)
        // legitimately yields a multi-second interval (1e9/0.5 = 2s); the 1e9-ns
        // clamp only guards genuine u64 overflow (rps below ~5e-11). The
        // security-load-bearing invariant is strictly the lower bound.
    }
}

#[test]
fn rate_limiter_interval_positive_across_arbitrary_retune() {
    // No ORDERING of two arbitrary rps values (construct with one, re-tune to the
    // other) can wedge the interval to zero (the guard is stateless per set).
    let mut state = 0x5EED_1234;
    for _ in 0..SAMPLES {
        let rps_a = draw_f64(&mut state);
        let rps_b = draw_f64(&mut state);
        let rl = RateLimiter::new(rps_a);
        rl.set_default_rps(rps_b);
        assert!(
            rl.default_interval() > Duration::ZERO,
            "retune {rps_a} -> {rps_b} produced a ZERO interval = infinite rate",
        );
    }
}
