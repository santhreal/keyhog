//! Per-service AIMD backoff MUST recover.
//!
//! Regression for the never-recovers bug: a `429` used to `update_limit(service,
//! 0.5)`, a HARD SET to 0.5 rps that pinned the service to a 2s interval for the
//! rest of the process, even after thousands of successes (Law 7: a permanently
//! throttled verifier is a throughput bug). The replacement is classic AIMD:
//! multiplicative decrease on `429` (`penalize_service`), additive increase on
//! every successful round-trip (`reward_service`), floored at the configured base
//! and capped at a max interval. Every assertion here is an EXACT `Duration`, not
//! a shape check.

use keyhog_verifier::rate_limit::RateLimiter;
use std::time::Duration;

#[tokio::test]
async fn service_rate_recovers_after_429_backoff() {
    let rl = RateLimiter::new(10.0); // default 10 rps = 100ms interval
    rl.update_limit("svc", 10.0).await; // base_interval = interval = 100ms
    let base = rl
        .service_interval("svc")
        .expect("update_limit creates the slot");
    assert_eq!(base, Duration::from_millis(100), "base interval is 1/10 s");

    // Multiplicative decrease: each 429 doubles the interval (halves the rate).
    rl.penalize_service("svc");
    assert_eq!(
        rl.service_interval("svc").unwrap(),
        Duration::from_millis(200),
        "one 429 doubles the interval"
    );
    rl.penalize_service("svc");
    assert_eq!(
        rl.service_interval("svc").unwrap(),
        Duration::from_millis(400),
        "sustained 429s keep backing off multiplicatively"
    );

    // Additive increase: each success recovers base/2 = 50ms, floored at base.
    // 400 -> 350 -> 300 -> 250 -> 200 -> 150 -> 100 (6 successes).
    rl.reward_service("svc");
    assert_eq!(
        rl.service_interval("svc").unwrap(),
        Duration::from_millis(350),
        "one success recovers exactly base/2 of the backoff"
    );
    for _ in 0..5 {
        rl.reward_service("svc");
    }
    assert_eq!(
        rl.service_interval("svc").unwrap(),
        base,
        "enough successes recover all the way back to the configured base"
    );

    // Recovery is floored: further successes never make it faster than base.
    rl.reward_service("svc");
    rl.reward_service("svc");
    assert_eq!(
        rl.service_interval("svc").unwrap(),
        base,
        "recovery never exceeds the configured base rate"
    );
}

#[tokio::test]
async fn backoff_is_capped_at_max_interval_and_never_overflows() {
    let rl = RateLimiter::new(1000.0); // 1ms base
    rl.update_limit("svc", 1000.0).await;
    // 40 doublings would overflow a naive Duration multiply; the cap + checked_mul
    // must saturate at exactly the 8s ceiling instead of panicking.
    for _ in 0..40 {
        rl.penalize_service("svc");
    }
    assert_eq!(
        rl.service_interval("svc").unwrap(),
        Duration::from_secs(8),
        "sustained throttling saturates at RATE_LIMIT_MAX_INTERVAL (8s), never overflows"
    );
    // One success recovers base/2 = 0.5ms off the 8s ceiling (proves recovery
    // engages even from the fully-saturated state).
    rl.reward_service("svc");
    assert_eq!(
        rl.service_interval("svc").unwrap(),
        Duration::from_secs(8) - Duration::from_micros(500),
        "recovery steps down from the saturated ceiling by base/2"
    );
}

#[tokio::test]
async fn penalizing_an_unknown_service_seeds_a_backed_off_slot() {
    let rl = RateLimiter::new(10.0); // default 100ms
    assert!(
        rl.service_interval("absent").is_none(),
        "no slot exists before the first wait/penalize"
    );
    rl.penalize_service("absent");
    assert_eq!(
        rl.service_interval("absent").unwrap(),
        Duration::from_millis(200),
        "penalizing an unknown service seeds a slot at 2x the default (backed off once)"
    );
}

#[tokio::test]
async fn rewarding_an_unknown_service_is_a_noop() {
    let rl = RateLimiter::new(10.0);
    rl.reward_service("absent");
    assert!(
        rl.service_interval("absent").is_none(),
        "rewarding a service that was never throttled must not create a slot"
    );
}

#[tokio::test]
async fn wait_lazy_create_seeds_base_at_default_and_recovers_to_it() {
    // The `wait()` lazy-create path (distinct from update_limit / penalize-unknown)
    // must seed base_interval = the DEFAULT interval, so AIMD recovery floors at
    // the default rather than at 0/unset. A fresh service admitted on first wait
    // starts at the default; a 429 doubles it; two successes recover exactly to
    // the default and no further.
    let rl = RateLimiter::new(20.0); // default 20 rps = 50ms
    rl.wait("fresh").await; // lazily creates the slot at the default interval
    let default = Duration::from_millis(50);
    assert_eq!(
        rl.service_interval("fresh").unwrap(),
        default,
        "a lazily-created (via wait) service starts at the default interval"
    );
    rl.penalize_service("fresh");
    assert_eq!(
        rl.service_interval("fresh").unwrap(),
        Duration::from_millis(100),
        "429 doubles the lazily-created service's interval"
    );
    // Recovery step = base/2 = 25ms: 100 → 75 → 50 (floored at the default base).
    rl.reward_service("fresh");
    rl.reward_service("fresh");
    assert_eq!(
        rl.service_interval("fresh").unwrap(),
        default,
        "recovery floors at the lazily-seeded default base (proves base_interval == default)"
    );
    rl.reward_service("fresh");
    assert_eq!(
        rl.service_interval("fresh").unwrap(),
        default,
        "further successes never drop below the lazily-seeded default"
    );
}
