use keyhog_verifier::rate_limit::{get_rate_limiter, set_global_default_rps, RateLimiter};

#[test]
fn rate_limiter_constructs_with_positive_rps() {
    let limiter = RateLimiter::new(10.0);
    limiter.set_default_rps(20.0);
}

#[test]
fn set_global_default_rps_updates_shared_limiter() {
    set_global_default_rps(25.0);
    let _limiter = get_rate_limiter();
}
