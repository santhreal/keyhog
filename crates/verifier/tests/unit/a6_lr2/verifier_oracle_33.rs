use keyhog_verifier::rate_limit::RateLimiter;

#[test]
fn verifier_oracle_33() {
    let limiter = RateLimiter::new(33.0);
    assert!(limiter.default_interval().as_nanos() > 0);
}
