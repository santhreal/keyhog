use keyhog_verifier::rate_limit::RateLimiter;

#[test]
fn verifier_oracle_22() {
    let limiter = RateLimiter::new(22.0);
    assert!(limiter.default_interval().as_nanos() > 0);
}
