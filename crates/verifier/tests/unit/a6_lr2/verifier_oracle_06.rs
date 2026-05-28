use keyhog_verifier::rate_limit::RateLimiter;

#[test]
fn verifier_oracle_06() {
    let limiter = RateLimiter::new(6.0);
    assert!(limiter.default_interval().as_nanos() > 0);
}
