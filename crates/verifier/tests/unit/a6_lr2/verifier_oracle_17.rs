use keyhog_verifier::rate_limit::RateLimiter;

#[test]
fn verifier_oracle_17() {
    let limiter = RateLimiter::new(17.0);
    assert!(limiter.default_interval().as_nanos() > 0);
}
