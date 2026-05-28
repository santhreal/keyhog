use keyhog_verifier::rate_limit::RateLimiter;

#[test]
fn verifier_oracle_04() {
    let limiter = RateLimiter::new(4.0);
    assert!(limiter.default_interval().as_nanos() > 0);
}
