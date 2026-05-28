use keyhog_verifier::rate_limit::RateLimiter;

#[test]
fn verifier_oracle_13() {
    let limiter = RateLimiter::new(13.0);
    assert!(limiter.default_interval().as_nanos() > 0);
}
