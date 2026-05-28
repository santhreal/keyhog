use keyhog_verifier::rate_limit::RateLimiter;
use std::time::{Duration, Instant};

#[tokio::test]
async fn rate_limit_burst_respects_interval() {
    let limiter = RateLimiter::new(10.0);
    limiter.update_limit("svc", 5.0).await;
    let t0 = Instant::now();
    limiter.wait("svc").await;
    limiter.wait("svc").await;
    let elapsed = t0.elapsed();
    assert!(elapsed >= Duration::from_millis(150), "second wait must queue after first slot, got {elapsed:?}");
}
