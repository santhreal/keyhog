use keyhog_verifier::rate_limit::{get_rate_limiter, set_global_default_rps, RateLimiter};
use rusty_fork::rusty_fork_test;

#[test]
fn rate_limiter_constructs_with_positive_rps() {
    let limiter = RateLimiter::new(10.0);
    limiter.set_default_rps(20.0);
}

rusty_fork_test! {
    #![rusty_fork(timeout_ms = 5000)]
    #[test]
    fn set_global_default_rps_updates_shared_limiter() {
        set_global_default_rps(25.0);
        let _limiter = get_rate_limiter();
    }
}
