use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[test]
fn retry_backoff_uses_exponential_bounds_with_jitter() {
    assert_eq!(TestApi.retry_delay_bounds_for_attempt(0, 500), (0, 0));
    assert_eq!(TestApi.retry_delay_bounds_for_attempt(1, 500), (500, 625));
    assert_eq!(TestApi.retry_delay_bounds_for_attempt(2, 500), (1000, 1250));
    assert_eq!(TestApi.retry_delay_bounds_for_attempt(3, 500), (2000, 2500));
    assert_eq!(TestApi.retry_delay_bounds_for_attempt(1, 0), (0, 0));
}
