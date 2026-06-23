use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[tokio::test]
async fn verifier_attempts_feed_rate_limiter_backpressure() {
    let (
        after_rate_limited,
        after_transient_error,
        after_dead_response,
        after_local_unverifiable,
        after_revoked_response,
    ) = TestApi.rate_limit_feedback_sequence();

    assert_eq!(
        after_rate_limited, 1,
        "rate-limited HTTP attempts must increase verifier backpressure"
    );
    assert_eq!(
        after_transient_error, 2,
        "transient verifier errors must increase verifier backpressure"
    );
    assert_eq!(
        after_dead_response, 1,
        "successful HTTP classifications must ease verifier backpressure"
    );
    assert_eq!(
        after_local_unverifiable, 1,
        "local no-request outcomes must not mask upstream verifier backpressure"
    );
    assert_eq!(
        after_revoked_response, 0,
        "revoked HTTP classifications must ease verifier backpressure"
    );
    assert_eq!(
        TestApi.retry_loop_records_rate_limit_feedback().await,
        1,
        "the production retry loop must feed rate-limited attempts into the global limiter"
    );
}
