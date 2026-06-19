use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[tokio::test]
async fn retry_preserves_metadata_on_exhaustion() {
    let (res, meta): (keyhog_core::VerificationResult, std::collections::HashMap<String, String>) =
        TestApi.retry_loop_preserves_metadata_on_exhaustion().await;
    assert!(matches!(res, keyhog_core::VerificationResult::Error(_)));
    assert_eq!(meta.get("oob_id").map(String::as_str), Some("abc"));
}
