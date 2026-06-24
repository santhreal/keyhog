use keyhog_core::VerificationResult;

#[tokio::test]
async fn verify_all_preserves_join_error_groups_as_error_findings() {
    let finding = keyhog_verifier::testing::tracked_join_error_preservation_for_test()
        .await
        .expect("aborted tracked verifier task should produce an error finding");

    assert_eq!(finding.detector_id.as_ref(), "test-detector");
    assert_eq!(finding.service.as_ref(), "test-service");
    assert_eq!(finding.location.file_path.as_deref(), Some("fixture.txt"));
    match finding.verification {
        VerificationResult::Error(message) => {
            assert!(
                message.contains("verification task failed to join"),
                "join failure must be preserved in the verification result, got {message}"
            );
        }
        other => panic!("expected verification error for aborted task, got {other:?}"),
    }
}
