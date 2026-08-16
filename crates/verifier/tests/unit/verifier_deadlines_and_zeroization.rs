//! Unit tests for verifier deadline bounds.

use std::time::Duration;

use keyhog_core::VerificationResult;
use keyhog_verifier::engine::VerificationDeadline;
use keyhog_verifier::testing::TIMEOUT_ERROR;
#[test]
fn deadline_remaining_decreases_and_expires() {
    let timeout = Duration::from_millis(50);
    let deadline = VerificationDeadline::new(timeout);
    assert!(!deadline.is_expired());
    assert!(deadline.remaining().is_ok());

    std::thread::sleep(Duration::from_millis(60));
    assert!(deadline.is_expired());
    assert!(deadline.check().is_err());
    let err = deadline.remaining().unwrap_err();
    match &err {
        VerificationResult::Error(msg) => {
            assert!(msg.contains("timeout:"));
            assert_eq!(msg.as_str(), TIMEOUT_ERROR);
        }
        other => panic!("expected Error with TIMEOUT_ERROR, got {other:?}"),
    }
}

#[test]
fn deadline_for_attempts_scales_budget() {
    let timeout = Duration::from_millis(20);
    let deadline = VerificationDeadline::for_attempts(timeout, 3);
    assert!(!deadline.is_expired());
    assert_eq!(deadline.timeout(), timeout);
    let remaining = deadline.remaining().expect("deadline must not be expired");
    assert!(remaining >= Duration::from_millis(40));
}

#[tokio::test]
async fn deadline_run_bounded_success() {
    let deadline = VerificationDeadline::new(Duration::from_millis(200));
    let result = deadline
        .run_bounded(async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            42
        })
        .await;
    assert_eq!(result, Ok(42));
}

#[tokio::test]
async fn deadline_run_bounded_times_out() {
    let deadline = VerificationDeadline::new(Duration::from_millis(20));
    let result = deadline
        .run_bounded(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            42
        })
        .await;
    match &result {
        Err(VerificationResult::Error(msg)) => {
            assert_eq!(msg.as_str(), TIMEOUT_ERROR);
        }
        other => panic!("expected timeout error, got {other:?}"),
    }
}

