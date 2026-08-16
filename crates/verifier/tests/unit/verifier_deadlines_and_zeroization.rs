//! Unit tests for verifier deadline bounds and zeroizing auth headers.

use std::sync::Arc;
use std::time::Duration;

use keyhog_core::VerificationResult;
use keyhog_verifier::engine::{acquire_permit_bounded, VerificationDeadline, ZeroizingAuthHeader};
use keyhog_verifier::testing::TIMEOUT_ERROR;
use tokio::sync::Semaphore;
use zeroize::Zeroize;

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

#[tokio::test]
async fn acquire_permit_bounded_success() {
    let semaphore = Semaphore::new(1);
    let deadline = VerificationDeadline::new(Duration::from_millis(100));
    let permit = acquire_permit_bounded(&semaphore, &deadline).await;
    assert!(permit.is_ok());
}

#[tokio::test]
async fn acquire_permit_bounded_times_out_when_saturated() {
    let semaphore = Arc::new(Semaphore::new(0));
    let deadline = VerificationDeadline::new(Duration::from_millis(20));
    let result = acquire_permit_bounded(&semaphore, &deadline).await;
    match &result {
        Err(VerificationResult::Error(msg)) => {
            assert_eq!(msg.as_str(), TIMEOUT_ERROR);
        }
        other => panic!("expected timeout error on saturated semaphore, got {other:?}"),
    }
}

#[test]
fn zeroizing_auth_header_redacts_debug() {
    let header = ZeroizingAuthHeader::new("Bearer secret_token_12345".to_string());
    assert_eq!(header.as_str(), "Bearer secret_token_12345");
    let debug_output = format!("{header:?}");
    assert!(!debug_output.contains("secret_token_12345"));
    assert_eq!(debug_output, "[REDACTED AUTH HEADER]");
}

#[test]
fn zeroizing_auth_header_zeroizes_explicitly() {
    let mut header = ZeroizingAuthHeader::new("Bearer my_api_key".to_string());
    assert_eq!(header.as_str(), "Bearer my_api_key");
    header.zeroize();
    assert_eq!(header.as_str(), "");
}
