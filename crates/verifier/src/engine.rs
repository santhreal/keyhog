//! Verification engine deadline bounds and sensitive intermediate state management.
//!
//! Enforces strict bounded deadline checks across verification execution and
//! ensures intermediate auth header strings and credentials are automatically
//! zeroized on completion or error.

use std::future::Future;
use std::time::{Duration, Instant};

use keyhog_core::VerificationResult;
use tokio::sync::{Semaphore, SemaphorePermit};
use zeroize::{Zeroize, Zeroizing};

use crate::verify::request::TIMEOUT_ERROR;

/// Enforces a strict bounded deadline for verification tasks.
#[derive(Debug, Clone, Copy)]
pub struct VerificationDeadline {
    start: Instant,
    deadline: Instant,
    timeout: Duration,
}

impl VerificationDeadline {
    /// Create a new verification deadline from the given timeout duration.
    pub fn new(timeout: Duration) -> Self {
        let start = Instant::now();
        let deadline = start.checked_add(timeout).unwrap_or(start);
        Self {
            start,
            deadline,
            timeout,
        }
    }

    /// Create a bounded deadline for a multi-attempt task.
    pub fn for_attempts(timeout: Duration, max_attempts: usize) -> Self {
        let start = Instant::now();
        let total_duration = timeout
            .saturating_mul(max_attempts as u32)
            .max(Duration::from_secs(1));
        let deadline = start.checked_add(total_duration).unwrap_or(start);
        Self {
            start,
            deadline,
            timeout,
        }
    }

    /// Return the remaining duration before the deadline expires.
    ///
    /// Fails closed with [`TIMEOUT_ERROR`] if the deadline has already passed.
    pub fn remaining(&self) -> Result<Duration, VerificationResult> {
        let now = Instant::now();
        if now >= self.deadline {
            Err(VerificationResult::Error(TIMEOUT_ERROR.into()))
        } else {
            Ok(self.deadline.saturating_duration_since(now))
        }
    }

    /// Check whether the deadline has passed, returning an error if expired.
    pub fn check(&self) -> Result<(), VerificationResult> {
        if self.is_expired() {
            Err(VerificationResult::Error(TIMEOUT_ERROR.into()))
        } else {
            Ok(())
        }
    }

    /// Returns `true` if the deadline has elapsed.
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// Elapsed time since this deadline was constructed.
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// The base timeout configured for this deadline.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Execute a future bounded strictly by the remaining deadline.
    pub async fn run_bounded<F, T>(&self, fut: F) -> Result<T, VerificationResult>
    where
        F: Future<Output = T>,
    {
        let remaining = self.remaining()?;
        match tokio::time::timeout(remaining, fut).await {
            Ok(val) => Ok(val),
            Err(_) => Err(VerificationResult::Error(TIMEOUT_ERROR.into())),
        }
    }
}

/// Acquire a semaphore permit under a strict bounded deadline.
pub async fn acquire_permit_bounded<'a>(
    semaphore: &'a Semaphore,
    deadline: &VerificationDeadline,
) -> Result<SemaphorePermit<'a>, VerificationResult> {
    let remaining = deadline.remaining()?;
    match tokio::time::timeout(remaining, semaphore.acquire()).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_closed)) => Err(VerificationResult::Error(
            "verification semaphore closed".into(),
        )),
        Err(_elapsed) => Err(VerificationResult::Error(TIMEOUT_ERROR.into())),
    }
}

/// A zeroizing wrapper around intermediate authentication header strings.
///
/// Ensures credentials and authorization tokens populated into HTTP headers
/// are securely zeroed out when the wrapper is dropped on completion or error.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ZeroizingAuthHeader(Zeroizing<String>);

impl ZeroizingAuthHeader {
    /// Wrap an existing string into zeroized storage.
    pub fn new(header_value: String) -> Self {
        Self(Zeroizing::new(header_value))
    }

    /// Borrow the inner header value as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Extract the inner string reference.
    pub fn inner(&self) -> &Zeroizing<String> {
        &self.0
    }
}

impl std::ops::Deref for ZeroizingAuthHeader {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Debug for ZeroizingAuthHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED AUTH HEADER]")
    }
}

impl Zeroize for ZeroizingAuthHeader {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
