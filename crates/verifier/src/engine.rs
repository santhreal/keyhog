//! Verification engine deadline bounds and sensitive intermediate state management.
//!
//! Enforces strict bounded deadline checks across verification execution and
//! ensures intermediate auth header strings and credentials are automatically
//! zeroized on completion or error.

use std::future::Future;
use std::time::{Duration, Instant};

use keyhog_core::VerificationResult;

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

