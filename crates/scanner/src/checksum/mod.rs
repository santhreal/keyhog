//! Checksum-aware credential validation.
//!
//! Modern API tokens embed self-verifying checksums that let us eliminate
//! false positives without network requests. This module implements
//! validators for several well-documented token families.

mod github;
mod gitlab;
mod npm;
mod slack;
mod stripe;

pub use github::{GithubClassicPatValidator, GithubFineGrainedPatValidator};
pub use gitlab::GitlabTokenValidator;
pub use npm::{NpmTokenValidator, PypiTokenValidator};
pub use slack::SlackTokenValidator;
pub use stripe::StripeTokenValidator;

use std::sync::LazyLock;

/// Result of a checksum validation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChecksumResult {
    /// Checksum matches — token is/was real.
    Valid,
    /// Checksum fails — likely false positive.
    Invalid,
    /// Token format doesn't have a checksum (or this validator can't verify it).
    NotApplicable,
}

/// A validator that can check whether a credential's embedded checksum is correct.
pub trait ChecksumValidator: Send + Sync {
    /// Identifier for this validator (used for diagnostics and registry lookups).
    fn validator_id(&self) -> &str;

    /// Validate the checksum embedded in `credential`.
    ///
    /// Returns [`ChecksumResult::NotApplicable`] when the credential does not
    /// match the token family this validator understands.
    fn validate(&self, credential: &str) -> ChecksumResult;
}

static VALIDATORS: LazyLock<Vec<Box<dyn ChecksumValidator>>> = LazyLock::new(|| {
    vec![
        Box::new(GithubClassicPatValidator),
        Box::new(GithubFineGrainedPatValidator),
        Box::new(NpmTokenValidator),
        Box::new(SlackTokenValidator),
        Box::new(PypiTokenValidator),
        Box::new(StripeTokenValidator),
        Box::new(GitlabTokenValidator),
    ]
});

/// Run the credential through all registered checksum validators.
///
/// The first validator that returns `Valid` or `Invalid` wins.
/// If none claims the token, [`ChecksumResult::NotApplicable`] is returned.
pub fn validate_checksum(credential: &str) -> ChecksumResult {
    for validator in VALIDATORS.iter() {
        match validator.validate(credential) {
            ChecksumResult::NotApplicable => continue,
            result => return result,
        }
    }
    ChecksumResult::NotApplicable
}
