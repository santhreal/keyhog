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
    /// Checksum matches - token is/was real.
    Valid,
    /// Checksum fails - likely false positive.
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

/// Confidence floor applied to a credential whose embedded checksum is `Valid`.
///
/// A matching CRC is cryptographic proof the token is well-formed, so a
/// confirmed token must clear the high-precision (`--precision`) 0.85 bar. The
/// floor is the single value behind that guarantee; keep it above
/// [`ScannerConfig::HIGH_PRECISION_MIN_CONFIDENCE`](crate::ScannerConfig::HIGH_PRECISION_MIN_CONFIDENCE).
pub const CHECKSUM_VALID_FLOOR: f64 = 0.9;

/// Map a credential's embedded-checksum verdict onto a confidence decision.
///
/// This is the single source of truth for how a [`ChecksumResult`] adjusts a
/// freshly-scored confidence. EVERY match-emission path - the hot-pattern fast
/// path ([`crate::engine`] `hot_patterns`), the regex/`process_match` path, and
/// the batched ML scorer (`apply_ml_batch_scores`) - routes through it so a
/// `ghp_`/`xoxb-`/npm/Stripe/GitLab/PyPI token is adjudicated identically no
/// matter which backend produced the match. Before this existed the fast path
/// skipped checksums entirely (a fabricated `ghp_` survived; a confirmed one
/// never got the boost), so the `--precision` "drops checksum-failing matches"
/// contract was only honoured on the slow regex path.
///
/// - `Valid` -> floor the confidence at [`CHECKSUM_VALID_FLOOR`].
/// - `Invalid` -> the embedded CRC does not match its body (fabricated or
///   corrupted): returns `None` so the caller DROPS the match.
/// - `NotApplicable` -> no checksum to consult: confidence passes through
///   unchanged.
#[inline]
pub fn checksum_adjusted_confidence(confidence: f64, credential: &str) -> Option<f64> {
    match validate_checksum(credential) {
        ChecksumResult::Invalid => None,
        ChecksumResult::Valid => Some(confidence.max(CHECKSUM_VALID_FLOOR)),
        ChecksumResult::NotApplicable => Some(confidence),
    }
}

pub(crate) fn warm_runtime_regexes() {
    slack::warm_runtime_regexes();
}
