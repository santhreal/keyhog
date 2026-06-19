//! Checksum-aware credential validation.
//!
//! Modern API tokens embed self-verifying checksums that let us eliminate
//! false positives without network requests. This module implements
//! validators for several well-documented token families.

pub(crate) mod github;
pub(crate) mod gitlab;
pub(crate) mod npm;
pub(crate) mod slack;
pub(crate) mod stripe;

use github::{GithubClassicPatValidator, GithubFineGrainedPatValidator};
use gitlab::GitlabTokenValidator;
use npm::{NpmTokenValidator, PypiTokenValidator};
use slack::SlackTokenValidator;
use stripe::StripeTokenValidator;

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
pub(crate) trait ChecksumValidator: Send + Sync {
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

#[cfg(test)]
pub(crate) fn standard_crc32(data: &[u8]) -> u32 {
    github::crc32(data)
}

#[cfg(test)]
pub(crate) fn base62_encode_u32(value: u32, width: usize) -> String {
    github::base62_encode_u32(value, width)
}

#[cfg(test)]
pub(crate) fn crc32_base62_suffix(data: &[u8], width: usize) -> String {
    base62_encode_u32(standard_crc32(data), width)
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
