//! Checksum-aware credential validation.
//!
//! Modern API tokens embed self-verifying checksums that let us eliminate
//! false positives without network requests. This module implements
//! validators for several well-documented token families.

pub(crate) mod github;
pub(crate) mod gitlab;
pub(crate) mod npm;
pub(crate) mod prefixes;
pub(crate) mod slack;
pub(crate) mod stripe;

use github::{GithubClassicPatValidator, GithubFineGrainedPatValidator};
use gitlab::GitlabTokenValidator;
use npm::{NpmTokenValidator, PypiTokenValidator};
use slack::SlackTokenValidator;
use stripe::StripeTokenValidator;

use std::sync::LazyLock;

const BASE62_DIGITS: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Result of a checksum validation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChecksumResult {
    /// Checksum matches - token is/was real.
    Valid,
    /// Token family and shape are valid, but no embedded checksum was verified.
    StructurallyValid,
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
/// The first validator that returns a claimed verdict wins.
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

/// True when extending `original` to `extended` turned a `Valid` checksum into a
/// non-`Valid` one, a boundary extension that corrupted a complete,
/// checksum-valid token by grabbing an adjacent byte. The credential-boundary
/// extender in `engine::scan_filters` reverts to `original` in that case so the
/// canonical, checksum-valid token still surfaces.
///
/// Lives here in the checksum-validity owner so engine emission paths ask a
/// named checksum question rather than owning raw `validate_checksum` calls (the
/// `engine_match_policy_checksum_owner` architecture gate keeps confidence AND
/// validity primitives out of `src/engine/`).
pub(crate) fn extension_downgrades_checksum(original: &str, extended: &str) -> bool {
    validate_checksum(original) == ChecksumResult::Valid
        && validate_checksum(extended) != ChecksumResult::Valid
}

/// Compute the standard CRC32 checksum of `data`.
pub(crate) fn crc32(data: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut crc = i as u32;
            let mut j = 0;
            while j < 8 {
                if crc & 1 != 0 {
                    crc = 0xEDB88320 ^ (crc >> 1);
                } else {
                    crc >>= 1;
                }
                j += 1;
            }
            table[i] = crc;
            i += 1;
        }
        table
    };

    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc = TABLE[((crc ^ (byte as u32)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

/// Encode a `u32` as base62, left-padded with `'0'` to `width` characters.
pub(crate) fn base62_encode_u32(mut value: u32, width: usize) -> String {
    if value == 0 {
        return "0".repeat(width);
    }
    let mut rev = Vec::with_capacity(width.max(6));
    while value > 0 {
        rev.push(BASE62_DIGITS[(value % 62) as usize] as char);
        value /= 62;
    }
    while rev.len() < width {
        rev.push('0');
    }
    rev.reverse();
    rev.into_iter().collect()
}

/// Confidence floor applied to a credential whose embedded checksum is `Valid`.
///
/// A matching CRC is cryptographic proof the token is well-formed, so a
/// confirmed token must clear the high-precision (`--precision`) 0.85 bar. The
/// floor is the single value behind that guarantee; keep it above
/// [`ScannerConfig::HIGH_PRECISION_MIN_CONFIDENCE`](crate::ScannerConfig::HIGH_PRECISION_MIN_CONFIDENCE).
pub const CHECKSUM_VALID_FLOOR: f64 = 0.9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChecksumConfidenceDecision {
    result: ChecksumResult,
}

impl ChecksumConfidenceDecision {
    #[inline]
    pub(crate) fn for_credential(credential: &str) -> Self {
        Self {
            result: validate_checksum(credential),
        }
    }

    #[inline]
    pub(crate) fn is_invalid(self) -> bool {
        matches!(self.result, ChecksumResult::Invalid)
    }

    #[inline]
    pub(crate) fn result(self) -> ChecksumResult {
        self.result
    }
}

/// Compatibility wrapper for applying a credential's embedded-checksum verdict
/// to a confidence score.
///
/// The confidence adjustment policy lives in [`crate::confidence::policy`];
/// this public wrapper preserves the checksum module API used by tests and
/// callers while keeping match-scoring ownership in the confidence subsystem.
///
/// - `Valid` -> floor the confidence at [`CHECKSUM_VALID_FLOOR`].
/// - `StructurallyValid` -> token shape is valid, but no checksum proof exists:
///   confidence passes through unchanged.
/// - `Invalid` -> the embedded CRC does not match its body (fabricated or
///   corrupted): returns `None` so the caller DROPS the match.
/// - `NotApplicable` -> no checksum to consult: confidence passes through
///   unchanged.
#[inline]
pub fn checksum_adjusted_confidence(confidence: f64, credential: &str) -> Option<f64> {
    crate::confidence::policy::apply_checksum_confidence(confidence, credential)
}

pub(crate) fn warm_runtime_regexes() {
    slack::warm_runtime_regexes();
}
