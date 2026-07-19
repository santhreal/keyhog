//! Checksum-aware credential validation.
//!
//! Modern API tokens expose offline evidence that can eliminate false positives
//! without network requests. Individual detector TOMLs own the validator type,
//! prefixes, layout parameters, and confidence floor; this module supplies the
//! shared compiled primitives.

mod compiled;

pub(crate) use compiled::{CompiledDetectorValidators, CompiledValidatorIndex};

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

static VALIDATOR_CATALOG: LazyLock<compiled::CompiledValidatorCatalog> = LazyLock::new(|| {
    match compiled::CompiledValidatorCatalog::compile(keyhog_core::embedded_detector_specs()) {
        Ok(catalog) => catalog,
        Err(error) => panic!(
            "embedded detector validators failed to compile: {error}. Fix the owning detector TOML"
        ),
    }
});

/// Validate a credential against the compiled embedded detector catalog.
/// Custom scanners use their own compiled plans and never consult this catalog.
pub fn validate_checksum(credential: &str) -> ChecksumResult {
    VALIDATOR_CATALOG.validate_any(credential).result()
}

#[inline]
pub(crate) fn validate_for_detector(
    detector_id: &str,
    credential: &str,
) -> ChecksumConfidenceDecision {
    VALIDATOR_CATALOG.validate_for_detector(detector_id, credential)
}

pub(crate) fn detector_declared_prefixes() -> Vec<&'static str> {
    VALIDATOR_CATALOG.prefixes()
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

/// Compatibility floor used only by callers that construct a `Valid` decision
/// without a detector declaration. Production detector plans carry the owning
/// TOML's explicit `confidence_floor` instead.
pub const CHECKSUM_VALID_FLOOR: f64 = 0.9;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct ChecksumConfidenceDecision {
    result: ChecksumResult,
    valid_confidence_floor: Option<f64>,
    claimed_family: bool,
}

impl ChecksumConfidenceDecision {
    #[inline]
    pub(crate) const fn new(result: ChecksumResult, valid_confidence_floor: Option<f64>) -> Self {
        Self {
            result,
            valid_confidence_floor,
            claimed_family: true,
        }
    }

    #[inline]
    pub(crate) const fn not_applicable() -> Self {
        Self {
            result: ChecksumResult::NotApplicable,
            valid_confidence_floor: None,
            claimed_family: false,
        }
    }

    #[inline]
    pub(crate) fn for_credential(credential: &str) -> Self {
        VALIDATOR_CATALOG.validate_any(credential)
    }

    #[inline]
    pub(crate) fn is_invalid(self) -> bool {
        matches!(self.result, ChecksumResult::Invalid)
    }

    #[inline]
    pub(crate) fn result(self) -> ChecksumResult {
        self.result
    }

    #[inline]
    pub(crate) fn valid_confidence_floor(self) -> Option<f64> {
        self.valid_confidence_floor
    }

    #[inline]
    pub(crate) fn claims_family(self) -> bool {
        self.claimed_family
    }

    #[inline]
    pub(crate) fn is_proven_valid(self) -> bool {
        matches!(self.result, ChecksumResult::Valid)
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
