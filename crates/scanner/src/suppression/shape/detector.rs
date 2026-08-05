//! Existing detector-owned exceptions to canonical non-secret shape gates.
//!
//! These predicates do not define new value shapes. They encode the narrow
//! cases where detector evidence permits a canonical-looking value to survive.
//! Dependencies flow one way to the canonical byte-shape owner.

use super::canonical::is_uniform_hex;

/// True for a complete, uniform-case pure-hex value of a canonical service-key
/// length. A service-anchored detector's regex required its service-specific
/// keyword to match, so a capture of this shape may be a real key rather than a
/// coincidental digest.
///
/// The widths are Tier-B data (`rules/hex-digest-policy.toml`
/// `service_key_lengths`), validated as a subset of the bare-digest widths.
/// The digest-only widths are deliberately excluded because no service detector
/// requests those key widths.
///
/// The exception only skips the bare-hex-digest and algorithmic-placeholder
/// arms. Every explicit decoy gate still runs.
pub(crate) fn is_canonical_service_hex_key(credential: &str) -> bool {
    crate::hex_digest_policy::is_service_key_length(credential.len()) && is_uniform_hex(credential)
}

#[cfg(test)]
#[path = "../../../tests/unit/suppression_shape_detector.rs"]
mod tests;
