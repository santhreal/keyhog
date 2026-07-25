//! Existing detector-owned exceptions to canonical non-secret shape gates.
//!
//! These predicates do not define new value shapes. They encode the narrow
//! cases where detector evidence permits a canonical-looking value to survive.
//! Dependencies flow one way to the canonical byte-shape owner.

use super::canonical::is_uniform_hex;

/// True for a complete, uniform-case pure-hex value of a canonical service-key
/// length (32 / 40 / 48 / 64). A service-anchored detector's regex required its
/// service-specific keyword to match, so a capture of this shape may be a real
/// key rather than a coincidental digest.
///
/// The exception only skips the bare-hex-digest and algorithmic-placeholder
/// arms. Every explicit decoy gate still runs. Digest-only widths 56/72/128 are
/// deliberately excluded because no service detector requests those key widths.
pub(crate) fn is_canonical_service_hex_key(credential: &str) -> bool {
    matches!(credential.len(), 32 | 40 | 48 | 64) && is_uniform_hex(credential)
}

#[cfg(test)]
#[path = "../../../tests/unit/suppression_shape_detector.rs"]
mod tests;
