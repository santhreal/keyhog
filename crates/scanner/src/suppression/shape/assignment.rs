//! Assignment-path roles for canonical value shapes.
//!
//! This module decides how the entropy and generic assignment paths interpret
//! canonical shapes. The byte-level predicates remain in [`super::canonical`];
//! dependencies flow from this policy layer to that value-shape owner only.

/// Entropy's UUID assignment role is an alias of the canonical predicate, not
/// a second predicate that can drift.
pub(crate) use super::canonical::is_uuid_v4_shape as looks_like_entropy_uuid_shape;
use super::canonical::{
    is_canonical_hex_digest_length, is_five_by_five_dash_shape, HASH_ALGO_INTEGRITY_LABELS,
};

/// Shannon-entropy (bits/char) threshold separating high-entropy base64 blobs
/// from lower-entropy generic candidates. Single source of truth shared by the
/// two generic-base64 assignment roles and report-time high-entropy carve-outs.
pub(crate) const HIGH_ENTROPY_BASE64_CUTOFF: f64 = 4.8;

/// Canonical non-secret shapes rejected at entropy candidate generation.
///
/// This intentionally preserves the historical entropy semantics instead of
/// reusing broader report-time suppression helpers. Entropy generation treats
/// exact UUID, 32/40/64/128 pure-hex, npm SRI, and uppercase 5x5 license serial
/// shapes as canonical non-secrets.
pub(crate) fn looks_like_entropy_canonical_non_secret_shape(value: &str) -> bool {
    looks_like_entropy_uuid_shape(value)
        || looks_like_entropy_canonical_hex_digest(value)
        || looks_like_entropy_integrity_digest(value)
        || looks_like_entropy_upper_license_serial(value)
}

/// Entropy's exact canonical-digest assignment role.
pub(crate) fn looks_like_entropy_canonical_hex_digest(value: &str) -> bool {
    is_canonical_hex_digest_length(value.len()) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn looks_like_entropy_integrity_digest(value: &str) -> bool {
    HASH_ALGO_INTEGRITY_LABELS.iter().any(|prefix| {
        value.strip_prefix(prefix.as_str()).is_some_and(|body| {
            !body.is_empty() && crate::decode::standard_base64_shape(body).is_some()
        })
    })
}

fn looks_like_entropy_upper_license_serial(value: &str) -> bool {
    is_five_by_five_dash_shape(value, |b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

#[cfg(feature = "entropy")]
pub(crate) fn looks_like_entropy_random_base64_blob_decoy(value: &str) -> bool {
    crate::decode_structure::is_byte_distribution_base64_blob(value, 50, 300)
}

pub(crate) fn looks_like_generic_random_base64_blob_decoy(value: &str, entropy: f64) -> bool {
    if entropy >= HIGH_ENTROPY_BASE64_CUTOFF {
        return false;
    }
    crate::decode_structure::is_byte_distribution_base64_blob(value, 40, 300)
}

pub(crate) fn generic_base64_candidate_is_ambiguous(value: &str, entropy: f64) -> bool {
    const MIN_DISTINCT_ALNUM: u32 = 32;

    if entropy < HIGH_ENTROPY_BASE64_CUTOFF {
        return false;
    }
    let Some(shape) = crate::decode::standard_base64_shape(value) else {
        return false;
    };
    shape.distinct_alnum >= MIN_DISTINCT_ALNUM
}

#[cfg(test)]
#[path = "../../../tests/unit/suppression_shape_assignment.rs"]
mod tests;
