//! Tier 2.5 hash primitives.
//!
//! The path IS the interface. Callers write
//! `vyre_primitives::hash::fnv1a::fnv1a32(...)` — explicit paths;
//! no wildcard re-exports. See `docs/primitives-tier.md` and
//! `docs/lego-block-rule.md`.

/// FNV-1a 32-bit + 64-bit hash primitives.
pub mod fnv1a;

/// Shared BLAKE3 mix/round helpers.
pub mod blake3;

/// CRC-32 (IEEE 802.3 polynomial 0xEDB88320) hash primitive.
pub mod crc32;

/// Hash table primitives.
pub mod table;
