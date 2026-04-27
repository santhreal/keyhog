//! Cat-A hash / checksum compositions.
//!
//! Consolidates `vyre-libs::crypto` (fnv1a32, blake3_compress) with
//! the migrated-from-vyre-ops ops (fnv1a64, crc32, adler32) per
//! `docs/migration-vyre-ops-to-intrinsics.md`. Each op is a pure
//! serial composition over existing IR primitives (XOR + multiply +
//! shift); no dedicated Naga emitter arm required.
//!
//! Migration 3 continues to move the existing crypto submodules into
//! this tree; until that lands, both `vyre-libs::hash` and
//! `vyre-libs::crypto` coexist. After Migration 3, `crypto` becomes a
//! deprecation re-export shim for one release, then dissolves.

pub mod adler32;
pub mod blake3_compress;
pub mod crc32;
pub mod fnv1a32;
pub mod fnv1a64;
pub mod multi_hash;

pub use adler32::adler32;
pub use blake3_compress::blake3_compress;
pub use crc32::crc32;
pub use fnv1a32::fnv1a32;
pub use fnv1a64::fnv1a64;
pub use multi_hash::multi_hash;

#[cfg(test)]
pub(crate) fn pack_bytes_as_u32(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 4);
    for &b in bytes {
        out.extend_from_slice(&u32::from(b).to_le_bytes());
    }
    out
}
