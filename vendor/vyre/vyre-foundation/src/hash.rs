//! Canonical hash helpers used across the vyre tree.
//!
//! Before this module existed there were at least three parallel
//! FNV-1a 32-bit implementations:
//!
//! * `vyre_foundation::transform::compiler::string_interner::fnv1a32`
//!   (bytes; the historical canonical site, still re-exported here)
//! * `vyre_cc::pipeline::buffers::fnv1a32_words` (u32 words)
//! * `vyre_frontend_c::pipeline::buffers::fnv1a32_packed_u32_bytes`
//!   (bytes; literal copy of foundation's `fnv1a32`)
//!
//! All three computed the same 32-bit value with identical constants;
//! the only difference was input shape. This module collapses them
//! to two functions — `fnv1a32(&[u8])` and `fnv1a32_words(&[u32])` —
//! and keeps every existing import path working via back-compat shims
//! at the original call sites.

/// FNV-1a 32-bit hash of a byte slice. Standard offset and prime
/// constants from <http://www.isthe.com/chongo/tech/comp/fnv/>.
#[must_use]
pub fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for &byte in bytes {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// FNV-1a 32-bit hash of a `[u32]` slice, treating each word as four
/// little-endian bytes. Equivalent to
/// `fnv1a32(&bytemuck::cast_slice(words))` but allocation-free and
/// independent of the `bytemuck` crate. Matches the per-byte iteration
/// order used by C-frontend pipelines (vyre-cc, vyre-frontend-c) so
/// the canonical implementation produces byte-identical hashes vs.
/// the legacy clones.
#[must_use]
pub fn fnv1a32_words(words: &[u32]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for word in words {
        for byte in word.to_le_bytes() {
            hash ^= u32::from(byte);
            hash = hash.wrapping_mul(0x0100_0193);
        }
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a32_known_inputs() {
        assert_eq!(fnv1a32(b""), 0x811c_9dc5);
        // FNV-1a 32-bit of "foobar"
        assert_eq!(fnv1a32(b"foobar"), 0xbf9c_f968);
    }

    #[test]
    fn fnv1a32_words_matches_bytes_via_le_concat() {
        let words = [0x0403_0201u32, 0x0807_0605u32];
        let bytes: Vec<u8> = words
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        assert_eq!(fnv1a32_words(&words), fnv1a32(&bytes));
    }

    #[test]
    fn fnv1a32_words_empty() {
        assert_eq!(fnv1a32_words(&[]), 0x811c_9dc5);
    }
}
