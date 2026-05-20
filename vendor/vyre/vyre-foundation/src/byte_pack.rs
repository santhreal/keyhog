//! Canonical LE byte-packing helpers.
//!
//! These two functions are shared across the vyre tree wherever a
//! Rust-side helper needs to hand bytes to a wgpu / naga / cuda input
//! buffer. Before this module existed there were at least five
//! parallel implementations:
//!
//! * `vyre_libs::matching::dispatch_io::pack_u32_slice`
//! * `vyre_libs::matching::dispatch_io::pack_haystack_u32`
//! * `vyre_primitives::matching::bracket_match::pack_u32`
//! * `vyre_primitives::text::char_class::pack_u32`
//! * `vyre_cc::pipeline::buffers::pack_haystack`
//! * `vyre_frontend_c::pipeline::buffers::fast_pack_u32_le`
//!
//! With a documented perf regression: vyre-cc and one
//! vyre-primitives variant still used the iterator
//! `flat_map(...).collect()` form, while vyre-frontend-c had migrated
//! to a pre-allocated `extend_from_slice` loop *with a comment*
//! explaining the previous form blew up on million-element token
//! streams. Centralising here gets every consumer onto the fast path
//! and keeps the wire-format contract in one place.
//!
//! Both helpers stay in `vyre-foundation` (not `vyre-libs`) because
//! every downstream crate already depends on foundation and
//! `vyre-primitives` lives a layer below `vyre-libs` — neither could
//! import from libs.

/// Pack a `&[u32]` slice into a little-endian byte stream suitable
/// for upload to a `BufferDecl::storage(.., DataType::U32, ..)`
/// input. Pre-allocates the exact output capacity and uses
/// `extend_from_slice` of `to_le_bytes()` to keep per-word cost flat
/// (no growth-on-push, no iterator overhead).
#[must_use]
pub fn pack_u32_slice_le(words: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len().saturating_mul(4));
    for word in words {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out
}

/// Pack a `&[u8]` haystack into the standard 4-bytes-per-u32 layout
/// every byte-scan matcher in `vyre-libs::matching` expects. Each
/// group of 4 input bytes becomes one little-endian `u32`; a trailing
/// group with fewer than 4 bytes is zero-padded into the high lanes.
///
/// Equivalent to the historical
/// `vyre_libs::matching::dispatch_io::pack_haystack_u32` — preserved
/// here so consumers below `vyre-libs` (e.g. `vyre-primitives` self
/// tests, conform harness fixtures) can share the wire format
/// without taking a dep on `matching/`.
#[must_use]
pub fn pack_haystack_u32(haystack: &[u8]) -> Vec<u8> {
    let mut packed: Vec<u32> = Vec::with_capacity(haystack.len().div_ceil(4));
    for chunk in haystack.chunks(4) {
        let mut word = 0u32;
        for (i, &b) in chunk.iter().enumerate() {
            word |= (b as u32) << (i * 8);
        }
        packed.push(word);
    }
    pack_u32_slice_le(&packed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_u32_slice_matches_documented_layout() {
        let words = [0x04030201u32, 0x08070605u32];
        let bytes = pack_u32_slice_le(&words);
        assert_eq!(bytes, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn pack_haystack_unaligned_zero_pads_high_lanes() {
        let bytes = b"abc";
        let packed = pack_haystack_u32(bytes);
        // Single LE word: "abc\0" -> 0x00636261
        assert_eq!(packed, vec![0x61, 0x62, 0x63, 0x00]);
    }

    #[test]
    fn pack_haystack_aligned_packs_into_4_byte_words() {
        let bytes = b"abcdefgh";
        let packed = pack_haystack_u32(bytes);
        assert_eq!(packed, vec![0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68]);
    }

    #[test]
    fn pack_haystack_empty_is_empty() {
        assert!(pack_haystack_u32(&[]).is_empty());
    }
}
