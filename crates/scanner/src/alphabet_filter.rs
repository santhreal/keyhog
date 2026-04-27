//! Alphabet-based bitmask pre-filtering for ultra-fast chunk skipping.
//!
//! This provides a "Layer 0" screen that can discard non-matching chunks
//! in O(N) with very low constant factors using bit-parallelism.

#![deny(unsafe_op_in_unsafe_fn)]

/// A 256-bit mask representing the presence of all ASCII characters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AlphabetMask {
    mask: [u64; 4],
}

impl AlphabetMask {
    /// Create a mask from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx2") {
                // SAFETY: We just checked for AVX2 support.
                return unsafe { Self::from_bytes_avx2(bytes) };
            }
            if is_x86_feature_detected!("sse2") {
                // SAFETY: SSE2 is a baseline for x86_64 but we gate it for clarity.
                return unsafe { Self::from_bytes_sse2(bytes) };
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: ARM NEON is always available on aarch64.
            return unsafe { Self::from_bytes_neon(bytes) };
        }

        Self::from_bytes_scalar(bytes)
    }

    pub fn from_bytes_scalar(bytes: &[u8]) -> Self {
        let mut mask = [0u64; 4];
        for &b in bytes {
            mask[(b / 64) as usize] |= 1 << (b % 64);
        }
        Self { mask }
    }

    #[cfg(target_arch = "aarch64")]
    unsafe fn from_bytes_neon(bytes: &[u8]) -> Self {
        let mut mask = [0u64; 4];
        let chunks = bytes.chunks_exact(16);
        let remainder = chunks.remainder();

        for chunk in chunks {
            for &b in chunk {
                mask[(b / 64) as usize] |= 1 << (b % 64);
            }
        }

        for &b in remainder {
            mask[(b / 64) as usize] |= 1 << (b % 64);
        }

        Self { mask }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn from_bytes_avx2(bytes: &[u8]) -> Self {
        let mut mask = [0u64; 4];

        let chunks = bytes.chunks_exact(4);
        let remainder = chunks.remainder();

        for chunk in chunks {
            mask[(chunk[0] / 64) as usize] |= 1 << (chunk[0] % 64);
            mask[(chunk[1] / 64) as usize] |= 1 << (chunk[1] % 64);
            mask[(chunk[2] / 64) as usize] |= 1 << (chunk[2] % 64);
            mask[(chunk[3] / 64) as usize] |= 1 << (chunk[3] % 64);
        }

        for &b in remainder {
            mask[(b / 64) as usize] |= 1 << (b % 64);
        }

        Self { mask }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse2")]
    unsafe fn from_bytes_sse2(bytes: &[u8]) -> Self {
        let mut mask = [0u64; 4];
        for &b in bytes {
            mask[(b / 64) as usize] |= 1 << (b % 64);
        }
        Self { mask }
    }

    /// Create a mask from a string.
    pub fn from_text(s: &str) -> Self {
        Self::from_bytes(s.as_bytes())
    }

    /// Check if two masks have any common bits set.
    pub fn intersects(&self, other: &Self) -> bool {
        (self.mask[0] & other.mask[0]) != 0
            || (self.mask[1] & other.mask[1]) != 0
            || (self.mask[2] & other.mask[2]) != 0
            || (self.mask[3] & other.mask[3]) != 0
    }

    /// Union two masks together.
    pub fn union(&mut self, other: &Self) {
        self.mask[0] |= other.mask[0];
        self.mask[1] |= other.mask[1];
        self.mask[2] |= other.mask[2];
        self.mask[3] |= other.mask[3];
    }
}

/// A pre-filter that uses an [`AlphabetMask`] to quickly skip chunks.
#[derive(Clone, Debug, Default)]
pub struct AlphabetScreen {
    target_mask: AlphabetMask,
}

impl AlphabetScreen {
    /// Create a new screen from a set of target strings (literals or keywords).
    pub fn new(targets: &[String]) -> Self {
        let mut target_mask = AlphabetMask::default();
        for target in targets {
            target_mask.union(&AlphabetMask::from_text(target));
            // Ensure case-insensitivity for the pre-screen
            target_mask.union(&AlphabetMask::from_text(&target.to_lowercase()));
            target_mask.union(&AlphabetMask::from_text(&target.to_uppercase()));
        }
        Self { target_mask }
    }

    /// Quick screen of a data chunk.
    pub fn screen(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }

        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx2") {
                // SAFETY: We just checked for AVX2 support.
                return unsafe { self.screen_avx2(data) };
            }
        }

        // Fallback to building the mask and intersecting.
        // This is actually faster than a simple scalar search for 1MB no-match.
        self.target_mask.intersects(&AlphabetMask::from_bytes(data))
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn screen_avx2(&self, data: &[u8]) -> bool {
        use std::arch::x86_64::*;

        // SAFETY: `target_mask.mask` is `[u64; 4]` (32 bytes total). Slicing
        // `[..2]` gives 16 bytes / `[2..]` gives 16 bytes — exactly what
        // `_mm_loadu_si128` needs. Loadu permits unaligned pointers.
        // AVX2 availability is enforced by the surrounding
        // `#[target_feature(enable = "avx2")]`. kimi-wave1 finding 6.LOW.alphabet_filter.rs.162.
        let (bitset_low, bitset_high, bit_selector) = unsafe {
            let low_mask = _mm_loadu_si128(self.target_mask.mask[..2].as_ptr() as *const __m128i);
            let high_mask = _mm_loadu_si128(self.target_mask.mask[2..].as_ptr() as *const __m128i);

            (
                _mm256_set_m128i(low_mask, low_mask),
                _mm256_set_m128i(high_mask, high_mask),
                _mm256_setr_epi8(
                    1, 2, 4, 8, 16, 32, 64, -128, 1, 2, 4, 8, 16, 32, 64, -128, 1, 2, 4, 8, 16, 32,
                    64, -128, 1, 2, 4, 8, 16, 32, 64, -128,
                ),
            )
        };

        let chunks = data.chunks_exact(32);
        let remainder = chunks.remainder();

        for chunk in chunks {
            // SAFETY: `chunks_exact(32)` guarantees chunk.len() == 32, so
            // `chunk.as_ptr()` is valid for a 32-byte AVX2 unaligned load.
            // Subsequent intrinsics are pure register ops; AVX2 availability
            // is enforced by the surrounding `#[target_feature(enable =
            // "avx2")]`. kimi-wave1 finding 6.LOW.alphabet_filter.rs.180.
            unsafe {
                let v = _mm256_loadu_si256(chunk.as_ptr() as *const __m256i);

                // bit_index = v & 7
                let bit_indices = _mm256_and_si256(v, _mm256_set1_epi8(0x07));
                let bits = _mm256_shuffle_epi8(bit_selector, bit_indices);

                // byte_index = (v >> 3) & 0x0F
                let byte_indices =
                    _mm256_and_si256(_mm256_srli_epi16(v, 3), _mm256_set1_epi8(0x0F));

                let is_128_255 = _mm256_cmpgt_epi8(_mm256_setzero_si256(), v); // Bit 7 set

                let row_low = _mm256_shuffle_epi8(bitset_low, byte_indices);
                let row_high = _mm256_shuffle_epi8(bitset_high, byte_indices);

                let row = _mm256_blendv_epi8(row_low, row_high, is_128_255);

                if _mm256_testz_si256(row, bits) == 0 {
                    return true;
                }
            }
        }

        for &b in remainder {
            if (self.target_mask.mask[(b / 64) as usize] & (1 << (b % 64))) != 0 {
                return true;
            }
        }

        false
    }
}
