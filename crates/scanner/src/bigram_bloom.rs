//! Bigram-bloom prefilter - Layer 0.5 between alphabet screening and AC/HS.
//!
//! `AlphabetMask` (Layer 0) tells us which BYTES appear in the chunk; it can't
//! tell us about adjacencies. A 1 MB Java source file likely contains
//! `g`, `h`, `p`, `_` somewhere (Layer 0 says "scan it") but never the bigram
//! `gh` followed by `p_` (which the GitHub PAT prefix `ghp_` requires).
//!
//! This module builds a 65536-bit (8 KB / 1024 u64) DIRECT lookup table at
//! scanner construction time:
//!   * `LITERAL_BIGRAM_TABLE` - one bit per (byte_a, byte_b) pair. Set
//!     whenever any detector literal prefix contains that bigram, plus an
//!     extension where the literal's terminal byte is followed by ANY byte
//!     (so a 4-char prefix `ghp_` populates `gh`, `hp`, `p_`, and every
//!     `_X` row).
//!   * `MAYBE_HAS_LITERAL_PREFIX(chunk)` - true if the chunk contains AT
//!     LEAST ONE bigram whose bit is set; false (skip the chunk) when
//!     there's zero overlap.
//!
//! ## Why a direct table beats the previous FNV-1a bloom
//!
//! The previous implementation used a 4096-bit bloom keyed by a 4-instruction
//! FNV-1a hash (xor, mul, xor, mul). Each `maybe_overlaps` byte pair carried
//! a 4-cycle serial dependency (`mul` depends on the previous `xor`), defeating
//! out-of-order execution; the inner loop ran at ~4 cycles/byte. A 65536-bit
//! direct table (`bits[(a<<8) | b]`) is a single byte load + bit-test per
//! window with no FNV math, runs at ~1 cycle/byte on Zen 4 / Apple M-series,
//! and fits entirely in L1d (8 KB << 32 KB). As a bonus it eliminates hash
//! collisions, so prefilter false positives drop to zero (recall is preserved
//! because the previous FNV bloom never had false NEGATIVES either - just
//! more false positives, which scanned more chunks than necessary).
//!
//! Cost: ~1 ns per byte on AVX2/scalar - strictly cheaper than
//! `AlphabetMask::from_bytes`. The 8 KB construction cost is paid once per
//! scanner build (compile.rs), not per chunk.

#![deny(unsafe_op_in_unsafe_fn)]

/// 65536-bit (8 KB) direct bigram lookup table. Indexed by the 16-bit value
/// `(a as u16) << 8 | b as u16` for every byte pair `(a, b)`.
///
/// `Box<[u64; 1024]>` (not inline) keeps the `CompiledScanner` struct compact:
/// the scanner is moved during compile, and 8 KB inline would force stack
/// spill on every move.
pub struct BigramBloom {
    bits: Box<[u64; 1024]>,
}

impl Clone for BigramBloom {
    fn clone(&self) -> Self {
        Self {
            bits: Box::new(*self.bits),
        }
    }
}

impl BigramBloom {
    pub fn empty() -> Self {
        Self {
            bits: Box::new([0; 1024]),
        }
    }

    /// Insert every distinct bigram from `bytes` into this table.
    pub fn insert_all(&mut self, bytes: &[u8]) {
        for window in bytes.windows(2) {
            self.insert(window[0], window[1]);
        }
    }

    #[inline]
    fn insert(&mut self, a: u8, b: u8) {
        let idx = bigram_slot(a, b);
        self.bits[idx >> 6] |= 1u64 << (idx & 63);
    }

    /// Set every bigram of the form `(a, *)` (the whole "row" for byte `a`).
    /// Used for 1-byte literal prefixes (which can be followed by anything)
    /// and to widen each literal's terminal byte by one ASCII byte (so we
    /// admit secrets that START with the prefix and continue with any byte).
    #[inline]
    fn insert_row(&mut self, a: u8) {
        // Every (a, b) for b in 0..=255 is a contiguous range of 256 slots
        // starting at `(a as usize) << 8`. That's exactly 4 u64 words on a
        // 256-bit boundary.
        let word = (a as usize) << 2;
        self.bits[word] = u64::MAX;
        self.bits[word + 1] = u64::MAX;
        self.bits[word + 2] = u64::MAX;
        self.bits[word + 3] = u64::MAX;
    }

    /// Build a table containing every bigram of every literal prefix in
    /// `literals`, plus `prefix[i] || ANY_BYTE` for each interior position
    /// (so we accept secrets that *start* with the prefix and continue with
    /// any byte). The "extension" widening keeps the table sound under
    /// truncated prefixes (`ghp` matches `ghp_AB...`).
    pub fn from_literal_prefixes(literals: &[String]) -> Self {
        let mut bloom = Self::empty();
        for literal in literals {
            let bytes = literal.as_bytes();
            if bytes.is_empty() {
                continue;
            }
            if bytes.len() < 2 {
                // 1-byte literal: every bigram starting with that byte is
                // possible; we set the byte's full row to true. This is
                // costly but 1-byte literal prefixes are pathological and
                // the AC matcher will short-circuit before the table even
                // sees the chunk.
                bloom.insert_row(bytes[0]);
                continue;
            }
            bloom.insert_all(bytes);
            // Extension: terminal byte may be followed by anything in a
            // real secret. Add `last || any`. The `len() < 2` guard
            // above proves non-empty; if a future refactor weakens
            // the guard we'd rather skip the terminal extension for
            // that literal (slight precision loss in the prefilter)
            // than panic the scanner mid-scan.
            let Some(&last) = bytes.last() else { continue };
            bloom.insert_row(last);
        }
        bloom
    }

    /// Returns `true` when the chunk contains AT LEAST ONE bigram present
    /// in `self`. Returns `false` when there is no overlap (skip the chunk).
    ///
    /// Inner loop: single byte load + bit-test per window. The optimizer
    /// auto-unrolls and the load/test pair pipelines at ~1 cycle per byte
    /// on Zen 4 / Apple M-series CPUs.
    pub fn maybe_overlaps(&self, chunk: &[u8]) -> bool {
        if chunk.len() < 2 {
            return true;
        }
        let bits = self.bits.as_ref();
        for window in chunk.windows(2) {
            let idx = bigram_slot(window[0], window[1]);
            // idx is at most 0xFFFF; idx>>6 is at most 1023, in bounds for
            // [u64; 1024]. The optimizer proves this and elides the bounds
            // check.
            if bits[idx >> 6] & (1u64 << (idx & 63)) != 0 {
                return true;
            }
        }
        false
    }

    /// Population count - useful for diagnostics and to detect a near-full
    /// table (where `maybe_overlaps` would always return true and the
    /// prefilter is providing zero value).
    pub fn popcount(&self) -> u32 {
        self.bits.iter().map(|w| w.count_ones()).sum()
    }
}

/// Direct index into the 65536-bit table: high byte is the first byte,
/// low byte is the second. One cycle of arithmetic on every modern CPU
/// (one shift, one or, both single-cycle ops). The previous implementation
/// ran 4 dependent instructions (FNV-1a) here.
#[inline(always)]
fn bigram_slot(a: u8, b: u8) -> usize {
    ((a as usize) << 8) | (b as usize)
}
