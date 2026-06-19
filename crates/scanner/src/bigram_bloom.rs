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
pub(crate) struct BigramBloom {
    bits: Box<[u64; 1024]>,
    /// `true` once the table is so densely populated that `maybe_overlaps`
    /// would return `true` for essentially every real chunk - i.e. the
    /// prefilter has zero filtering value and only costs an O(L) pass. Set
    /// at build time (see [`Self::recompute_saturation`]) so the hot path
    /// can short-circuit without walking the chunk. Returning `true` is
    /// always sound: `maybe_overlaps` is allowed false positives (never
    /// false negatives), so a blanket `true` can never drop a real secret.
    saturated: bool,
}

/// When the set-bit fraction of the 65536-slot table reaches this share, the
/// bloom admits almost every real-world chunk (common ASCII bigrams like
/// `th`, `e `, `in` are present) and provides no useful rejection. At that
/// point the downstream AC/HS automaton - which is strictly more precise -
/// should run unconditionally rather than paying for a dead O(L) scalar pass.
/// 60% (39322 of 65536 slots) is deliberately conservative: a table this full
/// already lets through the overwhelming majority of source bytes.
const SATURATION_NUMERATOR: u32 = 3;
const SATURATION_DENOMINATOR: u32 = 5;
const TABLE_SLOTS: u32 = 65536;

impl Clone for BigramBloom {
    fn clone(&self) -> Self {
        Self {
            bits: Box::new(*self.bits),
            saturated: self.saturated,
        }
    }
}

impl BigramBloom {
    pub(crate) fn empty() -> Self {
        Self {
            bits: Box::new([0; 1024]),
            saturated: false,
        }
    }

    /// Insert every distinct bigram from `bytes` into this table.
    ///
    /// Refreshes the saturation flag so a table built directly through this
    /// public entry point (rather than [`Self::from_literal_prefixes`]) keeps
    /// `maybe_overlaps`'s short-circuit consistent with its bit population.
    pub(crate) fn insert_all(&mut self, bytes: &[u8]) {
        for window in bytes.windows(2) {
            self.insert(window[0], window[1]);
        }
        self.recompute_saturation();
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
    pub(crate) fn from_literal_prefixes(literals: &[String]) -> Self {
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
        bloom.recompute_saturation();
        bloom
    }

    /// Recompute the `saturated` flag from the current bit population. Cheap
    /// (one popcount pass, ~1024 `u64` words, paid once per scanner build) so
    /// the per-chunk `maybe_overlaps` hot path can branch on a precomputed
    /// bool instead of re-deriving density per call.
    fn recompute_saturation(&mut self) {
        // `popcount * DENOM >= SLOTS * NUMER`  avoids any float / division.
        self.saturated = self.popcount() as u64 * SATURATION_DENOMINATOR as u64
            >= TABLE_SLOTS as u64 * SATURATION_NUMERATOR as u64;
    }

    /// Returns `true` when the chunk contains AT LEAST ONE bigram present
    /// in `self`. Returns `false` when there is no overlap (skip the chunk).
    ///
    /// Two cheap escapes precede the scan:
    ///   * `chunk.len() < 2` - no bigram exists, so we cannot prove the chunk
    ///     is clean; conservatively admit it.
    ///   * `self.saturated` - the table is dense enough that this walk would
    ///     return `true` for essentially every real chunk. Skip the dead
    ///     O(L) pass and let the strictly-more-precise AC/HS automaton run.
    ///     Sound because admitting (`true`) never drops a real secret.
    ///
    /// Hot loop: four independent byte-pair probes per iteration. Each probe
    /// is a load + bit-test into the 8 KB L1-resident table; unrolling by 4
    /// breaks the per-window serial dependency the old `windows(2)` walk
    /// carried (each iteration depended on the prior comparison) so the four
    /// loads issue in parallel and retire at ~1 byte/cycle on Zen 4 /
    /// Apple M-series. This mirrors the 4-wide unroll the alphabet filter's
    /// AVX2 body uses; a true 64 KB SIMD gather offers no win because the
    /// table exceeds a single shuffle register.
    pub(crate) fn maybe_overlaps(&self, chunk: &[u8]) -> bool {
        if chunk.len() < 2 {
            return true;
        }
        if self.saturated {
            return true;
        }
        let bits = self.bits.as_ref();

        // Each window starts at byte index `i` and pairs `chunk[i]` with
        // `chunk[i+1]`, for `i` in `0..=chunk.len()-2`. We unroll the leading
        // window indices in groups of four, then mop up the tail.
        let last_start = chunk.len() - 2; // valid because len >= 2
        let probe = |i: usize| -> bool {
            // i <= last_start guarantees i + 1 is in bounds.
            let idx = bigram_slot(chunk[i], chunk[i + 1]);
            // idx is at most 0xFFFF; idx >> 6 is at most 1023, in bounds for
            // [u64; 1024]. The optimizer proves this and elides the check.
            bits[idx >> 6] & (1u64 << (idx & 63)) != 0
        };

        let mut i = 0usize;
        // Process four independent windows per step while a full group fits.
        while i + 4 <= last_start + 1 {
            // OR the four results so the loads are independent (no early
            // return inside the group); branch once per group of four.
            if probe(i) | probe(i + 1) | probe(i + 2) | probe(i + 3) {
                return true;
            }
            i += 4;
        }
        // Tail: remaining windows (fewer than four).
        while i <= last_start {
            if probe(i) {
                return true;
            }
            i += 1;
        }
        false
    }

    /// Population count - useful for diagnostics and the basis of the
    /// `saturated` short-circuit ([`Self::recompute_saturation`]): a near-full
    /// table makes `maybe_overlaps` always return true and the prefilter
    /// provides zero filtering value, so the hot path skips its O(L) walk.
    pub(crate) fn popcount(&self) -> u32 {
        self.bits.iter().map(|w| w.count_ones()).sum()
    }

    /// Whether the table is saturated enough that `maybe_overlaps`
    /// short-circuits to `true`. Exposed for diagnostics and tests.
    pub(crate) fn is_saturated(&self) -> bool {
        self.saturated
    }

    /// Test-only naive reference: "does any bigram of `chunk` have its bit
    /// set", with NO saturation short-circuit and NO unrolling. The unrolled,
    /// saturation-aware [`maybe_overlaps`](Self::maybe_overlaps) must agree
    /// with this on every non-saturated table. Exposed through
    /// `testing::BigramBloom` so the differential test in
    /// `tests/unit/bigram_bloom.rs` can compare against the private
    /// `bits`/`bigram_slot` internals.
    pub(crate) fn scalar_overlaps_reference(&self, chunk: &[u8]) -> bool {
        if chunk.len() < 2 {
            return true;
        }
        chunk.windows(2).any(|w| {
            let idx = bigram_slot(w[0], w[1]);
            self.bits[idx >> 6] & (1u64 << (idx & 63)) != 0
        })
    }

    /// Test-only constructor of a saturated table (enough full rows to cross
    /// the saturation threshold), so the external suite can exercise the
    /// short-circuit path without reaching the private `insert_row` /
    /// `recompute_saturation` mutators.
    pub(crate) fn saturated_for_test() -> Self {
        let mut bloom = Self::empty();
        // 158 full rows * 256 slots = 40448 set bits > the 3/5 threshold.
        for a in 0u16..158 {
            bloom.insert_row(a as u8);
        }
        bloom.recompute_saturation();
        bloom
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
