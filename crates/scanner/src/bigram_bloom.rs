//! Selective literal-anchor prefilter (the public diagnostic name remains
//! "bigram Bloom" for compatibility).
//!
//! The original Layer-0.5 table inserted every bigram from every detector
//! literal and widened each terminal byte to a full row. The production table
//! was only 28.13% populated, but ordinary source lines still overlapped it
//! almost universally: density was truthful while rejection was zero.
//!
//! Construction now chooses one mandatory anchor for every direct-matcher
//! literal alternative. Alternatives shorter than eight bytes use one exact
//! ASCII-case-insensitive automaton; longer alternatives select the least-common
//! eight-byte window measured by a bounded deterministic frequency sketch, with
//! deterministic byte and position tie-breaking. Every complete alternative
//! therefore contains its selected anchor. Empty/unextractable alternatives
//! invalidate this gate and fail open.
//!
//! The 65,536-bit table stores two independent stable hashes of each selected
//! eight-byte anchor. A query requires both bits. Hash collisions can only
//! admit extra chunks; they cannot reject a real candidate.
//! Prefixless and dynamic regexes are not trained into this table. They remain
//! in the scanner's explicit phase-2 always-admit/no-hit lane, which is evaluated
//! even when this direct-literal gate rejects a chunk.
//!
//! Keeping the existing 8 KB table and diagnostic surface preserves operator
//! compatibility while replacing an overbroad two-byte representation with a
//! selective, proof-carrying one.

#![deny(unsafe_op_in_unsafe_fn)]

/// Scanner-owned selective anchor gate: one exact short-literal automaton plus
/// a 65,536-bit (8 KB) double-hash table for selected eight-byte anchors.
///
/// `Box<[u64; 1024]>` (not inline) keeps the `CompiledScanner` struct compact:
/// the scanner is moved during compile, and 8 KB inline would force stack
/// spill on every move.
pub(crate) struct BigramBloom {
    bits: Box<[u64; 1024]>,
    /// Exact owner for mandatory literal alternatives shorter than eight bytes.
    short_anchors: Option<aho_corasick::AhoCorasick>,
    /// Bit `n - 1` is set when hashed anchors of byte width `n` exist.
    width_mask: u8,
    minimum_anchor_bytes: u8,
    /// Cached build-time state. Saturated and invalid states fail open.
    state: BigramPrefilterState,
}

/// Operator-visible health state for the Layer-0.5 selective anchor prefilter.
///
/// `Saturated` and `Invalid` are deliberately fail-open states: production
/// scanning bypasses the prefilter and retains full downstream matcher recall.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BigramPrefilterState {
    Healthy,
    Saturated,
    Invalid,
}

/// Build-time hash-table density diagnostics for the Layer-0.5 prefilter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BigramPrefilterStatus {
    pub populated_slots: u32,
    pub total_slots: u32,
    pub saturation_threshold_slots: u32,
    pub density_basis_points: u16,
    pub state: BigramPrefilterState,
}

/// Rejection effectiveness measured over one explicitly named input corpus.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BigramPrefilterCorpusStatus<'a> {
    pub corpus_name: &'a str,
    pub input_count: u64,
    /// Inputs large enough for the production bloom gate to run.
    pub eligible_inputs: u64,
    pub rejected_inputs: u64,
    /// Rejected share in basis points (10_000 = 100.00%).
    pub rejection_basis_points: u16,
}

/// When the set-bit fraction of the 65,536-slot hash table reaches this share,
/// collision admissions make the hashed owner ineffective. At that point the
/// downstream AC/HS automaton should run unconditionally rather than paying for
/// a dead prefilter pass. The exact short-anchor owner does not alter the table
/// population. 60% (39,322 slots) retains conservative saturation headroom.
const SATURATION_NUMERATOR: u32 = 3;
const SATURATION_DENOMINATOR: u32 = 5;
const TABLE_SLOTS: u32 = 65_536;
const SATURATION_THRESHOLD_SLOTS: u32 =
    (TABLE_SLOTS * SATURATION_NUMERATOR + SATURATION_DENOMINATOR - 1) / SATURATION_DENOMINATOR;

const MAX_ANCHOR_BYTES: usize = 8;
const FREQUENCY_SLOTS: usize = TABLE_SLOTS as usize;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct AnchorKey {
    bytes: [u8; MAX_ANCHOR_BYTES],
    len: u8,
}

impl AnchorKey {
    fn from_slice(bytes: &[u8]) -> Self {
        debug_assert!(!bytes.is_empty() && bytes.len() <= MAX_ANCHOR_BYTES);
        let mut key = Self {
            bytes: [0; MAX_ANCHOR_BYTES],
            len: bytes.len() as u8,
        };
        key.bytes[..bytes.len()].copy_from_slice(bytes);
        for byte in &mut key.bytes[..bytes.len()] {
            *byte = byte.to_ascii_lowercase();
        }
        key
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl Clone for BigramBloom {
    fn clone(&self) -> Self {
        Self {
            bits: Box::new(*self.bits),
            short_anchors: self.short_anchors.clone(),
            width_mask: self.width_mask,
            minimum_anchor_bytes: self.minimum_anchor_bytes,
            state: self.state,
        }
    }
}

impl BigramBloom {
    pub(crate) fn empty() -> Self {
        Self {
            bits: Box::new([0; 1024]),
            short_anchors: None,
            width_mask: width_bit(2),
            minimum_anchor_bytes: 2,
            state: BigramPrefilterState::Healthy,
        }
    }

    fn blank() -> Self {
        Self {
            bits: Box::new([0; 1024]),
            short_anchors: None,
            width_mask: 0,
            minimum_anchor_bytes: 0,
            state: BigramPrefilterState::Healthy,
        }
    }

    #[inline]
    fn insert_anchor(&mut self, anchor: &[u8]) {
        for slot in ngram_slots(anchor) {
            self.bits[slot >> 6] |= 1u64 << (slot & 63);
        }
    }

    fn insert_folded_anchor(&mut self, anchor: AnchorKey) {
        self.insert_anchor(anchor.as_slice());
    }

    /// Build one mandatory anchor for every literal alternative.
    ///
    /// A fixed two-probe saturating frequency sketch ranks long-anchor
    /// candidates without retaining one hash-table row per corpus window.
    /// Collisions only choose a less selective mandatory window; they cannot
    /// reject a literal-bearing chunk. Short alternatives use exact matching.
    /// An empty
    /// alternative cannot provide a rejection proof, so construction marks the
    /// filter invalid and every query fails open.
    pub(crate) fn from_literal_prefixes(literals: &[String]) -> Self {
        if literals.is_empty() || literals.iter().any(String::is_empty) {
            return Self::invalid_for_test();
        }

        let mut frequencies = Box::new([0u16; FREQUENCY_SLOTS]);
        let mut short_literals = Vec::<&[u8]>::new();
        for literal in literals {
            let bytes = literal.as_bytes();
            if bytes.len() < MAX_ANCHOR_BYTES {
                short_literals.push(bytes);
                continue;
            }
            for window in bytes.windows(MAX_ANCHOR_BYTES) {
                let key = AnchorKey::from_slice(window);
                let [first, second] = ngram_slots(key.as_slice());
                frequencies[first] = frequencies[first].saturating_add(1);
                if second != first {
                    frequencies[second] = frequencies[second].saturating_add(1);
                }
            }
        }

        let mut bloom = Self::blank();
        let Some(minimum_literal_bytes) = literals.iter().map(|literal| literal.len()).min() else {
            return Self::invalid_for_test();
        };
        bloom.minimum_anchor_bytes = minimum_literal_bytes.min(MAX_ANCHOR_BYTES) as u8;
        if !short_literals.is_empty() {
            bloom.short_anchors = match aho_corasick::AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(short_literals)
            {
                Ok(anchors) => Some(anchors),
                Err(error) => {
                    tracing::error!(%error, "selective short-anchor automaton build failed; filter is invalid and fail-open");
                    return Self::invalid_for_test();
                }
            };
        }
        for literal in literals {
            let bytes = literal.as_bytes();
            if bytes.len() < MAX_ANCHOR_BYTES {
                continue;
            }
            let mut selected = None;
            for (position, window) in bytes.windows(MAX_ANCHOR_BYTES).enumerate() {
                let key = AnchorKey::from_slice(window);
                let [first, second] = ngram_slots(key.as_slice());
                let frequency = frequencies[first].min(frequencies[second]);
                let candidate = (frequency, key, position);
                if selected.is_none_or(|current| candidate < current) {
                    selected = Some(candidate);
                }
            }
            let Some((_, selected, _)) = selected else {
                return Self::invalid_for_test();
            };
            bloom.width_mask |= width_bit(MAX_ANCHOR_BYTES);
            bloom.insert_folded_anchor(selected);
        }
        bloom.recompute_saturation();
        bloom
    }

    fn recompute_saturation(&mut self) {
        self.state = classify_population(self.popcount(), TABLE_SLOTS);
    }

    /// Return whether a selected mandatory anchor may occur in `chunk`.
    ///
    /// Saturated/invalid states and chunks shorter than the shortest compiled
    /// anchor fail open. A healthy miss proves that none of the direct matcher
    /// literal alternatives can occur. Prefixless/dynamic phase-2 alternatives
    /// are owned by the scanner's separate always-admit lane.
    pub(crate) fn maybe_overlaps(&self, chunk: &[u8]) -> bool {
        if self.state != BigramPrefilterState::Healthy {
            return true;
        }
        if chunk.len() < usize::from(self.minimum_anchor_bytes) {
            return true;
        }
        if self
            .short_anchors
            .as_ref()
            .is_some_and(|anchors| anchors.is_match(chunk))
        {
            return true;
        }
        if self.width_mask == 0 {
            return false;
        }
        // Reject path walks every 8-byte window. one_long_line / many_small pay
        // this per filesystem window; keep the probe allocation-free and avoid
        // per-window scratch copies on the ASCII-dominated hot path.
        self.any_long_anchor(chunk)
    }

    #[inline]
    fn any_long_anchor(&self, chunk: &[u8]) -> bool {
        if chunk.len() < MAX_ANCHOR_BYTES {
            return false;
        }
        let bits = self.bits.as_ref();
        let last = chunk.len() - MAX_ANCHOR_BYTES;
        let mut i = 0usize;
        while i <= last {
            if contains_anchor_ascii8(bits, &chunk[i..i + MAX_ANCHOR_BYTES]) {
                return true;
            }
            i += 1;
        }
        false
    }


    pub(crate) fn popcount(&self) -> u32 {
        self.bits.iter().map(|word| word.count_ones()).sum()
    }

    pub(crate) fn status(&self) -> BigramPrefilterStatus {
        let populated_slots = self.popcount();
        let derived_state = classify_population(populated_slots, TABLE_SLOTS);
        let has_anchor_owner = self.width_mask != 0 || self.short_anchors.is_some();
        let state = if self.state == BigramPrefilterState::Invalid
            || self.state != derived_state
            || !has_anchor_owner
        {
            BigramPrefilterState::Invalid
        } else {
            derived_state
        };
        BigramPrefilterStatus {
            populated_slots,
            total_slots: TABLE_SLOTS,
            saturation_threshold_slots: SATURATION_THRESHOLD_SLOTS,
            density_basis_points: share_basis_points(populated_slots as u64, TABLE_SLOTS as u64),
            state,
        }
    }

    pub(crate) fn corpus_status<'a, I>(
        &self,
        corpus_name: &'a str,
        inputs: I,
        minimum_input_bytes: usize,
    ) -> BigramPrefilterCorpusStatus<'a>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut input_count = 0u64;
        let mut eligible_inputs = 0u64;
        let mut rejected_inputs = 0u64;
        for input in inputs {
            input_count += 1;
            if input.len() >= minimum_input_bytes {
                eligible_inputs += 1;
                if !self.maybe_overlaps(input) {
                    rejected_inputs += 1;
                }
            }
        }
        BigramPrefilterCorpusStatus {
            corpus_name,
            input_count,
            eligible_inputs,
            rejected_inputs,
            rejection_basis_points: share_basis_points(rejected_inputs, input_count),
        }
    }

    pub(crate) fn is_saturated(&self) -> bool {
        self.status().state == BigramPrefilterState::Saturated
    }

    #[cfg(test)]
    pub(crate) fn scalar_overlaps_reference(&self, chunk: &[u8]) -> bool {
        if self.state != BigramPrefilterState::Healthy {
            return true;
        }
        if chunk.len() < usize::from(self.minimum_anchor_bytes) {
            return true;
        }
        if self
            .short_anchors
            .as_ref()
            .is_some_and(|anchors| anchors.is_match(chunk))
        {
            return true;
        }
        self.width_mask != 0
            && chunk
                .windows(MAX_ANCHOR_BYTES)
                .any(|window| self.contains_anchor(window))
    }

    #[cfg(test)]
    pub(crate) fn saturated_for_test() -> Self {
        Self::with_population_for_test(SATURATION_THRESHOLD_SLOTS)
    }

    #[doc(hidden)]
    pub(crate) fn with_population_for_test(populated_slots: u32) -> Self {
        let mut bloom = Self::empty();
        let bounded = populated_slots.min(TABLE_SLOTS) as usize;
        for slot in 0..bounded {
            bloom.bits[slot >> 6] |= 1u64 << (slot & 63);
        }
        bloom.recompute_saturation();
        bloom
    }

    #[doc(hidden)]
    pub(crate) fn invalid_for_test() -> Self {
        Self {
            bits: Box::new([0; 1024]),
            short_anchors: None,
            width_mask: 0,
            minimum_anchor_bytes: 0,
            state: BigramPrefilterState::Invalid,
        }
    }
}

const fn classify_population(populated_slots: u32, total_slots: u32) -> BigramPrefilterState {
    if total_slots == 0 || populated_slots > total_slots {
        return BigramPrefilterState::Invalid;
    }
    if populated_slots >= SATURATION_THRESHOLD_SLOTS {
        BigramPrefilterState::Saturated
    } else {
        BigramPrefilterState::Healthy
    }
}

fn share_basis_points(numerator: u64, denominator: u64) -> u16 {
    if denominator == 0 {
        return 0;
    }
    let basis_points = (u128::from(numerator) * 10_000) / u128::from(denominator);
    basis_points.min(10_000) as u16
}

#[inline(always)]
fn width_bit(width: usize) -> u8 {
    1 << (width - 1)
}


#[inline(always)]
fn contains_anchor_ascii8(bits: &[u64; 1024], anchor: &[u8]) -> bool {
    debug_assert_eq!(anchor.len(), MAX_ANCHOR_BYTES);
    // Inline `to_ascii_lowercase` + `ngram_slots` so the reject path does not
    // allocate an 8-byte scratch array on every window of a multi-MiB chunk.
    let mut first = 0x811c_9dc5u32 ^ MAX_ANCHOR_BYTES as u32;
    let mut second = 0x9e37_79b9u32 ^ (MAX_ANCHOR_BYTES as u32).rotate_left(16);
    for &byte in anchor {
        let folded = byte.to_ascii_lowercase();
        first ^= u32::from(folded);
        first = first.wrapping_mul(0x0100_0193);
        second ^= u32::from(folded);
        second = second.rotate_left(5).wrapping_mul(0x85eb_ca6b);
    }
    let slot0 = usize::from(((first ^ (first >> 16)) & 0xffff) as u16);
    let slot1 = usize::from(((second ^ (second >> 16)) & 0xffff) as u16);
    (bits[slot0 >> 6] & (1u64 << (slot0 & 63))) != 0
        && (bits[slot1 >> 6] & (1u64 << (slot1 & 63))) != 0
}


/// Two stable 16-bit slots for an anchor of one to eight bytes. Requiring both
/// bits keeps long real-corpus lines selective without enlarging the public
/// 65,536-slot diagnostic table. Collisions remain fail-open admissions.
#[inline(always)]
fn ngram_slots(bytes: &[u8]) -> [usize; 2] {
    debug_assert!(!bytes.is_empty() && bytes.len() <= MAX_ANCHOR_BYTES);
    let mut first = 0x811c_9dc5u32 ^ bytes.len() as u32;
    let mut second = 0x9e37_79b9u32 ^ (bytes.len() as u32).rotate_left(16);
    for byte in bytes {
        first ^= u32::from(*byte);
        first = first.wrapping_mul(0x0100_0193);
        second ^= u32::from(*byte);
        second = second.rotate_left(5).wrapping_mul(0x85eb_ca6b);
    }
    [
        usize::from(((first ^ (first >> 16)) & 0xffff) as u16),
        usize::from(((second ^ (second >> 16)) & 0xffff) as u16),
    ]
}
