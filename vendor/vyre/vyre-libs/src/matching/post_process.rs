//! Match post-processing: dedup, entropy, and confidence in one pass.
//!
//! The module is the canonical host reference for matcher output shaping.
//! Consumers that need device-resident post-processing use the same field
//! contract: sorted non-overlapping `(pattern_id, start, end)` spans plus
//! deterministic entropy and confidence signals.

use vyre_foundation::match_result::Match;
use vyre_primitives::matching::region::{dedup_regions_inplace, RegionTriple};

/// Post-processing contract violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostProcessError {
    /// A match range does not fit inside the haystack that was scanned.
    InvalidRange {
        /// Pattern id attached to the invalid match.
        pattern_id: u32,
        /// Inclusive start byte offset.
        start: u32,
        /// Exclusive end byte offset.
        end: u32,
        /// Haystack length in bytes.
        haystack_len: usize,
    },
}

impl std::fmt::Display for PostProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::InvalidRange {
                pattern_id,
                start,
                end,
                haystack_len,
            } => write!(
                f,
                "match range is outside the scanned haystack: pattern_id={pattern_id}, start={start}, end={end}, haystack_len={haystack_len}. Fix: preserve matcher readback bounds and reject corrupt hit triples before scoring."
            ),
        }
    }
}

impl std::error::Error for PostProcessError {}

/// Output of [`try_post_process_cpu`]. Carries the deduped match and the
/// two derived signals every downstream consumer reads.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PostProcessedMatch {
    /// Pattern id from the original `Match`.
    pub pattern_id: u32,
    /// Inclusive start byte offset.
    pub start: u32,
    /// Exclusive end byte offset.
    pub end: u32,
    /// Shannon entropy in bits/byte over `haystack[start..end]`. `0.0`
    /// for zero-width matches.
    pub entropy_bits_per_byte: f32,
    /// `[0.0, 1.0]` confidence score combining length + entropy.
    /// Specifically `min(1, len/16) * (entropy / 8)` — the same
    /// heuristic keyhog's per-match scorer applies. The factor of 16
    /// matches the typical AKIA / ghp_ token width; entropy is
    /// normalised against the 8 bits/byte ceiling for binary-uniform
    /// data.
    pub confidence: f32,
}

/// Fuse `dedup_regions_inplace`, entropy-per-span, and confidence into one
/// CPU reference pass over the input.
///
/// Returned vector is sorted by `(pid, start, end)` (the dedup
/// post-condition). `haystack` is the same byte buffer the matcher scanned.
///
/// # Errors
///
/// Returns [`PostProcessError::InvalidRange`] if any deduped match points
/// outside `haystack`.
pub fn try_post_process_cpu(
    matches: &[Match],
    haystack: &[u8],
) -> Result<Vec<PostProcessedMatch>, PostProcessError> {
    if matches.is_empty() {
        return Ok(Vec::new());
    }

    let mut triples: Vec<RegionTriple> = matches
        .iter()
        .map(|m| RegionTriple::new(m.pattern_id, m.start, m.end))
        .collect();
    dedup_regions_inplace(&mut triples);

    let mut out = Vec::with_capacity(triples.len());
    for t in triples {
        let s = t.start as usize;
        let e = t.end as usize;
        if e > haystack.len() || s > e {
            return Err(PostProcessError::InvalidRange {
                pattern_id: t.pid,
                start: t.start,
                end: t.end,
                haystack_len: haystack.len(),
            });
        }
        let bytes = &haystack[s..e];
        let entropy = shannon_entropy_bits_per_byte(bytes);
        let len_score = (bytes.len() as f32 / 16.0).min(1.0);
        let entropy_score = entropy / 8.0;
        let confidence = (len_score * entropy_score).clamp(0.0, 1.0);
        out.push(PostProcessedMatch {
            pattern_id: t.pid,
            start: t.start,
            end: t.end,
            entropy_bits_per_byte: entropy,
            confidence,
        });
    }
    Ok(out)
}

/// Infallible reference wrapper for callers whose matcher contract has
/// already proved all ranges are within `haystack`.
///
/// Panics with an actionable message on corrupt match triples instead of
/// silently dropping evidence.
#[must_use]
pub fn post_process_cpu(matches: &[Match], haystack: &[u8]) -> Vec<PostProcessedMatch> {
    try_post_process_cpu(matches, haystack)
        .expect("post_process_cpu received corrupt match ranges; use try_post_process_cpu to surface PostProcessError")
}

/// Shannon entropy in bits/byte. Returns `0.0` on an empty slice. The
/// implementation is straight `-sum(p_i log2 p_i)` over a 256-bucket
/// histogram — match cost is dominated by the haystack scan, so a
/// fixed stack histogram here is amortised on every realistic input.
#[must_use]
pub fn shannon_entropy_bits_per_byte(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f32;
    let mut h = 0.0_f32;
    for c in counts {
        if c == 0 {
            continue;
        }
        let p = c as f32 / n;
        h -= p * p.log2();
    }
    h
}
