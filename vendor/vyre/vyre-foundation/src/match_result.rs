//! Native scan match result — **legacy scan-domain shim.**
//!
//! CRITIQUE_VISION_ALIGNMENT_2026-04-23 V1: this type was the Tier-1
//! return shape for every byte-range scan in vyre. Its field name
//! (`pattern_id`) pre-decided that every byte range is a "match"
//! from a "pattern" — a matching-dialect concept that shouldn't
//! live in foundation. A crypto decoder, an AST-span emitter, or a
//! capture-group producer would either adopt matching vocabulary
//! awkwardly or ship a parallel type.
//!
//! The canonical home is now
//! [`vyre_primitives::range::ByteRange`][`super`] (Tier 2.5). `Match`
//! remains here as a backward-compat alias with a `#[deprecated]`
//! marker pointing authors at the new name. Bridges between the
//! two types are zero-cost (`repr(C)` u32×3 on both sides).
//!
//! The full migration removes `Match` entirely; we keep it for one
//! release so dependent crates don't hard-break.

/// A byte-range match emitted by vyre scanning engines.
///
/// **Deprecated:** callers should migrate to
/// `vyre_primitives::range::ByteRange`. The two types share layout
/// and the `From` bridges are zero-cost (see
/// `vyre_primitives::range::match_bridge`).
///
/// Background: `pattern_id` is a matching-dialect concept. The
/// neutral name on the new type is `tag`; the producer decides what
/// it means (pattern id, encoding id, AST kind, source index, …).
/// CRITIQUE_VISION_ALIGNMENT_2026-04-23 V1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Match {
    /// Stable pattern identifier that produced the match.
    pub pattern_id: u32,
    /// Inclusive byte start offset.
    pub start: u32,
    /// Exclusive byte end offset.
    pub end: u32,
}

impl Match {
    /// Construct a match from its pattern id and byte range.
    ///
    /// This constructor is a const fn so that engines can emit match
    /// literals at compile time. The byte range is half-open `[start, end)`
    /// to match Rust slicing conventions.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::Match;
    ///
    /// let m = Match::new(1, 10, 20);
    /// assert_eq!(m.pattern_id, 1);
    /// assert_eq!(m.start, 10);
    /// assert_eq!(m.end, 20);
    /// ```
    #[must_use]
    pub const fn new(pattern_id: u32, start: u32, end: u32) -> Self {
        Self {
            pattern_id,
            start,
            end,
        }
    }
}
