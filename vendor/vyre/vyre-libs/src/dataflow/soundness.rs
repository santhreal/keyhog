//! Soundness regime markers for dataflow primitives.
//!
//! Rules with zero-FP precision contracts MUST only compose primitives
//! whose marker is [`Soundness::Exact`], or [`Soundness::MayOver`]
//! primitives gated by an explicit sanitizer filter downstream.

/// Soundness regime of a dataflow primitive.
///
/// Rules with zero-FP precision contracts MUST only compose primitives
/// whose marker is `Exact`, or `MayOver` primitives gated by an explicit
/// sanitizer filter downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Soundness {
    /// Over-approximates: may report taint where none exists. Safe for
    /// recall-driven rules paired with a downstream filter.
    MayOver,
    /// Under-approximates: may miss taint that exists. Safe only when
    /// the rule semantics explicitly accept false negatives.
    MustUnder,
    /// Exact: reports taint iff taint exists on the given CFG. No false
    /// positives, no false negatives, given a correct input AST.
    Exact,
}

impl Soundness {
    /// Conservative join of two soundness markers.
    ///
    /// The join is the least precise soundness that soundly describes
    /// the composition of two primitives.
    #[must_use]
    pub const fn join(self, other: Soundness) -> Soundness {
        match (self, other) {
            (Soundness::MayOver, _) | (_, Soundness::MayOver) => Soundness::MayOver,
            (Soundness::MustUnder, Soundness::MustUnder) => Soundness::MustUnder,
            (Soundness::MustUnder, Soundness::Exact) | (Soundness::Exact, Soundness::MustUnder) => {
                Soundness::MustUnder
            }
            (Soundness::Exact, Soundness::Exact) => Soundness::Exact,
        }
    }
}

/// Trait for types that carry a soundness marker.
pub trait SoundnessTagged {
    /// Return the soundness regime of this primitive.
    fn soundness(&self) -> Soundness;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn may_over_join_must_under_is_may_over() {
        assert_eq!(
            Soundness::MayOver.join(Soundness::MustUnder),
            Soundness::MayOver
        );
        assert_eq!(
            Soundness::MustUnder.join(Soundness::MayOver),
            Soundness::MayOver
        );
    }
}
