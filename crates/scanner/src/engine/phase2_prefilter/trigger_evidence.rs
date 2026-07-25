//! Allocation-free observations used by the phase-2 prefilter gates.

use aho_corasick::AhoCorasick;

/// Facts about the current extraction text that every later prefilter decision
/// must share. Keeping the borrowed text here prevents each gate from deriving
/// its own subtly different notion of ASCII or chunk length.
#[derive(Clone, Copy, Debug)]
pub(super) struct ChunkTriggerEvidence<'a> {
    text: &'a str,
    ascii: bool,
}

impl<'a> ChunkTriggerEvidence<'a> {
    #[inline]
    pub(super) fn inspect(text: &'a str) -> Self {
        Self {
            text,
            ascii: text.is_ascii(),
        }
    }

    #[inline]
    pub(super) fn text(self) -> &'a str {
        self.text
    }

    #[inline]
    pub(super) fn is_ascii(self) -> bool {
        self.ascii
    }

    #[cfg(feature = "simd")]
    #[inline]
    pub(super) fn len(self) -> usize {
        self.text.len()
    }

    /// Observe an optional trigger automaton without inventing evidence when it
    /// is unavailable. `Unavailable` is deliberately distinct from `Absent`:
    /// only the latter can justify skipping work.
    #[inline]
    pub(super) fn observe_ac(self, ac: Option<&AhoCorasick>) -> TriggerEvidence {
        match ac {
            Some(ac) if ac.is_match(self.text) => TriggerEvidence::Present,
            Some(_) => TriggerEvidence::Absent,
            None => TriggerEvidence::Unavailable,
        }
    }
}

/// Exact result of observing one trigger source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TriggerEvidence {
    Present,
    Absent,
    Unavailable,
}
