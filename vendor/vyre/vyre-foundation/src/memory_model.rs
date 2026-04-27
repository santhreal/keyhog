//! Substrate-neutral memory model contracts.

/// Memory ordering attached to atomic and barrier operations.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum MemoryOrdering {
    /// No synchronization beyond atomicity of the operation.
    Relaxed,
    /// Subsequent reads observe writes released by another participant.
    Acquire,
    /// Prior writes become visible to acquiring participants.
    Release,
    /// Acquire and release semantics in one operation.
    AcqRel,
    /// Single total order across sequentially consistent operations.
    SeqCst,
}

impl Default for MemoryOrdering {
    #[inline]
    fn default() -> Self {
        Self::SeqCst
    }
}
