//! Frozen atomic-operation discriminants for backend intrinsic metadata.
// TAG RESERVATIONS: Add=0x01, Or=0x02, And=0x03, Xor=0x04, Min=0x05,
// Max=0x06, Exchange=0x07, CompareExchange=0x08,
// CompareExchangeWeak=0x09, FetchNand=0x0A, LruUpdate=0x0B,
// 0x0C..=0x7F reserved, Opaque=0x80.

use crate::extension::ExtensionAtomicOpId;

/// Atomic operation kind in the frozen data contract.
///
/// Stability: frozen as of v0.4.0-alpha.2. Downstream matches must include a
/// fallback arm so the data contract can grow without breaking `SemVer`.
/// Example: `AtomicOp::CompareExchange` identifies a compare-and-exchange
/// primitive without binding it to one backend's spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
#[non_exhaustive]
pub enum AtomicOp {
    /// Atomic add.
    Add,
    /// Atomic bitwise OR.
    Or,
    /// Atomic bitwise AND.
    And,
    /// Atomic bitwise XOR.
    Xor,
    /// Atomic minimum.
    Min,
    /// Atomic maximum.
    Max,
    /// Atomic exchange.
    Exchange,
    /// Atomic compare-and-exchange.
    CompareExchange,
    /// Weak atomic compare-and-exchange.
    CompareExchangeWeak,
    /// Atomic fetch NAND.
    FetchNand,
    /// Update LRU timestamp/priority in a shared buffer.
    LruUpdate,
    /// Extension-declared atomic operator.
    ///
    /// The `ExtensionAtomicOpId` resolves via the vyre-core extension
    /// registry to a `&'static dyn ExtensionAtomicOp` with per-backend
    /// lowerings. Wire encoding is `0x80 ++ u32 extension_id`.
    Opaque(ExtensionAtomicOpId),
}

impl AtomicOp {
    /// Frozen builtin wire tag for this atomic operation.
    ///
    /// Returns `None` for extension-declared opaque operators because their
    /// wire representation is the high-bit extension id, not a core tag.
    #[must_use]
    pub const fn builtin_wire_tag(&self) -> Option<u8> {
        match self {
            Self::Add => Some(0x01),
            Self::Or => Some(0x02),
            Self::And => Some(0x03),
            Self::Xor => Some(0x04),
            Self::Min => Some(0x05),
            Self::Max => Some(0x06),
            Self::Exchange => Some(0x07),
            Self::CompareExchange => Some(0x08),
            Self::CompareExchangeWeak => Some(0x09),
            Self::FetchNand => Some(0x0A),
            Self::LruUpdate => Some(0x0B),
            Self::Opaque(_) => None,
        }
    }
}
