//! Frozen ternary-operation discriminants for operation signature metadata.
// TAG RESERVATIONS: Fma=0x01, Select=0x02, 0x03..=0x7F reserved,
// Opaque=0x80.

use crate::extension::ExtensionTernaryOpId;

/// Ternary operation kind in the frozen data contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
#[non_exhaustive]
pub enum TernaryOp {
    /// Fused multiply-add.
    Fma,
    /// Ternary select.
    Select,
    /// Extension-declared ternary operator.
    Opaque(ExtensionTernaryOpId),
}
