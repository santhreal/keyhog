//! Frozen binary-operation discriminants for primitive operation metadata.
// TAG RESERVATIONS: Add=0x01, Sub=0x02, Mul=0x03, Div=0x04, Mod=0x05,
// BitAnd=0x06, BitOr=0x07, BitXor=0x08, Shl=0x09, Shr=0x0A, Eq=0x0B,
// Ne=0x0C, Lt=0x0D, Gt=0x0E, AbsDiff=0x0F, Le=0x10, Ge=0x11,
// And=0x12, Or=0x13, Min=0x14, Max=0x15, SaturatingAdd=0x16,
// SaturatingSub=0x17, SaturatingMul=0x18, Shuffle=0x19, Ballot=0x1A,
// WaveReduce=0x1B, WaveBroadcast=0x1C, RotateLeft=0x1D, WrappingAdd=0x1F, WrappingSub=0x20,
// RotateRight=0x1E, MulHigh=0x21, 0x22..=0x7F reserved, Opaque=0x80.

use crate::extension::ExtensionBinOpId;

/// Computational intensity class for a binary operation.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum OpIntensity {
    /// Zero-cost (bitcasts, aliasing).
    Free,
    /// Single-cycle ALU (Add, Sub, Bitwise).
    Light,
    /// Multi-cycle ALU (Mul, Div, Mod).
    Medium,
    /// High latency / Register heavy (transcendentals, subgroup ops).
    Heavy,
}

/// Binary operation kind in the frozen data contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
#[non_exhaustive]
pub enum BinOp {
    /// Addition.
    Add,
    /// Subtraction.
    Sub,
    /// Multiplication.
    Mul,
    /// Division.
    Div,
    /// Remainder.
    Mod,
    /// Wrapping addition.
    WrappingAdd,
    /// Wrapping subtraction.
    WrappingSub,
    /// Bitwise AND.
    BitAnd,
    /// Bitwise OR.
    BitOr,
    /// Bitwise XOR.
    BitXor,
    /// Shift left.
    Shl,
    /// Shift right.
    Shr,
    /// Equality.
    Eq,
    /// Inequality.
    Ne,
    /// Less than.
    Lt,
    /// Greater than.
    Gt,
    /// Less than or equal.
    Le,
    /// Greater than or equal.
    Ge,
    /// Logical AND.
    And,
    /// Logical OR.
    Or,
    /// Unsigned absolute difference.
    AbsDiff,
    /// Minimum (f32).
    Min,
    /// Maximum (f32).
    Max,
    /// Saturating addition.
    SaturatingAdd,
    /// Saturating subtraction.
    SaturatingSub,
    /// Saturating multiplication.
    SaturatingMul,
    /// GPU subgroup shuffle.
    Shuffle,
    /// GPU subgroup ballot.
    Ballot,
    /// GPU subgroup reduction.
    WaveReduce,
    /// GPU subgroup broadcast.
    WaveBroadcast,
    /// Rotate-left.
    RotateLeft,
    /// Rotate-right.
    RotateRight,
    /// Unsigned multiply-high: upper 32 bits of `(left × right)` treated
    /// as a 64-bit product. Enables Granlund-Montgomery strength reduction
    /// of integer division by constant to 2 instructions.
    MulHigh,
    /// Extension-declared binary operator.
    Opaque(ExtensionBinOpId),
}

impl BinOp {
    /// Frozen builtin wire tag for this binary operation.
    ///
    /// Returns `None` for extension-declared opaque operators because their
    /// wire representation is the high-bit extension id, not a core tag.
    #[must_use]
    pub const fn builtin_wire_tag(&self) -> Option<u8> {
        match self {
            Self::Add => Some(0x01),
            Self::Sub => Some(0x02),
            Self::Mul => Some(0x03),
            Self::Div => Some(0x04),
            Self::Mod => Some(0x05),
            Self::BitAnd => Some(0x06),
            Self::BitOr => Some(0x07),
            Self::BitXor => Some(0x08),
            Self::Shl => Some(0x09),
            Self::Shr => Some(0x0A),
            Self::Eq => Some(0x0B),
            Self::Ne => Some(0x0C),
            Self::Lt => Some(0x0D),
            Self::Gt => Some(0x0E),
            Self::AbsDiff => Some(0x0F),
            Self::Le => Some(0x10),
            Self::Ge => Some(0x11),
            Self::And => Some(0x12),
            Self::Or => Some(0x13),
            Self::Min => Some(0x14),
            Self::Max => Some(0x15),
            Self::SaturatingAdd => Some(0x16),
            Self::SaturatingSub => Some(0x17),
            Self::SaturatingMul => Some(0x18),
            Self::Shuffle => Some(0x19),
            Self::Ballot => Some(0x1A),
            Self::WaveReduce => Some(0x1B),
            Self::WaveBroadcast => Some(0x1C),
            Self::RotateLeft => Some(0x1D),
            Self::RotateRight => Some(0x1E),
            Self::WrappingAdd => Some(0x1F),
            Self::WrappingSub => Some(0x20),
            Self::MulHigh => Some(0x21),
            Self::Opaque(_) => None,
        }
    }

    /// Return the static computational intensity of this operation.
    #[must_use]
    pub fn intensity(&self) -> OpIntensity {
        match self {
            Self::Add
            | Self::Sub
            | Self::BitAnd
            | Self::BitOr
            | Self::BitXor
            | Self::Shl
            | Self::Shr
            | Self::WrappingAdd
            | Self::WrappingSub
            | Self::RotateLeft
            | Self::RotateRight
            | Self::SaturatingAdd
            | Self::SaturatingSub
            | Self::SaturatingMul
            | Self::AbsDiff => OpIntensity::Light,
            Self::Ballot | Self::Shuffle | Self::WaveReduce | Self::WaveBroadcast => {
                OpIntensity::Heavy
            }
            _ => OpIntensity::Medium,
        }
    }
}
