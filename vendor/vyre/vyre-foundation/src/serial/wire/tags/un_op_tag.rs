use crate::ir::UnOp;

/// Encode a [`UnOp`] into its stable VIR0 wire-format tag byte.
///
/// # Preconditions
///
/// `value` must be a variant known to the VIR0 encoder. Because `UnOp` is
/// `#[non_exhaustive]`, future spec additions must receive a tag here before
/// they can round-trip through the wire format.
///
/// # Returns
///
/// `Ok(u8)` containing the tag value (`0..=18`).
///
/// # Failure mode
///
/// Returns `Err("unknown UnOp variant")` when the variant has no registered
/// tag. This prevents silent data loss on round-trip.
///
/// # Audit history
///
/// L.1.27 / I4: remaining f32 unary ops had no wire tags, breaking roundtrip
/// serialization for any Program that declared them. They now map to `11..=18`.
#[inline]
pub(crate) fn un_op_tag(value: UnOp) -> Result<u8, String> {
    match value {
        UnOp::Negate => Ok(0x01),
        UnOp::BitNot => Ok(0x02),
        UnOp::LogicalNot => Ok(0x03),
        UnOp::Popcount => Ok(0x04),
        UnOp::Clz => Ok(0x05),
        UnOp::Ctz => Ok(0x06),
        UnOp::ReverseBits => Ok(0x07),
        UnOp::Cos => Ok(0x08),
        UnOp::Sin => Ok(0x09),
        UnOp::Abs => Ok(0x0A),
        UnOp::Sqrt => Ok(0x0B),
        // L.1.27 / I4: remaining f32 unary ops had no wire tags,
        // breaking roundtrip serialization for any Program that
        // declared them.
        UnOp::Floor => Ok(0x0C),
        UnOp::Ceil => Ok(0x0D),
        UnOp::Round => Ok(0x0E),
        UnOp::Trunc => Ok(0x0F),
        UnOp::Sign => Ok(0x10),
        UnOp::IsNan => Ok(0x11),
        UnOp::IsInf => Ok(0x12),
        UnOp::IsFinite => Ok(0x13),
        UnOp::Exp => Ok(0x14),
        UnOp::Log => Ok(0x15),
        UnOp::Log2 => Ok(0x16),
        UnOp::Exp2 => Ok(0x17),
        UnOp::Tan => Ok(0x18),
        UnOp::Acos => Ok(0x19),
        UnOp::Asin => Ok(0x1A),
        UnOp::Atan => Ok(0x1B),
        UnOp::Tanh => Ok(0x1C),
        UnOp::Sinh => Ok(0x1D),
        UnOp::Cosh => Ok(0x1E),
        UnOp::InverseSqrt => Ok(0x1F),
        UnOp::Unpack4Low => Ok(0x20),
        UnOp::Unpack4High => Ok(0x21),
        UnOp::Unpack8Low => Ok(0x22),
        UnOp::Unpack8High => Ok(0x23),
        _ => Err("unknown UnOp variant".to_string()),
    }
}
