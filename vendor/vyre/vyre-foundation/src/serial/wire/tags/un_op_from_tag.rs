use crate::ir::UnOp;

/// Decode a [`UnOp`] from its VIR0 wire-format tag byte.
///
/// # Preconditions
///
/// `tag` must be a tag assigned by the VIR0 specification. Values outside
/// the defined tag space indicate a version mismatch or malformed input.
///
/// # Returns
///
/// `Ok(UnOp)` on a recognized tag. The mapping covers integer bitwise,
/// arithmetic, and floating-point unary operators.
///
/// # Failure mode
///
/// Returns `Err("Fix: unknown unary op tag {tag}; use a compatible IR serializer.")`
/// for any unrecognized tag so callers reject the blob with an actionable
/// diagnostic.
#[inline]
pub(crate) fn un_op_from_tag(tag: u8) -> Result<UnOp, String> {
    match tag {
        0x01 => Ok(UnOp::Negate),
        0x02 => Ok(UnOp::BitNot),
        0x03 => Ok(UnOp::LogicalNot),
        0x04 => Ok(UnOp::Popcount),
        0x05 => Ok(UnOp::Clz),
        0x06 => Ok(UnOp::Ctz),
        0x07 => Ok(UnOp::ReverseBits),
        0x08 => Ok(UnOp::Cos),
        0x09 => Ok(UnOp::Sin),
        0x0A => Ok(UnOp::Abs),
        0x0B => Ok(UnOp::Sqrt),
        // L.1.27 / I4: decode counterpart of the float-unary tag
        // assignments in `un_op_tag.rs`.
        0x0C => Ok(UnOp::Floor),
        0x0D => Ok(UnOp::Ceil),
        0x0E => Ok(UnOp::Round),
        0x0F => Ok(UnOp::Trunc),
        0x10 => Ok(UnOp::Sign),
        0x11 => Ok(UnOp::IsNan),
        0x12 => Ok(UnOp::IsInf),
        0x13 => Ok(UnOp::IsFinite),
        0x14 => Ok(UnOp::Exp),
        0x15 => Ok(UnOp::Log),
        0x16 => Ok(UnOp::Log2),
        0x17 => Ok(UnOp::Exp2),
        0x18 => Ok(UnOp::Tan),
        0x19 => Ok(UnOp::Acos),
        0x1A => Ok(UnOp::Asin),
        0x1B => Ok(UnOp::Atan),
        0x1C => Ok(UnOp::Tanh),
        0x1D => Ok(UnOp::Sinh),
        0x1E => Ok(UnOp::Cosh),
        0x1F => Ok(UnOp::InverseSqrt),
        0x20 => Ok(UnOp::Unpack4Low),
        0x21 => Ok(UnOp::Unpack4High),
        0x22 => Ok(UnOp::Unpack8Low),
        0x23 => Ok(UnOp::Unpack8High),
        _ => Err(format!(
            "Fix: unknown unary op tag {tag}; use a compatible IR serializer."
        )),
    }
}
