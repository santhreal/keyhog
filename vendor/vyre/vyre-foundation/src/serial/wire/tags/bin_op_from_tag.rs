use crate::ir::BinOp;

/// Decode a [`BinOp`] from its VIR0 wire-format tag byte.
///
/// # Preconditions
///
/// `tag` must be a tag assigned by the VIR0 specification. Values outside
/// the defined tag space indicate a version mismatch or malformed input.
///
/// # Returns
///
/// `Ok(BinOp)` on a recognized tag. The mapping is stable and covers
/// arithmetic, bitwise, relational, logical, and floating-point helpers.
///
/// # Failure mode
///
/// Returns `Err("Fix: unknown binary op tag {tag}; use a compatible IR serializer.")`
/// for any unrecognized tag so callers reject the blob with an actionable
/// diagnostic.
#[inline]
pub(crate) fn bin_op_from_tag(tag: u8) -> Result<BinOp, String> {
    match tag {
        0x01 => Ok(BinOp::Add),
        0x02 => Ok(BinOp::Sub),
        0x03 => Ok(BinOp::Mul),
        0x04 => Ok(BinOp::Div),
        0x05 => Ok(BinOp::Mod),
        0x06 => Ok(BinOp::BitAnd),
        0x07 => Ok(BinOp::BitOr),
        0x08 => Ok(BinOp::BitXor),
        0x09 => Ok(BinOp::Shl),
        0x0A => Ok(BinOp::Shr),
        0x0B => Ok(BinOp::Eq),
        0x0C => Ok(BinOp::Ne),
        0x0D => Ok(BinOp::Lt),
        0x0E => Ok(BinOp::Gt),
        0x0F => Ok(BinOp::Le),
        0x10 => Ok(BinOp::Ge),
        0x11 => Ok(BinOp::And),
        0x12 => Ok(BinOp::Or),
        0x13 => Ok(BinOp::AbsDiff),
        // L.1.27 / I4: decode counterpart of the Min/Max tag assignments
        // in `bin_op_tag.rs`.
        0x14 => Ok(BinOp::Min),
        0x15 => Ok(BinOp::Max),
        0x16 => Ok(BinOp::SaturatingAdd),
        0x17 => Ok(BinOp::SaturatingSub),
        0x18 => Ok(BinOp::SaturatingMul),
        0x19 => Ok(BinOp::Shuffle),
        0x1A => Ok(BinOp::Ballot),
        0x1B => Ok(BinOp::WaveReduce),
        0x1C => Ok(BinOp::WaveBroadcast),
        0x1D => Ok(BinOp::RotateLeft),
        0x1E => Ok(BinOp::RotateRight),
        0x1F => Ok(BinOp::WrappingAdd),
        0x20 => Ok(BinOp::WrappingSub),
        _ => Err(format!(
            "Fix: unknown binary op tag {tag}; use a compatible IR serializer."
        )),
    }
}
