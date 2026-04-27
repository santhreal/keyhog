use crate::ir::BinOp;

/// Encode a [`BinOp`] into its stable VIR0 wire-format tag byte.
///
/// # Preconditions
///
/// `value` must be a variant known to the VIR0 encoder. Because `BinOp` is
/// `#[non_exhaustive]`, future spec additions must receive a tag here before
/// they can round-trip through the wire format.
///
/// # Returns
///
/// `Ok(u8)` containing the tag value (`0..=20`).
///
/// # Failure mode
///
/// Returns `Err("unknown BinOp variant")` when the variant has no registered
/// tag. This prevents silent data loss on round-trip.
///
/// # Audit history
///
/// L.1.27 / I4: Min and Max had no tag and were rejected at serialize time,
/// breaking `Program::from_wire(Program::to_wire(p))` for any program that
/// legitimately declared a Min/Max BinOp. They now map to `19` and `20`.
#[inline]
pub(crate) fn bin_op_tag(value: BinOp) -> Result<u8, String> {
    match value {
        BinOp::Add => Ok(0x01),
        BinOp::Sub => Ok(0x02),
        BinOp::Mul => Ok(0x03),
        BinOp::Div => Ok(0x04),
        BinOp::Mod => Ok(0x05),
        BinOp::BitAnd => Ok(0x06),
        BinOp::BitOr => Ok(0x07),
        BinOp::BitXor => Ok(0x08),
        BinOp::Shl => Ok(0x09),
        BinOp::Shr => Ok(0x0A),
        BinOp::Eq => Ok(0x0B),
        BinOp::Ne => Ok(0x0C),
        BinOp::Lt => Ok(0x0D),
        BinOp::Gt => Ok(0x0E),
        BinOp::Le => Ok(0x0F),
        BinOp::Ge => Ok(0x10),
        BinOp::And => Ok(0x11),
        BinOp::Or => Ok(0x12),
        BinOp::AbsDiff => Ok(0x13),
        // L.1.27 / I4: Min and Max had no tag and were rejected at
        // serialize time, breaking `Program::from_wire(Program::to_wire(p))`
        // for any program that legitimately declared a Min/Max BinOp.
        BinOp::Min => Ok(0x14),
        BinOp::Max => Ok(0x15),
        BinOp::SaturatingAdd => Ok(0x16),
        BinOp::SaturatingSub => Ok(0x17),
        BinOp::SaturatingMul => Ok(0x18),
        BinOp::Shuffle => Ok(0x19),
        BinOp::Ballot => Ok(0x1A),
        BinOp::WaveReduce => Ok(0x1B),
        BinOp::WaveBroadcast => Ok(0x1C),
        BinOp::RotateLeft => Ok(0x1D),
        BinOp::RotateRight => Ok(0x1E),
        BinOp::WrappingAdd => Ok(0x1F),
        BinOp::WrappingSub => Ok(0x20),
        _ => Err("unknown BinOp variant".to_string()),
    }
}
