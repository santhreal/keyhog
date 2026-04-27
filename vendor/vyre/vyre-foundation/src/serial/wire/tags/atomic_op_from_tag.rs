use crate::ir::AtomicOp;

/// Decode an [`AtomicOp`] from its VIR0 wire-format tag byte.
///
/// # Preconditions
///
/// `tag` must be a tag assigned by the VIR0 specification. Values outside
/// the defined tag space indicate a version mismatch or malformed input.
///
/// # Returns
///
/// `Ok(AtomicOp)` on a recognized tag. The mapping is stable:
/// `0 → Add`, `1 → Or`, `2 → And`, `3 → Xor`, `4 → Min`, `5 → Max`,
/// `6 → Exchange`, `7 → CompareExchange`.
///
/// # Failure mode
///
/// Returns `Err("Fix: unknown atomic op tag {tag}; use a compatible IR serializer.")`
/// for any unrecognized tag so callers reject the blob with an actionable
/// diagnostic.
#[inline]
pub(crate) fn atomic_op_from_tag(tag: u8) -> Result<AtomicOp, String> {
    match tag {
        0x01 => Ok(AtomicOp::Add),
        0x02 => Ok(AtomicOp::Or),
        0x03 => Ok(AtomicOp::And),
        0x04 => Ok(AtomicOp::Xor),
        0x05 => Ok(AtomicOp::Min),
        0x06 => Ok(AtomicOp::Max),
        0x07 => Ok(AtomicOp::Exchange),
        0x08 => Ok(AtomicOp::CompareExchange),
        0x09 => Ok(AtomicOp::CompareExchangeWeak),
        0x0A => Ok(AtomicOp::FetchNand),
        0x0B => Ok(AtomicOp::LruUpdate),
        _ => Err(format!(
            "Fix: unknown atomic op tag {tag}; use a compatible IR serializer."
        )),
    }
}
