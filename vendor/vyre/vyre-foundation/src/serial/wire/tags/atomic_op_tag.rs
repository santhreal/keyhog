use crate::ir::AtomicOp;

/// Encode an [`AtomicOp`] into its stable VIR0 wire-format tag byte.
///
/// # Preconditions
///
/// `value` must be a variant known to the VIR0 encoder. Because `AtomicOp`
/// is `#[non_exhaustive]`, future spec additions must receive a tag here
/// before they can round-trip through the wire format.
///
/// # Returns
///
/// `Ok(u8)` containing the tag value (`0..=7`).
///
/// # Failure mode
///
/// Returns `Err("unknown AtomicOp variant")` when the variant has no
/// registered tag. This prevents silent data loss on round-trip.
#[inline]
pub(crate) fn atomic_op_tag(value: AtomicOp) -> Result<u8, String> {
    let tag = match value {
        AtomicOp::Add => 0x01,
        AtomicOp::Or => 0x02,
        AtomicOp::And => 0x03,
        AtomicOp::Xor => 0x04,
        AtomicOp::Min => 0x05,
        AtomicOp::Max => 0x06,
        AtomicOp::Exchange => 0x07,
        AtomicOp::CompareExchange => 0x08,
        AtomicOp::CompareExchangeWeak => 0x09,
        AtomicOp::FetchNand => 0x0A,
        AtomicOp::LruUpdate => 0x0B,
        _ => return Err("unknown AtomicOp variant".to_string()),
    };
    Ok(tag)
}
