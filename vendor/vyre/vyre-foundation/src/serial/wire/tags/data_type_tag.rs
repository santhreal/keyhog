use crate::ir::DataType;
use crate::serial::wire::framing::{put_u32, put_u8};

/// Encode a [`DataType`] into its stable VIR0 wire-format tag byte.
///
/// # Preconditions
///
/// `value` must be a variant known to the VIR0 encoder. Because `DataType` is
/// `#[non_exhaustive]`, future spec additions must receive a tag here before
/// they can round-trip through the wire format.
///
/// # Returns
///
/// `Ok(u8)` containing the tag value. Scalar and tensor types map to a single
/// byte; `Array` maps to tag `12` and the caller must follow up with the
/// `element_size` payload via [`put_data_type`].
///
/// # Failure mode
///
/// Returns `Err("unknown DataType variant")` when the variant has no
/// registered tag, preventing silent data loss on round-trip.
/// Wire tag reserved for extension DataTypes. The tag byte is 0x80;
/// the u32 extension id follows immediately (little-endian). See
/// `docs/wire-format.md` §Extensions.
pub(crate) const DATA_TYPE_TAG_OPAQUE: u8 = 0x80;

#[inline]
pub(crate) fn data_type_tag(value: &DataType) -> Result<u8, String> {
    match value {
        DataType::U32 => Ok(0x01),
        DataType::I32 => Ok(0x02),
        DataType::U64 => Ok(0x03),
        DataType::Vec2U32 => Ok(0x04),
        DataType::Vec4U32 => Ok(0x05),
        DataType::Bool => Ok(0x06),
        DataType::Bytes => Ok(0x07),
        DataType::Array { .. } => Ok(0x08),
        DataType::F16 => Ok(0x09),
        DataType::BF16 => Ok(0x0A),
        DataType::F32 => Ok(0x0B),
        DataType::F64 => Ok(0x0C),
        DataType::Tensor => Ok(0x0D),
        DataType::U8 => Ok(0x0E),
        DataType::U16 => Ok(0x0F),
        DataType::I8 => Ok(0x10),
        DataType::I16 => Ok(0x11),
        DataType::I64 => Ok(0x12),
        DataType::Handle(_) => Ok(0x13),
        DataType::Vec { .. } => Ok(0x14),
        DataType::TensorShaped { .. } => Ok(0x15),
        DataType::Opaque(_) => Ok(DATA_TYPE_TAG_OPAQUE),
        _ => Err("unknown DataType variant".to_string()),
    }
}

/// Write a [`DataType`] tag and any required payload into the output buffer.
///
/// # Preconditions
///
/// `value` must be a variant known to the VIR0 encoder. `out` is the byte
/// accumulator for the current wire-format message.
///
/// # Returns
///
/// `Ok(())` after appending the tag byte (and, for `Array`, the `element_size`
/// as a little-endian `u32`).
///
/// # Failure mode
///
/// * Returns the same error as [`data_type_tag`] if the variant is unknown.
/// * Returns `Err("Fix: array element_size ... cannot fit the VIR0 u32 payload")`
///   when `element_size` exceeds `u32::MAX`, which would truncate the payload.
#[inline]
pub(crate) fn put_data_type(out: &mut Vec<u8>, value: &DataType) -> Result<(), String> {
    put_u8(out, data_type_tag(value)?);
    match value {
        DataType::Array { element_size } => {
            let encoded = u32::try_from(*element_size).map_err(|err| {
                format!(
                    "Fix: array element_size {element_size} cannot fit the VIR0 u32 payload ({err}); cap the element size or extend the wire format."
                )
            })?;
            put_u32(out, encoded);
        }
        DataType::Opaque(id) => {
            // Opaque payload = u32 extension id (little-endian).
            put_u32(out, id.as_u32());
        }
        DataType::Handle(id) => {
            put_u32(out, id.as_u32());
        }
        DataType::Vec { element, count } => {
            put_data_type(out, element)?;
            put_u8(out, *count);
        }
        DataType::TensorShaped { element, shape } => {
            put_data_type(out, element)?;
            let len = u32::try_from(shape.len()).map_err(|err| {
                format!(
                    "Fix: tensor shape rank {} cannot fit the VIR0 u32 payload ({err}); cap rank before serialization.",
                    shape.len()
                )
            })?;
            put_u32(out, len);
            for dim in shape {
                put_u32(out, *dim);
            }
        }
        // Fixed-width scalar and vector types consume zero payload bytes
        // beyond the tag byte `data_type_tag` returned above.
        DataType::U8
        | DataType::U16
        | DataType::U32
        | DataType::I8
        | DataType::I16
        | DataType::I32
        | DataType::I64
        | DataType::U64
        | DataType::F32
        | DataType::F16
        | DataType::BF16
        | DataType::F64
        | DataType::Bool
        | DataType::Bytes
        | DataType::Tensor
        | DataType::Vec2U32
        | DataType::Vec4U32 => {}
        // `DataType` is `#[non_exhaustive]` in vyre-spec; future extension
        // variants added there must not break the existing encoder. Any
        // new variant must also add a payload-emission arm above before
        // being released, or encoding will fail fast here.
        _ => {
            return Err(format!(
                "Fix: unknown DataType variant {value:?} has no wire-format payload emitter. Add a match arm in put_data_type when the variant is introduced in vyre-spec."
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::put_data_type;
    use crate::ir::DataType;

    #[test]
    fn bool_data_type_wire_payload_is_single_u8_tag() {
        let mut encoded = Vec::new();
        put_data_type(&mut encoded, &DataType::Bool)
            .expect("Fix: DataType::Bool must encode as one u8 tag");
        assert_eq!(encoded, vec![0x06]);
    }
}
