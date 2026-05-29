use crate::ir::DataType;
use crate::serial::wire::encode::WireEncodeErr;
use crate::serial::wire::framing::{put_u32, put_u8};

/// Encode a [`DataType`] into its stable VIR0 wire-format tag byte.
///
/// # Preconditions
///
/// `value` must be a variant known to the VIR0 encoder. Because `DataType` is
/// `#[non_exhaustive]`, spec additions must receive a tag here before
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
/// Wire tag reserved for extension `DataTypes`. The tag byte is `0x80`;
/// the u32 extension id follows immediately (little-endian). See
/// `docs/wire-format.md` §Extensions.
pub(crate) const DATA_TYPE_TAG_OPAQUE: u8 = 0x80;

#[inline]
pub(crate) fn data_type_tag(value: &DataType) -> Result<u8, WireEncodeErr> {
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
        DataType::SparseCsr { .. } => Ok(0x16),
        DataType::SparseCoo { .. } => Ok(0x17),
        DataType::SparseBsr { .. } => Ok(0x18),
        DataType::F8E4M3 => Ok(0x19),
        DataType::F8E5M2 => Ok(0x1A),
        DataType::I4 => Ok(0x1B),
        DataType::FP4 => Ok(0x1C),
        DataType::NF4 => Ok(0x1D),
        DataType::DeviceMesh { .. } => Ok(0x1E),
        DataType::Quantized { .. } => Ok(0x1F),
        DataType::Opaque(_) => Ok(DATA_TYPE_TAG_OPAQUE),
        _ => Err(WireEncodeErr::static_msg("unknown DataType variant")),
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
pub(crate) fn put_data_type(out: &mut Vec<u8>, value: &DataType) -> Result<(), WireEncodeErr> {
    put_u8(out, data_type_tag(value)?);
    match value {
        DataType::Array { element_size } => {
            let encoded = u32::try_from(*element_size).map_err(|_| {
                WireEncodeErr::fmt_usize(
                    "Fix: array element_size ",
                    *element_size,
                    " cannot fit the VIR0 u32 payload; cap the element size or extend the wire format.",
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
            let len = u32::try_from(shape.len()).map_err(|_| {
                WireEncodeErr::fmt_usize(
                    "Fix: tensor shape rank ",
                    shape.len(),
                    " cannot fit the VIR0 u32 payload; cap rank before serialization.",
                )
            })?;
            put_u32(out, len);
            for dim in shape {
                put_u32(out, *dim);
            }
        }
        DataType::SparseCsr { element } | DataType::SparseCoo { element } => {
            put_data_type(out, element)?;
        }
        DataType::SparseBsr {
            element,
            block_rows,
            block_cols,
        } => {
            put_data_type(out, element)?;
            put_u32(out, *block_rows);
            put_u32(out, *block_cols);
        }
        DataType::DeviceMesh { axes } => {
            let len = u32::try_from(axes.len()).map_err(|_| {
                WireEncodeErr::fmt_usize(
                    "Fix: device-mesh axes count ",
                    axes.len(),
                    " cannot fit the VIR0 u32 payload; cap mesh rank before serialization.",
                )
            })?;
            put_u32(out, len);
            for axis in axes {
                put_u32(out, *axis);
            }
        }
        DataType::Quantized {
            storage,
            scale,
            zero_point,
        } => {
            if !storage.is_quantized_storage() {
                return Err(WireEncodeErr::static_msg(
                    "Fix: DataType::Quantized storage must be I4/I8/I16/U8/U16/F8E4M3/F8E5M2/FP4/NF4.",
                ));
            }
            put_data_type(out, storage)?;
            put_quantization_scale(out, scale)?;
            put_quantization_zero_point(out, zero_point)?;
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
        | DataType::Vec4U32
        | DataType::F8E4M3
        | DataType::F8E5M2
        | DataType::I4
        | DataType::FP4
        | DataType::NF4 => {}
        // `DataType` is `#[non_exhaustive]` in vyre-spec; extension
        // variants added there must not break the existing encoder. Any
        // new variant must also add a payload-emission arm above before
        // being released, or encoding will fail fast here.
        _ => {
            return Err(WireEncodeErr::static_msg(
                "Fix: unknown DataType variant has no wire-format payload emitter. Add a match arm in put_data_type when the variant is introduced in vyre-spec.",
            ));
        }
    }
    Ok(())
}

fn put_quantization_scale(
    out: &mut Vec<u8>,
    scale: &vyre_spec::QuantizationScale,
) -> Result<(), WireEncodeErr> {
    match scale {
        vyre_spec::QuantizationScale::PerTensor => {
            put_u8(out, 0);
            put_u32(out, 0);
        }
        vyre_spec::QuantizationScale::PerChannel { axis } => {
            put_u8(out, 1);
            put_u32(out, *axis);
        }
        vyre_spec::QuantizationScale::PerGroup { group_size } => {
            if *group_size == 0 {
                return Err(WireEncodeErr::static_msg(
                    "Fix: quantized PerGroup scale requires group_size > 0.",
                ));
            }
            put_u8(out, 2);
            put_u32(out, *group_size);
        }
    }
    Ok(())
}

fn put_quantization_zero_point(
    out: &mut Vec<u8>,
    zero_point: &vyre_spec::QuantizationZeroPoint,
) -> Result<(), WireEncodeErr> {
    match zero_point {
        vyre_spec::QuantizationZeroPoint::Absent => {
            put_u8(out, 0);
            put_u32(out, 0);
        }
        vyre_spec::QuantizationZeroPoint::PerTensor => {
            put_u8(out, 1);
            put_u32(out, 0);
        }
        vyre_spec::QuantizationZeroPoint::PerChannel { axis } => {
            put_u8(out, 2);
            put_u32(out, *axis);
        }
        vyre_spec::QuantizationZeroPoint::PerGroup { group_size } => {
            if *group_size == 0 {
                return Err(WireEncodeErr::static_msg(
                    "Fix: quantized PerGroup zero-point requires group_size > 0.",
                ));
            }
            put_u8(out, 3);
            put_u32(out, *group_size);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::put_data_type;
    use crate::ir::DataType;
    use crate::serial::wire::Reader;
    use smallvec::smallvec;

    #[test]
    fn bool_data_type_wire_payload_is_single_u8_tag() {
        let mut encoded = Vec::new();
        put_data_type(&mut encoded, &DataType::Bool)
            .expect("Fix: DataType::Bool must encode as one u8 tag");
        assert_eq!(encoded, vec![0x06]);
    }

    /// Every DataType variant the encoder accepts must also round-trip
    /// through the decoder with bit-exact equality. A drift here means
    /// the on-disk wire format silently corrupts buffer-element types
    /// across encode/decode  -  a contract-invariant the optimizer cache
    /// and AOT artifact format both rely on.
    #[test]
    fn every_supported_data_type_round_trips_through_the_wire() {
        let cases: Vec<DataType> = vec![
            DataType::U8,
            DataType::U16,
            DataType::U32,
            DataType::U64,
            DataType::I8,
            DataType::I16,
            DataType::I32,
            DataType::I64,
            DataType::F16,
            DataType::BF16,
            DataType::F32,
            DataType::F64,
            DataType::Bool,
            DataType::Bytes,
            DataType::Tensor,
            DataType::Vec2U32,
            DataType::Vec4U32,
            DataType::F8E4M3,
            DataType::F8E5M2,
            DataType::I4,
            DataType::FP4,
            DataType::NF4,
            DataType::Array { element_size: 16 },
            DataType::Handle(vyre_spec::data_type::TypeId(0xDEAD_BEEF)),
            DataType::Vec {
                element: Box::new(DataType::F32),
                count: 4,
            },
            DataType::TensorShaped {
                element: Box::new(DataType::F32),
                shape: smallvec![32, 32],
            },
            DataType::SparseCsr {
                element: Box::new(DataType::F32),
            },
            DataType::SparseCoo {
                element: Box::new(DataType::F32),
            },
            DataType::SparseBsr {
                element: Box::new(DataType::F32),
                block_rows: 8,
                block_cols: 8,
            },
            DataType::DeviceMesh {
                axes: smallvec![4, 8, 16],
            },
            DataType::Quantized {
                storage: Box::new(DataType::I4),
                scale: vyre_spec::QuantizationScale::PerGroup { group_size: 128 },
                zero_point: vyre_spec::QuantizationZeroPoint::Absent,
            },
            DataType::Quantized {
                storage: Box::new(DataType::I8),
                scale: vyre_spec::QuantizationScale::PerChannel { axis: 1 },
                zero_point: vyre_spec::QuantizationZeroPoint::PerChannel { axis: 1 },
            },
            // Extension ids must have the high bit set per
            // reject_reserved_extension_id (low half is reserved for core IR).
            DataType::Opaque(vyre_spec::extension::ExtensionDataTypeId(0x8000_0001)),
        ];

        for ty in &cases {
            let mut encoded = Vec::new();
            put_data_type(&mut encoded, ty)
                .unwrap_or_else(|e| panic!("encode {ty:?} failed: {e:?}"));
            let mut reader = Reader {
                bytes: &encoded,
                pos: 0,
                depth: 0,
            };
            let decoded = reader
                .data_type()
                .unwrap_or_else(|e| panic!("decode {ty:?} failed: {e}"));
            assert_eq!(
                &decoded, ty,
                "round-trip diverged for {ty:?}: re-decoded as {decoded:?}"
            );
            assert_eq!(
                reader.pos,
                encoded.len(),
                "encoder produced trailing bytes for {ty:?}"
            );
        }
    }
}
