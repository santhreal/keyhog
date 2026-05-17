use super::TypeKey;
use crate::ir::DataType;

impl From<DataType> for TypeKey {
    fn from(value: DataType) -> Self {
        Self::from(&value)
    }
}

impl From<&DataType> for TypeKey {
    fn from(value: &DataType) -> Self {
        match value {
            DataType::U32 => Self(0x01),
            DataType::I32 => Self(0x02),
            DataType::U64 => Self(0x03),
            DataType::Vec2U32 => Self(0x04),
            DataType::Vec4U32 => Self(0x05),
            DataType::Bool => Self(0x06),
            DataType::Bytes => Self(0x07),
            DataType::F16 => Self(0x09),
            DataType::BF16 => Self(0x0A),
            DataType::F32 => Self(0x0B),
            DataType::F64 => Self(0x0C),
            DataType::Tensor => Self(0x0D),
            DataType::U8 => Self(0x0E),
            DataType::U16 => Self(0x0F),
            DataType::I8 => Self(0x10),
            DataType::I16 => Self(0x11),
            DataType::I64 => Self(0x12),
            DataType::Array { element_size } => {
                Self(0x08 | (u64::try_from(*element_size).unwrap_or(u64::MAX) << 8))
            }
            DataType::Handle(id) => Self(0x13 | (u64::from(id.as_u32()) << 8)),
            DataType::Vec { element, count } => {
                Self(0x14 | (u64::from(*count) << 8) | (Self::from(element.as_ref()).0 << 16))
            }
            DataType::TensorShaped { .. } => Self(0x15),
            _ => Self(255),
        }
    }
}
