//! Runtime values accepted and returned by the core reference interpreter.

use std::sync::Arc;

/// A concrete value passed into or returned from the reference interpreter.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Value {
    /// Unsigned 32-bit integer.
    U32(u32),
    /// Signed 32-bit integer.
    I32(i32),
    /// Unsigned 64-bit integer.
    U64(u64),
    /// Boolean value.
    Bool(bool),
    /// Raw little-endian storage bytes.
    Bytes(Arc<[u8]>),
    /// Floating-point value represented with stable host bits.
    Float(f64),
    /// Fixed-size array of values.
    Array(Vec<Value>),
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::U32(a), Self::U32(b)) => a == b,
            (Self::I32(a), Self::I32(b)) => a == b,
            (Self::U64(a), Self::U64(b)) => a == b,
            (Self::Bool(a), Self::Bool(b)) => a == b,
            (Self::Bytes(a), Self::Bytes(b)) => a == b,
            (Self::Float(a), Self::Float(b)) => a.to_bits() == b.to_bits(),
            (Self::Array(a), Self::Array(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for Value {}

impl Value {
    /// Interpret the value using the IR truth convention.
    #[must_use]
    pub fn truthy(&self) -> bool {
        match self {
            Self::Array(values) => !values.is_empty(),
            Self::Float(value) => *value != 0.0,
            _ => self.try_as_u32().unwrap_or(1) != 0,
        }
    }

    /// Return this value as little-endian bytes for buffer initialization.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::U32(value) => value.to_le_bytes().to_vec(),
            Self::I32(value) => value.to_le_bytes().to_vec(),
            Self::U64(value) => value.to_le_bytes().to_vec(),
            Self::Bool(value) => u32::from(*value).to_le_bytes().to_vec(),
            Self::Bytes(bytes) => bytes.to_vec(),
            Self::Float(value) => value.to_le_bytes().to_vec(),
            Self::Array(values) => values.iter().flat_map(Self::to_bytes).collect(),
        }
    }

    /// Return this value encoded at the declared input width.
    #[must_use]
    pub fn to_bytes_width(&self, declared_width: usize) -> Vec<u8> {
        let mut bytes = self.to_bytes();
        if declared_width == 0 {
            return bytes;
        }
        bytes.resize(declared_width, 0);
        bytes.truncate(declared_width);
        bytes
    }

    /// Try to interpret the value as the IR's scalar `u32` word.
    #[must_use]
    pub fn try_as_u32(&self) -> Option<u32> {
        match self {
            Self::U32(value) => Some(*value),
            Self::I32(value) => u32::try_from(*value).ok(),
            Self::U64(value) => u32::try_from(*value).ok(),
            Self::Bool(value) => Some(u32::from(*value)),
            Self::Bytes(bytes) => (bytes.len() <= 4).then(|| read_u32_prefix(bytes)),
            Self::Float(value) => Some(*value as u32),
            Self::Array(_) => None,
        }
    }

    /// Interpret the value as the IR's scalar `u32` word.
    #[must_use]
    pub fn as_u32(&self) -> u32 {
        self.try_as_u32().unwrap_or(0)
    }

    /// Try to interpret the value as a full `u64`.
    #[must_use]
    pub fn try_as_u64(&self) -> Option<u64> {
        match self {
            Self::U32(value) => Some(u64::from(*value)),
            Self::I32(value) => u64::try_from(*value).ok(),
            Self::U64(value) => Some(*value),
            Self::Bool(value) => Some(u64::from(*value)),
            Self::Bytes(bytes) => (bytes.len() <= 8).then(|| read_u64_prefix(bytes)),
            Self::Float(value) => Some(*value as u64),
            Self::Array(_) => None,
        }
    }

    /// Interpret the value as a full `u64`.
    #[must_use]
    pub fn as_u64(&self) -> u64 {
        self.try_as_u64().unwrap_or(0)
    }

    /// Try to interpret the value as an `f32`.
    #[must_use]
    pub fn try_as_f32(&self) -> Option<f32> {
        match self {
            Self::Float(value) => Some(*value as f32),
            Self::U32(value) => Some(f32::from_bits(*value)),
            _ => None,
        }
    }

    /// Return the full value payload as little-endian bytes.
    #[must_use]
    pub fn wide_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }

    /// Create a zero value for the given data type.
    #[must_use]
    pub fn zero_for(ty: vyre::ir::DataType) -> Self {
        Self::try_zero_for(ty).unwrap_or_else(|| Self::Bytes(Arc::from([])))
    }

    /// Try to create a zero value for the given data type.
    #[must_use]
    pub fn try_zero_for(ty: vyre::ir::DataType) -> Option<Self> {
        match ty {
            vyre::ir::DataType::U32 => Some(Self::U32(0)),
            vyre::ir::DataType::I32 => Some(Self::I32(0)),
            vyre::ir::DataType::U64 => Some(Self::U64(0)),
            vyre::ir::DataType::Bool => Some(Self::Bool(false)),
            vyre::ir::DataType::Bytes => Some(Self::Bytes(Arc::from([]))),
            vyre::ir::DataType::F32 => Some(Self::Float(0.0)),
            vyre::ir::DataType::Vec2U32 => Some(Self::Bytes(Arc::from(vec![0; 8]))),
            vyre::ir::DataType::Vec4U32 => Some(Self::Bytes(Arc::from(vec![0; 16]))),
            _ => None,
        }
    }

    /// Create a value from element bytes for the given data type.
    ///
    /// # Errors
    ///
    /// Returns an error if the byte slice is too short for the declared type.
    pub fn from_element_bytes(ty: vyre::ir::DataType, bytes: &[u8]) -> Result<Self, String> {
        match ty {
            vyre::ir::DataType::U32 => {
                if bytes.len() < 4 {
                    return Err("u32 requires 4 bytes".to_string());
                }
                Ok(Self::U32(u32::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                ])))
            }
            vyre::ir::DataType::I32 => {
                if bytes.len() < 4 {
                    return Err("i32 requires 4 bytes".to_string());
                }
                Ok(Self::I32(i32::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                ])))
            }
            vyre::ir::DataType::U64 => {
                if bytes.len() < 8 {
                    return Err("u64 requires 8 bytes".to_string());
                }
                Ok(Self::U64(u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ])))
            }
            vyre::ir::DataType::Bool => {
                if bytes.len() < 4 {
                    return Err("bool requires 4 bytes".to_string());
                }
                Ok(Self::Bool(
                    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) != 0,
                ))
            }
            vyre::ir::DataType::Vec2U32 => {
                if bytes.len() < 8 {
                    return Err("vec2u32 requires 8 bytes".to_string());
                }
                Ok(Self::Bytes(Arc::from(&bytes[..8])))
            }
            vyre::ir::DataType::Vec4U32 => {
                if bytes.len() < 16 {
                    return Err("vec4u32 requires 16 bytes".to_string());
                }
                Ok(Self::Bytes(Arc::from(&bytes[..16])))
            }
            vyre::ir::DataType::F32 => {
                if bytes.len() < 4 {
                    return Err("f32 requires 4 bytes".to_string());
                }
                Ok(Self::Float(f64::from(f32::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                ]))))
            }
            vyre::ir::DataType::Bytes => Ok(Self::Bytes(Arc::from(bytes))),
            _ => Ok(Self::Bytes(Arc::from(bytes))),
        }
    }
}

impl From<Vec<u8>> for Value {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Bytes(Arc::from(bytes))
    }
}

impl From<&[u8]> for Value {
    fn from(bytes: &[u8]) -> Self {
        Self::Bytes(Arc::from(bytes))
    }
}

fn read_u32_prefix(bytes: &[u8]) -> u32 {
    let mut padded = [0u8; 4];
    let len = bytes.len().min(4);
    padded[..len].copy_from_slice(&bytes[..len]);
    u32::from_le_bytes(padded)
}

fn read_u64_prefix(bytes: &[u8]) -> u64 {
    let mut padded = [0u8; 8];
    let len = bytes.len().min(8);
    padded[..len].copy_from_slice(&bytes[..len]);
    u64::from_le_bytes(padded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn neg_zero_truthiness_is_false() {
        assert!(!Value::Float(-0.0).truthy());
    }

    #[test]
    fn pos_zero_truthiness_is_false() {
        assert!(!Value::Float(0.0).truthy());
    }

    #[test]
    fn nonzero_float_truthiness_is_true() {
        assert!(Value::Float(1.0).truthy());
        assert!(Value::Float(-1.0).truthy());
        assert!(Value::Float(f64::INFINITY).truthy());
        assert!(Value::Float(f64::NEG_INFINITY).truthy());
    }

    proptest! {
        #[test]
        fn neg_zero_select_branches_to_false(
            positive_sign in proptest::bool::ANY,
        ) {
            let zero = if positive_sign { 0.0_f64 } else { -0.0_f64 };
            prop_assert!(!Value::Float(zero).truthy(),
                "Value::Float({zero}).truthy() must be false to match WGSL bool(0.0)/bool(-0.0) semantics");
        }
    }
}
