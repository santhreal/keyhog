use crate::EmitError;
use std::fmt;
use vyre_foundation::ir::DataType;

/// PTX scalar register classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PtxType {
    /// `.b16` register (`%h<N>`)  -  used for packed f16/bf16 memory values.
    B16,
    /// `.u32` register (`%r<N>`).
    U32,
    /// `.s32` register (`%s<N>`).
    I32,
    /// `.f32` register (`%f<N>`).
    F32,
    /// `.pred` register (`%p<N>`).
    Bool,
    /// `.u64` register (`%rd<N>`)  -  used for pointers.
    U64,
}

impl PtxType {
    pub(crate) fn ptx_type_str(self) -> &'static str {
        match self {
            Self::B16 => "b16",
            Self::U32 => "u32",
            Self::I32 => "s32",
            Self::F32 => "f32",
            Self::Bool => "pred",
            Self::U64 => "u64",
        }
    }

    pub(crate) fn reg_prefix(self) -> &'static str {
        match self {
            Self::B16 => "h",
            Self::U32 => "r",
            Self::I32 => "s",
            Self::F32 => "f",
            Self::Bool => "p",
            Self::U64 => "rd",
        }
    }

    pub(crate) fn from_dtype(dt: &DataType) -> Result<Self, EmitError> {
        match dt {
            DataType::Bool => Ok(Self::Bool),
            DataType::U8 | DataType::U16 | DataType::U32 | DataType::Bytes => Ok(Self::U32),
            DataType::I8 | DataType::I16 | DataType::I32 => Ok(Self::I32),
            DataType::F16 | DataType::BF16 | DataType::F32 => Ok(Self::F32),
            other => Err(EmitError::UnsupportedDataType(format!("{other:?}"))),
        }
    }
}

/// One named PTX register: a (type, index) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Reg(pub(crate) PtxType, pub(crate) u32);

impl fmt::Display for Reg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "%{}{}", self.0.reg_prefix(), self.1)
    }
}
