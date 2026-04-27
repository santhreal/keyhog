//! Frozen IR data-type tags shared by signatures, validators, and wire metadata.
// TAG RESERVATIONS: U32=0x01, I32=0x02, U64=0x03, Vec2U32=0x04,
// Vec4U32=0x05, Bool=0x06, Bytes=0x07, Array=0x08, F16=0x09,
// BF16=0x0A, F32=0x0B, F64=0x0C, Tensor=0x0D, U8=0x0E, U16=0x0F,
// I8=0x10, I16=0x11, I64=0x12, Handle=0x13, Vec=0x14,
// TensorShaped=0x15, SparseCsr=0x16, SparseCoo=0x17, SparseBsr=0x18,
// F8E4M3=0x19, F8E5M2=0x1A, I4=0x1B, FP4=0x1C, NF4=0x1D,
// DeviceMesh=0x1E, 0x1F..=0x7F reserved, Opaque=0x80.

use core::fmt;

use crate::extension::ExtensionDataTypeId;

/// Stable handle type id for backend-owned GPU resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
pub struct TypeId(pub u32);

impl TypeId {
    /// Return the raw stable handle type id.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Canonical data types supported by the vyre IR frozen data contract.
///
/// Integer-first by design. GPU floating-point is nondeterministic across
/// vendors through different rounding, fused multiply-add, and subnormal
/// handling. Integer arithmetic is deterministic everywhere. F32 is supported
/// for primitives that require it, with conformance validated per-backend.
/// `vyre::ir::DataType` re-exports this same type; conformance metadata should
/// use this canonical contract path. Example: `DataType::Vec4U32` records a
/// four-word lane value and has a minimum byte width of 16.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
#[non_exhaustive]
pub enum DataType {
    /// Unsigned 8-bit integer.
    U8,
    /// Unsigned 16-bit integer.
    U16,
    /// Unsigned 32-bit integer. The fundamental GPU word.
    U32,
    /// Signed 8-bit integer.
    I8,
    /// Signed 16-bit integer.
    I16,
    /// Signed 32-bit integer.
    I32,
    /// Signed 64-bit integer.
    I64,
    /// Unsigned 64-bit integer, emulated as `vec2<u32>` with low and high words.
    U64,
    /// Two-component `u32` vector.
    Vec2U32,
    /// Four-component `u32` vector.
    Vec4U32,
    /// Boolean value stored as a GPU word.
    Bool,
    /// Variable-length byte buffer.
    Bytes,
    /// Fixed-element-size array.
    ///
    /// Each element is `element_size` bytes. The total byte count is
    /// `N * element_size` where N is encoded by the value.
    Array {
        /// Byte size of each element.
        element_size: usize,
    },
    /// Strict IEEE 754 binary16 floating-point.
    F16,
    /// Strict bfloat16 floating-point.
    BF16,
    /// IEEE 754 binary32 floating-point.
    F32,
    /// Strict IEEE 754 binary64 floating-point.
    F64,
    /// Multi-dimensional tensor value.
    Tensor,
    /// Opaque backend resource handle.
    Handle(TypeId),
    /// Generic fixed-lane vector.
    Vec {
        /// Lane element type.
        element: Box<Self>,
        /// Lane count.
        count: u8,
    },
    /// Tensor with explicit element type and rank-limited shape.
    TensorShaped {
        /// Tensor element type.
        element: Box<Self>,
        /// Tensor dimensions. Four dimensions stay inline.
        shape: smallvec::SmallVec<[u32; 4]>,
    },
    /// Sparse-CSR tensor: compressed sparse row layout. Element type
    /// lives in the dense values buffer; structure (indptr + `col_idx`)
    /// is laid out separately by the consumer per the documented CSR
    /// contract. Size depends on nnz; conservative sentinel applies.
    ///
    /// Wire encoding: tag `0x16` followed by the element type tag.
    SparseCsr {
        /// Element type of the dense values buffer.
        element: Box<Self>,
    },
    /// Sparse-COO tensor: coordinate-list layout with (row, col, val)
    /// triples. Simpler than CSR but less cache-friendly; lowering
    /// passes typically convert COO → CSR before dispatch.
    ///
    /// Wire encoding: tag `0x17` followed by the element type tag.
    SparseCoo {
        /// Element type of each triple's value.
        element: Box<Self>,
    },
    /// Sparse-BSR tensor: block-sparse rows with fixed block size.
    /// Favored by quantized LLM weight matrices (50%+ sparsity at
    /// block-granularity retains line-rate GEMM).
    ///
    /// Wire encoding: tag `0x18` followed by `block_rows u32`,
    /// `block_cols u32`, then the element type tag.
    SparseBsr {
        /// Element type.
        element: Box<Self>,
        /// Block height in elements.
        block_rows: u32,
        /// Block width in elements.
        block_cols: u32,
    },
    /// 8-bit float (E4M3 format, per FP8 spec) for quantized inference.
    F8E4M3,
    /// 8-bit float (E5M2 format, per FP8 spec) — wider range than E4M3.
    F8E5M2,
    /// 4-bit signed integer for aggressive LLM weight quantization.
    I4,
    /// 4-bit float (custom per NVIDIA FP4) for LLM-class inference.
    FP4,
    /// 4-bit "normal-float" (per `QLoRA` paper) for LLM weight compression.
    NF4,
    /// Device-mesh handle — topology identifier consumed by
    /// collective ops (`all_reduce`, `all_gather`, `reduce_scatter`,
    /// broadcast). Shape is informational; actual topology is
    /// resolved through the backend's mesh registry.
    DeviceMesh {
        /// Device count along each mesh axis. 1-D = pure ring/tree;
        /// 2-D = torus; higher-D = hypercube.
        axes: smallvec::SmallVec<[u32; 3]>,
    },
    /// Extension-declared data type.
    ///
    /// The `ExtensionDataTypeId` is stable across process runs and
    /// resolves to a `&'static dyn ExtensionDataType` via
    /// `vyre::dialect::extension::resolve_data_type` (in vyre-core).
    /// Wire encoding of Opaque is `0x80 ++ u32 extension_id` — see
    /// `docs/wire-format.md` §Extensions.
    ///
    /// The builtin const methods on `DataType` (`min_bytes`, `max_bytes`,
    /// `size_bytes`, `is_float_family`) return conservative sentinels for
    /// Opaque because the real values live behind the trait and are not
    /// known at compile time. Consumers that need the actual values
    /// should resolve the trait via the vyre-core registry.
    Opaque(ExtensionDataTypeId),
}

#[allow(clippy::match_same_arms)]
impl DataType {
    /// Minimum byte count to represent one value of this type.
    #[must_use]
    pub const fn min_bytes(&self) -> usize {
        match self {
            Self::U16 | Self::I16 | Self::F16 | Self::BF16 => 2,
            Self::Bool | Self::U32 | Self::I32 | Self::F32 | Self::Handle(_) => 4,
            Self::I64 | Self::U64 | Self::Vec2U32 | Self::F64 => 8,
            Self::Vec4U32 => 16,
            Self::Vec { element, count } => element.min_bytes() * (*count as usize),
            Self::Bytes | Self::Array { .. } | Self::Tensor | Self::TensorShaped { .. } => 0,
            // Quantized / compressed scalar families. F8/F4 = 1 byte rounded up;
            // I4 / NF4 = 1 byte rounded up (two values share a byte in practice,
            // but the conservative minimum is one byte per logical value).
            Self::U8
            | Self::I8
            | Self::F8E4M3
            | Self::F8E5M2
            | Self::I4
            | Self::FP4
            | Self::NF4 => 1,
            // Sparse layouts + device-mesh handles are unbounded at the
            // spec level; runtime asks the extension for a concrete size.
            Self::SparseCsr { .. } | Self::SparseCoo { .. } | Self::SparseBsr { .. } => 0,
            Self::DeviceMesh { .. } => 0,
            // Opaque: conservative sentinel. Real value via ExtensionDataType::min_bytes.
            Self::Opaque(_) => 0,
        }
    }

    /// Maximum byte count for one value of this type.
    ///
    /// Returns `None` for truly unbounded types; currently all variants
    /// have a hard ceiling. Fixed-width types return `Some(min_bytes())`.
    #[must_use]
    pub const fn max_bytes(&self) -> Option<usize> {
        match self {
            Self::U8 | Self::I8 => Some(1),
            Self::U16 | Self::I16 | Self::F16 | Self::BF16 => Some(2),
            Self::U32 | Self::I32 | Self::Bool => Some(4),
            Self::I64 | Self::U64 | Self::Vec2U32 | Self::F64 => Some(8),
            Self::Vec4U32 => Some(16),
            Self::F32 => Some(4),
            Self::Handle(_) => Some(4),
            Self::Vec { element, count } => match element.max_bytes() {
                Some(bytes) => Some(bytes * (*count as usize)),
                None => None,
            },
            Self::Bytes => Some(64 * 1024 * 1024),
            Self::Array { .. } | Self::Tensor => Some(256 * 1024 * 1024),
            Self::TensorShaped { .. } => None,
            Self::F8E4M3 | Self::F8E5M2 => Some(1),
            Self::I4 | Self::FP4 | Self::NF4 => Some(1),
            Self::SparseCsr { .. } | Self::SparseCoo { .. } | Self::SparseBsr { .. } => None,
            Self::DeviceMesh { .. } => Some(4),
            // Opaque: unbounded at the spec level. Real ceiling via ExtensionDataType::max_bytes.
            Self::Opaque(_) => None,
        }
    }

    /// Element size for array-typed outputs, or `None` for scalar types.
    #[must_use]
    pub const fn element_size(&self) -> Option<usize> {
        match self {
            Self::Array { element_size } => Some(*element_size),
            Self::Vec { element, .. }
            | Self::TensorShaped { element, .. }
            | Self::SparseCsr { element }
            | Self::SparseCoo { element }
            | Self::SparseBsr { element, .. } => element.size_bytes(),
            Self::Opaque(_) => None,
            _ => None,
        }
    }

    /// Fixed scalar element size in bytes, or `None` for variable-size types.
    ///
    /// Scalar types return their natural width (`U32` → `Some(4)`, `Vec4U32` →
    /// `Some(16)`). `Bytes` returns `Some(1)` because each element is one byte.
    /// `Array` returns `Some(element_size)`. `Tensor` returns `None` because it
    /// has no fixed per-element size.
    #[must_use]
    pub const fn size_bytes(&self) -> Option<usize> {
        match self {
            Self::U8 | Self::I8 => Some(1),
            Self::U16 | Self::I16 | Self::F16 | Self::BF16 => Some(2),
            Self::Bool | Self::U32 | Self::I32 | Self::F32 => Some(4),
            Self::I64 | Self::U64 | Self::Vec2U32 | Self::F64 => Some(8),
            Self::Vec4U32 => Some(16),
            Self::Handle(_) => Some(4),
            Self::Bytes => Some(1),
            Self::Array { element_size } => Some(*element_size),
            Self::Vec { element, count } => match element.size_bytes() {
                Some(bytes) => Some(bytes * (*count as usize)),
                None => None,
            },
            Self::Tensor | Self::TensorShaped { .. } => None,
            Self::F8E4M3 | Self::F8E5M2 => Some(1),
            Self::I4 | Self::FP4 | Self::NF4 => Some(1),
            Self::SparseCsr { .. } | Self::SparseCoo { .. } | Self::SparseBsr { .. } => None,
            Self::DeviceMesh { .. } => Some(4),
            // Opaque: real size via ExtensionDataType::size_bytes (runtime).
            Self::Opaque(_) => None,
        }
    }

    /// Whether this type belongs to the strict floating-point conformance family.
    #[must_use]
    pub const fn is_float_family(&self) -> bool {
        match self {
            Self::F16 | Self::BF16 | Self::F32 | Self::F64 => true,
            Self::F8E4M3 | Self::F8E5M2 | Self::FP4 | Self::NF4 => true,
            Self::Vec { element, .. }
            | Self::TensorShaped { element, .. }
            | Self::SparseCsr { element }
            | Self::SparseCoo { element }
            | Self::SparseBsr { element, .. } => element.is_float_family(),
            _ => false,
        }
    }
}

impl fmt::Display for DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::U8 => f.write_str("u8"),
            Self::U16 => f.write_str("u16"),
            Self::U32 => f.write_str("u32"),
            Self::I8 => f.write_str("i8"),
            Self::I16 => f.write_str("i16"),
            Self::I32 => f.write_str("i32"),
            Self::I64 => f.write_str("i64"),
            Self::U64 => f.write_str("u64"),
            Self::Vec2U32 => f.write_str("vec2<u32>"),
            Self::Vec4U32 => f.write_str("vec4<u32>"),
            Self::Bool => f.write_str("bool"),
            Self::Bytes => f.write_str("bytes"),
            Self::Array { element_size } => write!(f, "array<{element_size}B>"),
            Self::F16 => f.write_str("f16"),
            Self::BF16 => f.write_str("bf16"),
            Self::F32 => f.write_str("f32"),
            Self::F64 => f.write_str("f64"),
            Self::Tensor => f.write_str("tensor"),
            Self::Handle(id) => write!(f, "handle<{:#010x}>", id.as_u32()),
            Self::Vec { element, count } => write!(f, "vec<{element};{count}>"),
            Self::TensorShaped { element, shape } => {
                write!(f, "tensor<{element};")?;
                for (idx, dim) in shape.iter().enumerate() {
                    if idx > 0 {
                        f.write_str("x")?;
                    }
                    write!(f, "{dim}")?;
                }
                f.write_str(">")
            }
            Self::Opaque(id) => write!(f, "opaque<{:#010x}>", id.as_u32()),
            Self::F8E4M3 => f.write_str("f8e4m3"),
            Self::F8E5M2 => f.write_str("f8e5m2"),
            Self::I4 => f.write_str("i4"),
            Self::FP4 => f.write_str("fp4"),
            Self::NF4 => f.write_str("nf4"),
            Self::SparseCsr { element } => write!(f, "sparse_csr<{element}>"),
            Self::SparseCoo { element } => write!(f, "sparse_coo<{element}>"),
            Self::SparseBsr {
                element,
                block_rows,
                block_cols,
            } => write!(f, "sparse_bsr<{element};{block_rows}x{block_cols}>"),
            Self::DeviceMesh { axes } => {
                f.write_str("device_mesh<")?;
                for (i, a) in axes.iter().enumerate() {
                    if i > 0 {
                        f.write_str("x")?;
                    }
                    write!(f, "{a}")?;
                }
                f.write_str(">")
            }
        }
    }
}
