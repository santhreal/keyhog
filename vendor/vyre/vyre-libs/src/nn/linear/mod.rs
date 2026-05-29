//! Linear-layer sub-dialect: affine transforms built on `math::linalg`.
mod inner;

pub use inner::{
    batch_matmul, linear, linear_relu, linear_silu, linear_tiled, linear_tiled_reference,
    rms_norm_linear, try_rms_norm_linear, Linear,
};
#[cfg(feature = "nn-linear-4bit")]
pub use inner::{
    linear_4bit, linear_4bit_affine_grouped, linear_4bit_affine_grouped_typed,
    QuantizedLinear4BitSpec,
};
