//! Linear-layer sub-dialect: affine transforms built on `math::linalg`.
mod inner;

pub use inner::{
    batch_matmul, linear, linear_4bit, linear_relu, linear_silu, linear_tiled,
    linear_tiled_reference, rms_norm_linear, try_rms_norm_linear, Linear,
};
