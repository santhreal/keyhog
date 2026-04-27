//! Linear-layer sub-dialect: affine transforms built on `math::linalg`.
mod linear;

pub use linear::{linear, linear_relu, rms_norm_linear};
