//! Linear-algebra sub-dialect: dot product, matmul, tiled matmul.
mod dot;
mod matmul;
mod matmul_tiled;

pub use dot::dot;
pub use matmul::{matmul, matmul_bias, Matmul, MatmulBias};
pub use matmul_tiled::{matmul_tiled, MatmulTiled};
