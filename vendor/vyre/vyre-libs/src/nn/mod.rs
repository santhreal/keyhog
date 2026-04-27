//! Neural-net primitives — activation, linear, normalization, attention.
//! Each function is a Category-A composition over vyre-ops primitives
//! and lower-level `vyre-libs::math` functions.
//!
//! Organized into sub-dialects:
//! - `activation` — ReLU (future: gelu, silu, tanh, sigmoid)
//! - `linear` — affine linear layer
//! - `norm` — LayerNorm (future: rmsnorm, batchnorm, groupnorm)
//! - `attention` — softmax, scaled_dot_product_attention
//!
//! Flat re-exports preserve the pre-0.6 API surface.

#[cfg(feature = "nn-activation")]
pub mod activation;

#[cfg(feature = "nn-linear")]
pub mod linear;

#[cfg(feature = "nn-norm")]
pub mod norm;

#[cfg(feature = "nn-attention")]
pub mod attention;

#[cfg(feature = "nn-moe")]
pub mod moe;

// Flat re-exports for back-compat.
#[cfg(feature = "nn-activation")]
pub use activation::relu;
#[cfg(feature = "nn-attention")]
pub use attention::{attention, softmax, Attention, Softmax};
#[cfg(feature = "nn-linear")]
pub use linear::{linear, linear_relu};
#[cfg(feature = "nn-norm")]
pub use norm::{layer_norm, LayerNorm};
