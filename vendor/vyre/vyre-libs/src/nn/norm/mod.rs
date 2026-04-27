//! Normalization sub-dialect: LayerNorm and RMSNorm.
mod layer_norm;
mod rms_norm;

pub use layer_norm::{layer_norm, LayerNorm};
pub use rms_norm::rms_norm;
