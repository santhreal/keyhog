//! Mixture-of-Experts (MoE) sub-dialect.
pub mod gating;
pub mod top_k;

pub use gating::moe_gate;
pub use top_k::top_k;
