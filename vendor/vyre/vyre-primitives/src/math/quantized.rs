//! Quantized packing primitives.
//!
//! This module gives the spec-level `I4`/quantized type family executable
//! behavior: signed INT4 lanes are packed two per byte in a u32 word stream.
//! GPU kernels operate on u32 storage words so each word carries eight signed
//! 4-bit values.

mod cpu;
mod program_helpers;
mod programs;
#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "cpu-parity"))]
pub use cpu::{
    i4x8_batched_matmul_f32_scaled_cpu, i4x8_batched_matmul_top1_f32_scaled_cpu,
    i4x8_batched_matvec_f32_scaled_cpu, i4x8_dot_f32_scaled_cpu, i4x8_dot_i32_cpu,
    i4x8_matvec_f32_scaled_cpu, try_unpack_i4x8_cpu_into, unpack_i4x8_cpu, unpack_i4x8_cpu_into,
};
pub use cpu::{pack_i4x8_cpu, pack_i4x8_cpu_into, try_pack_i4x8_cpu_into};
pub use programs::{
    i4x8_batched_matmul_f32_scaled, i4x8_batched_matmul_top1_f32_scaled,
    i4x8_batched_matvec_f32_scaled, i4x8_dot_f32_scaled, i4x8_dot_i32, i4x8_matvec_f32_scaled,
    unpack_i4x8,
};

/// Canonical op id for packed signed INT4 unpacking.
pub const UNPACK_I4_OP_ID: &str = "vyre-primitives::math::quantized::unpack_i4x8";

/// Canonical op id for packed signed INT4 dot products.
pub const I4_DOT_I32_OP_ID: &str = "vyre-primitives::math::quantized::i4x8_dot_i32";

/// Canonical op id for fused scaled packed signed INT4 dot products.
pub const I4_DOT_F32_SCALED_OP_ID: &str = "vyre-primitives::math::quantized::i4x8_dot_f32_scaled";

/// Canonical op id for fused scaled packed signed INT4 matrix-vector products.
pub const I4_MATVEC_F32_SCALED_OP_ID: &str =
    "vyre-primitives::math::quantized::i4x8_matvec_f32_scaled";

/// Canonical op id for batched fused scaled packed signed INT4 matvec.
pub const I4_BATCHED_MATVEC_F32_SCALED_OP_ID: &str =
    "vyre-primitives::math::quantized::i4x8_batched_matvec_f32_scaled";

/// Canonical op id for batched fused scaled packed signed INT4 matmul.
pub const I4_BATCHED_MATMUL_F32_SCALED_OP_ID: &str =
    "vyre-primitives::math::quantized::i4x8_batched_matmul_f32_scaled";

/// Canonical op id for fused packed signed INT4 batched matmul top-1 routing.
pub const I4_BATCHED_MATMUL_TOP1_F32_SCALED_OP_ID: &str =
    "vyre-primitives::math::quantized::i4x8_batched_matmul_top1_f32_scaled";

/// Number of signed 4-bit lanes per packed u32 word.
pub const I4_LANES_PER_WORD: u32 = 8;

/// Number of packed signed INT4 words required for `lane_count` lanes.
#[must_use]
pub const fn i4_packed_words(lane_count: u32) -> u32 {
    lane_count.div_ceil(I4_LANES_PER_WORD)
}
