//! Quantization sub-dialect for Parameter Golf recipe.
//!
//! Contains int6/int8 pack/unpack, byte shuffle, and GPTQ-SDClip
//! ops needed for the 16MB parameter budget constraint.
pub mod byte_shuffle;
pub mod gptq;
pub mod int6;
pub mod int8;

pub use byte_shuffle::byte_shuffle;
pub use gptq::{gptq_round, gptq_sdclip};
pub use int6::{int6_pack, int6_unpack};
pub use int8::{int8_pack, int8_unpack};
