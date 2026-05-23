//! Attention sub-dialect: softmax + scaled dot-product + GQA + RoPE + MLA.
mod attention;
pub mod flash_attention;
pub mod flash_attention_2;
pub mod gqa_attention;
pub mod mla;
pub mod partial_rope;
pub mod qk_gain;
pub mod quest;
mod softmax;
pub mod turboquant;

pub use attention::{attention, attention_reference, try_attention_reference, Attention};
pub use flash_attention::flash_attention;
pub use flash_attention_2::{flash_attention_2, flash_attention_2_reference};
pub use gqa_attention::gqa_attention;
pub use mla::{mla_compress_kv, mla_decode};
pub use partial_rope::partial_rope;
pub use qk_gain::qk_gain;
pub use quest::quest_paging;
pub use softmax::{softmax, softmax_reference, Softmax};
pub use turboquant::turboquant_attention;
