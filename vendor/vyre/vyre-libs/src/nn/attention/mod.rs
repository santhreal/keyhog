//! Attention sub-dialect: softmax + scaled dot-product attention.
mod attention;
pub mod quest;
mod softmax;
pub mod turboquant;

pub use attention::{attention, Attention};
pub use quest::quest_paging;
pub use softmax::{softmax, Softmax};
pub use turboquant::turboquant_attention;
