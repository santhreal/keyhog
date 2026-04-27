//! # surgec-grammar-gen
//!
//! Host-side C11 grammar table generator for the vyre GPU C parser.
//! Produces DFA lexer + LR(1) action/goto tables as binary blobs that
//! `vyre-libs::parsing` loads as ReadOnly storage buffers.
//!
//! See `README.md` for the pipeline and binary-blob wire format.

#![warn(missing_docs)]

pub mod c11_lexer;
pub mod chunk_lexer_cpu;
pub mod dfa;
pub mod host_preprocess;
pub mod lex_c11_max_munch;
pub mod lr;
pub mod max_munch_cpu;
pub mod wire;

pub use c11_lexer::{build_c11_lexer_dfa, build_c11_lexer_dfa_for_host, C11_PATTERNS};
pub use chunk_lexer_cpu::count_chunked_valid_tokens;
pub use dfa::{DfaBuilder, DfaTable};
pub use host_preprocess::preprocess_c_host;
pub use lex_c11_max_munch::lex_c11_max_munch_kinds;
pub use lr::{LrBuilder, LrTable};
pub use max_munch_cpu::{kinds_blake3, LexCpuError};
pub use wire::{decode_dfa_from_bytes, decode_lr_from_bytes, BlobKind, PackedBlob, WireError};
