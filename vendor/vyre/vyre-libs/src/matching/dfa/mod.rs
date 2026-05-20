//! DFA / Aho-Corasick sub-dialect: pre-built transition tables + scanner.
//!
//! Lives in this submodule and not at `matching/` root so the
//! organisation matches the conceptual hierarchy: every matcher in
//! this directory operates on a precomputed AC/DFA transition table,
//! and the haystack format every one of them expects is
//! [`crate::matching::dispatch_io::pack_haystack_u32`] (4 bytes per
//! u32 word). Don't reach back into `matching/` to add a new
//! DFA-family matcher — drop it in here next to its siblings.

pub mod classic_ac;
mod aho_corasick;
mod cooperative_dfa;
mod dfa_compile;

pub use aho_corasick::{aho_corasick, aho_corasick_bounded};
pub use cooperative_dfa::{cooperative_dfa_scan, cooperative_dfa_scan_body_with_store};
pub use dfa_compile::{
    dfa_compile, dfa_compile_with_budget, CompiledDfa, DfaCompileError, DEFAULT_DFA_BUDGET_BYTES,
};
