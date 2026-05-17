//! Audit-fix A35 split expansion.rs (3187 LOC) into per-pass files.
//!
//! Each preprocessor expansion pass lives in its own file under
//! `expansion/`. The shared imports + magic constants stay here in
//! `mod.rs`.

pub(super) const EMPTY_MACRO_SLOT: u32 = u32::MAX;
pub(super) const MACRO_TABLE_SLOTS: u32 = 1024;
pub(super) const MACRO_TABLE_MASK: u32 = MACRO_TABLE_SLOTS - 1;
pub(super) const FNV1A32_OFFSET: u32 = 0x811c_9dc5;
pub(super) const FNV1A32_PRIME: u32 = 0x0100_0193;
pub(super) const MACRO_NAME_BYTES: u32 = 4096;

/// Object-like C macro table kind for `opt_named_macro_expansion`.
pub const C_MACRO_KIND_OBJECT_LIKE: u32 = 0;
/// Function-like C macro table kind for `opt_named_macro_expansion`.
pub const C_MACRO_KIND_FUNCTION_LIKE: u32 = 1;
/// Replacement parameter marker meaning this replacement token is literal.
pub const C_MACRO_REPLACEMENT_LITERAL: u32 = u32::MAX;

mod arg_scan;
mod conditional;
mod dynamic_pass;
mod fnlike;
mod fnlike_mat;
mod helpers;
mod named;
mod named_mat;
mod objlike;
mod objlike_mat;
mod paste_branch;
mod regular_branch;
mod string_branch;

pub use conditional::{opt_conditional_mask, opt_conditional_mask_with_directives};
pub use dynamic_pass::opt_dynamic_macro_expansion;
pub use named::opt_named_macro_expansion;
pub use named_mat::opt_named_macro_expansion_materialized;

// Re-exports so sibling modules can `use super::*` and reach every
// helper that A35 split out into per-pass files. Without this each
// child has to enumerate `use super::{fnlike::*, fnlike_mat::*, ...}`
// and the build-graph fragility shows up as the c-parser feature
// errors that follow A35.
