//! C semantic analysis passes.
//!
//! Currently ships scope-tree extraction from structural tokens.

/// Identifier interning IR fragments.
pub mod intern;
/// Declaration lookup IR fragments.
pub mod lookup;
/// Registered C semantic-analysis programs.
pub mod registry;
/// Scope-walk IR fragments.
pub mod walk;

pub use registry::{c_sema_scope, reference_scope_tree};
