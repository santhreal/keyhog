//! Scope binding metadata for the IR validator.
//!
//! During validation the compiler maintains a symbol table that maps
//! variable names to their declared types and mutability. `Binding` is
//! the per-variable record stored in that table.

/// Default validation limits re-exported for convenience.
///
/// These constants bound the size and depth of programs that the
/// validator will accept.
pub use super::depth::{DEFAULT_MAX_CALL_DEPTH, DEFAULT_MAX_NESTING_DEPTH, DEFAULT_MAX_NODE_COUNT};
use crate::ir_inner::model::types::DataType;
use crate::validate::{err, ValidationError};
use rustc_hash::FxHashSet;

/// Scope binding: type, mutability, and workgroup-uniformity.
///
/// The validator uses `Binding` to track every live variable: its
/// `DataType` (for type-checking expressions), whether it was
/// declared as mutable (for assignment validation), and whether
/// it holds a value that is *uniform* across every invocation in
/// the same workgroup. The uniformity bit feeds the relaxed
/// barrier-placement rule: a `Node::Barrier` inside a `Node::Loop`
/// or `Node::If` is legal when the loop bounds (or `If` condition)
/// are uniform, because every invocation reaches the barrier
/// through the same iteration count and branch.
#[derive(Debug, Clone)]
pub(crate) struct Binding {
    /// Declared type of the variable.
    pub(crate) ty: DataType,
    /// Whether the variable can be reassigned.
    pub(crate) mutable: bool,
    /// Whether the variable is uniform across the workgroup.
    pub(crate) uniform: bool,
}

#[inline]
pub(crate) fn check_sibling_duplicate(
    name: &str,
    region_bindings: &mut FxHashSet<String>,
    errors: &mut Vec<ValidationError>,
) -> bool {
    if region_bindings.insert(name.to_string()) {
        return false;
    }
    errors.push(err(format!(
        "V032: duplicate sibling let binding `{name}` in the same region. Fix: rename one binding or move one declaration into an inner Block/Region/Loop if a new scope is intended."
    )));
    true
}
