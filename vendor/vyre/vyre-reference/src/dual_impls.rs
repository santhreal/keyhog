//! Standalone primitive-operation CPU references.
#![allow(missing_docs)]

/// docs
pub mod arith;
#[path = "dual_impls/bitwise/mod.rs"]
/// docs
pub mod bitwise;
/// docs
pub mod common;
/// docs
pub mod compare;
/// docs
pub mod hash;
/// docs
pub mod memory;
/// docs
pub mod scan;
/// docs
pub mod workgroup;
pub use common::{EvalError, ReferenceEvaluator};
