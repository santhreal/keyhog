//! Backend-owned lowering contracts.
//!
//! Core owns the stable lowering protocol only. Concrete target lowering
//! belongs to backend crates so frontend IR consumers do not link shader or
//! device-specific machinery.

use crate::ir_inner::model::types::DataType;
use std::{error::Error, fmt};

/// Error raised while progressively lowering a [`Program`] into a backend IR
/// and then into a concrete target artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweringError {
    message: String,
}

impl LoweringError {
    /// Construct an actionable lowering error.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        let message = message.into();
        debug_assert!(message.contains("Fix:"));
        Self { message }
    }

    /// Construct an invalid-program lowering error.
    #[must_use]
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(message)
    }

    /// Construct an unsupported-type lowering error.
    #[must_use]
    pub fn unsupported_type(data_type: &DataType) -> Self {
        Self::new(format!(
            "unsupported data type {data_type:?} for this lowering target. Fix: add target support or route the op to a backend that declares this type capability."
        ))
    }

    /// Construct an unsupported-operation lowering error.
    #[must_use]
    pub fn unsupported_op(op: impl fmt::Debug) -> Self {
        Self::new(format!(
            "unsupported operation {op:?} for this lowering target. Fix: add target lowering support or route the op to a backend that declares this operation capability."
        ))
    }

    /// Construct a Naga validation lowering error.
    #[must_use]
    pub fn validation(error: impl std::error::Error) -> Self {
        Self::new(format!(
            "naga validation failed: {error}\nSource: {:#?}\nFix: repair the backend lowering contract before dispatch.", error.source()
        ))
    }

    /// Construct a target writer lowering error.
    #[must_use]
    pub fn writer(error: impl fmt::Display) -> Self {
        Self::new(format!(
            "target writer failed: {error}. Fix: repair the backend writer integration."
        ))
    }

    /// Return the diagnostic message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for LoweringError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for LoweringError {}
