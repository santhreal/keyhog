use crate::rule::condition_op;
use vyre_foundation::ir::{Expr, Program};

/// File size less-than condition operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct FileSizeLt;

impl FileSizeLt {
    /// Build the canonical IR program.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre_libs::rule::file_size_lt::FileSizeLt;
    ///
    /// assert!(!FileSizeLt::program().entry().is_empty());
    /// ```
    #[must_use]
    pub fn program() -> Program {
        condition_op::condition_program(OP_ID, || {
            Expr::lt(condition_op::file_size(), condition_op::threshold())
        })
    }
}

/// Stable operation id for strict upper file size checks.
pub const OP_ID: &str = "rule.file_size_lt";
