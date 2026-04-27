use crate::rule::condition_op;
use vyre_foundation::ir::{Expr, Program};

/// File size less-than-or-equal condition operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct FileSizeLte;

impl FileSizeLte {
    /// Build the canonical IR program.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre_libs::rule::file_size_lte::FileSizeLte;
    ///
    /// assert!(!FileSizeLte::program().entry().is_empty());
    /// ```
    #[must_use]
    pub fn program() -> Program {
        condition_op::condition_program(OP_ID, || {
            Expr::le(condition_op::file_size(), condition_op::threshold())
        })
    }
}

/// Stable operation id for inclusive upper file size checks.
pub const OP_ID: &str = "rule.file_size_lte";
