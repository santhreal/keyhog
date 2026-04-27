use crate::rule::condition_op;
use vyre_foundation::ir::{Expr, Program};

/// File size inequality condition operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct FileSizeNe;

impl FileSizeNe {
    /// Build the canonical IR program.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre_libs::rule::file_size_ne::FileSizeNe;
    ///
    /// assert!(!FileSizeNe::program().entry().is_empty());
    /// ```
    #[must_use]
    pub fn program() -> Program {
        condition_op::condition_program(OP_ID, || {
            Expr::ne(condition_op::file_size(), condition_op::threshold())
        })
    }
}

/// Stable operation id for file size inequality checks.
pub const OP_ID: &str = "rule.file_size_ne";
