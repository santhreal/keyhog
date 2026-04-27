use crate::rule::condition_op;
use vyre_foundation::ir::{Expr, Program};

/// File size equality condition operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct FileSizeEq;

impl FileSizeEq {
    /// Build the canonical IR program.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre_libs::rule::file_size_eq::FileSizeEq;
    ///
    /// assert!(!FileSizeEq::program().entry().is_empty());
    /// ```
    #[must_use]
    pub fn program() -> Program {
        condition_op::condition_program(OP_ID, || {
            Expr::eq(condition_op::file_size(), condition_op::threshold())
        })
    }
}

/// Stable operation id for file size equality checks.
pub const OP_ID: &str = "rule.file_size_eq";
