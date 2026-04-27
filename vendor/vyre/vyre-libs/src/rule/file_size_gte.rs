use crate::rule::condition_op;
use vyre_foundation::ir::{Expr, Program};

/// File size greater-than-or-equal condition operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct FileSizeGte;

impl FileSizeGte {
    /// Build the canonical IR program.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre_libs::rule::file_size_gte::FileSizeGte;
    ///
    /// assert!(!FileSizeGte::program().entry().is_empty());
    /// ```
    #[must_use]
    pub fn program() -> Program {
        condition_op::condition_program(OP_ID, || {
            Expr::ge(condition_op::file_size(), condition_op::threshold())
        })
    }
}

/// Stable operation id for inclusive lower file size checks.
pub const OP_ID: &str = "rule.file_size_gte";
