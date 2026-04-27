use crate::rule::condition_op;
use vyre_foundation::ir::{Expr, Program};
use vyre_spec::OperationContract;

/// File size greater-than condition operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct FileSizeGt;

impl FileSizeGt {
    /// Build the canonical IR program.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre_libs::rule::file_size_gt::FileSizeGt;
    ///
    /// assert!(!FileSizeGt::program().entry().is_empty());
    /// ```
    #[must_use]
    pub fn program() -> Program {
        condition_op::condition_program(OP_ID, || {
            Expr::gt(condition_op::file_size(), condition_op::threshold())
        })
    }
}

/// Stable operation id for strict lower file size checks.
pub const OP_ID: &str = "rule.file_size_gt";

/// Execution contract annotation for the standard catalog.
pub const CONTRACT: OperationContract = crate::contracts::RULE_PREDICATE_CHEAP;
