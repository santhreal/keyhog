use crate::rule::condition_op;
use vyre_foundation::ir::{Expr, Program};

impl PatternCountGt {
    /// Build the canonical IR program.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre_libs::rule::pattern_count_gt::PatternCountGt;
    ///
    /// assert!(!PatternCountGt::program().entry().is_empty());
    /// ```
    #[must_use]
    pub fn program() -> Program {
        condition_op::condition_program(OP_ID, || {
            Expr::gt(condition_op::pattern_count(), condition_op::threshold())
        })
    }
}

/// Stable operation id for strict pattern count checks.
pub const OP_ID: &str = "rule.pattern_count_gt";

/// Pattern count greater-than condition operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct PatternCountGt;
