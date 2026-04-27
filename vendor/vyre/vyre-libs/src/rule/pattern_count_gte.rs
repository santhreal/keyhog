use crate::rule::condition_op;
use vyre_foundation::ir::{Expr, Program};

impl PatternCountGte {
    /// Build the canonical IR program.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre_libs::rule::pattern_count_gte::PatternCountGte;
    ///
    /// assert!(!PatternCountGte::program().entry().is_empty());
    /// ```
    #[must_use]
    pub fn program() -> Program {
        condition_op::condition_program(OP_ID, || {
            Expr::ge(condition_op::pattern_count(), condition_op::threshold())
        })
    }
}

/// Stable operation id for inclusive pattern count checks.
pub const OP_ID: &str = "rule.pattern_count_gte";

/// Pattern count greater-than-or-equal condition operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct PatternCountGte;
