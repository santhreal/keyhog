use crate::ir_inner::model::expr::{Expr, Ident};
use crate::ir_inner::model::types::AtomicOp;

impl Expr {
    /// Atomic-add builder: `buffer[index] = buffer[index].wrapping_add(value)`.
    #[must_use]
    pub fn atomic_add(buffer: &str, index: Expr, value: Expr) -> Expr {
        atomic(buffer, AtomicOp::Add, index, None, value)
    }

    /// Atomic bitwise OR builder.
    #[must_use]
    pub fn atomic_or(buffer: &str, index: Expr, value: Expr) -> Expr {
        atomic(buffer, AtomicOp::Or, index, None, value)
    }

    /// Atomic bitwise AND builder.
    #[must_use]
    pub fn atomic_and(buffer: &str, index: Expr, value: Expr) -> Expr {
        atomic(buffer, AtomicOp::And, index, None, value)
    }

    /// Atomic bitwise XOR builder.
    #[must_use]
    pub fn atomic_xor(buffer: &str, index: Expr, value: Expr) -> Expr {
        atomic(buffer, AtomicOp::Xor, index, None, value)
    }

    /// Atomic unsigned-min builder.
    #[must_use]
    pub fn atomic_min(buffer: &str, index: Expr, value: Expr) -> Expr {
        atomic(buffer, AtomicOp::Min, index, None, value)
    }

    /// Atomic unsigned-max builder.
    #[must_use]
    pub fn atomic_max(buffer: &str, index: Expr, value: Expr) -> Expr {
        atomic(buffer, AtomicOp::Max, index, None, value)
    }

    /// Atomic exchange builder: swap `buffer[index]` with `value`.
    #[must_use]
    pub fn atomic_exchange(buffer: &str, index: Expr, value: Expr) -> Expr {
        atomic(buffer, AtomicOp::Exchange, index, None, value)
    }

    /// Atomic compare-exchange builder.
    ///
    /// Writes `new_value` into `buffer[index]` iff the current value equals
    /// `expected`; returns the previous value in either case.
    #[must_use]
    pub fn atomic_compare_exchange(
        buffer: &str,
        index: Expr,
        expected: Expr,
        new_value: Expr,
    ) -> Expr {
        atomic(
            buffer,
            AtomicOp::CompareExchange,
            index,
            Some(expected),
            new_value,
        )
    }
}

fn atomic(buffer: &str, op: AtomicOp, index: Expr, expected: Option<Expr>, value: Expr) -> Expr {
    Expr::Atomic {
        op,
        buffer: Ident::from(buffer),
        index: Box::new(index),
        expected: expected.map(Box::new),
        value: Box::new(value),
    }
}
