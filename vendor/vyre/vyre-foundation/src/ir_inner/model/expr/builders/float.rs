use crate::ir_inner::model::expr::Expr;
use crate::ir_inner::model::types::{BinOp, UnOp};

impl Expr {
    /// `min(a, b)` (f32).
    #[must_use]
    #[inline(always)]
    pub fn min(left: Expr, right: Expr) -> Expr {
        Expr::BinOp {
            op: BinOp::Min,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// `max(a, b)` (f32).
    #[must_use]
    #[inline(always)]
    pub fn max(left: Expr, right: Expr) -> Expr {
        Expr::BinOp {
            op: BinOp::Max,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// `floor(a)` (f32).
    #[must_use]
    #[inline(always)]
    pub fn floor(operand: Expr) -> Expr {
        Expr::UnOp {
            op: UnOp::Floor,
            operand: Box::new(operand),
        }
    }

    /// `ceil(a)` (f32).
    #[must_use]
    #[inline(always)]
    pub fn ceil(operand: Expr) -> Expr {
        Expr::UnOp {
            op: UnOp::Ceil,
            operand: Box::new(operand),
        }
    }

    /// `round(a)` (f32).
    #[must_use]
    #[inline(always)]
    pub fn round(operand: Expr) -> Expr {
        Expr::UnOp {
            op: UnOp::Round,
            operand: Box::new(operand),
        }
    }

    /// `trunc(a)` (f32).
    #[must_use]
    #[inline(always)]
    pub fn trunc(operand: Expr) -> Expr {
        Expr::UnOp {
            op: UnOp::Trunc,
            operand: Box::new(operand),
        }
    }

    /// `sign(a)` (f32).
    #[must_use]
    #[inline(always)]
    pub fn sign(operand: Expr) -> Expr {
        Expr::UnOp {
            op: UnOp::Sign,
            operand: Box::new(operand),
        }
    }

    /// `isNan(a)` (f32) -> bool-as-u32.
    #[must_use]
    #[inline(always)]
    pub fn is_nan(operand: Expr) -> Expr {
        Expr::UnOp {
            op: UnOp::IsNan,
            operand: Box::new(operand),
        }
    }

    /// `isInf(a)` (f32) -> bool-as-u32.
    #[must_use]
    #[inline(always)]
    pub fn is_inf(operand: Expr) -> Expr {
        Expr::UnOp {
            op: UnOp::IsInf,
            operand: Box::new(operand),
        }
    }

    /// `isFinite(a)` (f32) -> bool-as-u32.
    #[must_use]
    #[inline(always)]
    pub fn is_finite(operand: Expr) -> Expr {
        Expr::UnOp {
            op: UnOp::IsFinite,
            operand: Box::new(operand),
        }
    }
}
