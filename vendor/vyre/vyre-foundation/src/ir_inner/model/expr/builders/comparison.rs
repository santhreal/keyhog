use crate::ir_inner::model::expr::Expr;
use crate::ir_inner::model::types::{BinOp, UnOp};

impl Expr {
    /// `a == b`
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::eq(Expr::u32(1), Expr::u32(1));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn eq(left: Expr, right: Expr) -> Expr {
        Expr::BinOp {
            op: BinOp::Eq,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// `a < b`
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::lt(Expr::u32(1), Expr::u32(2));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn lt(left: Expr, right: Expr) -> Expr {
        Expr::BinOp {
            op: BinOp::Lt,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// `a != b`
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::ne(Expr::u32(1), Expr::u32(2));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn ne(left: Expr, right: Expr) -> Expr {
        Expr::BinOp {
            op: BinOp::Ne,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// `a > b`
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::gt(Expr::u32(2), Expr::u32(1));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn gt(left: Expr, right: Expr) -> Expr {
        Expr::BinOp {
            op: BinOp::Gt,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// `a <= b`
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::le(Expr::u32(1), Expr::u32(2));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn le(left: Expr, right: Expr) -> Expr {
        Expr::BinOp {
            op: BinOp::Le,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// `a >= b`
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::ge(Expr::u32(2), Expr::u32(1));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn ge(left: Expr, right: Expr) -> Expr {
        Expr::BinOp {
            op: BinOp::Ge,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// Logical `a && b` over integer truth values.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::{BinOp, Expr};
    ///
    /// assert!(matches!(Expr::and(Expr::u32(1), Expr::u32(0)), Expr::BinOp { op: BinOp::And, .. }));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn and(left: Expr, right: Expr) -> Expr {
        Expr::BinOp {
            op: BinOp::And,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// Logical `a || b` over integer truth values.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::{BinOp, Expr};
    ///
    /// assert!(matches!(Expr::or(Expr::u32(1), Expr::u32(0)), Expr::BinOp { op: BinOp::Or, .. }));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn or(left: Expr, right: Expr) -> Expr {
        Expr::BinOp {
            op: BinOp::Or,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// `!a` (logical NOT)
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::not(Expr::bool(true));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn not(operand: Expr) -> Expr {
        Expr::UnOp {
            op: UnOp::LogicalNot,
            operand: Box::new(operand),
        }
    }

    /// `sin(a)` (f32).
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::sin(Expr::f32(0.0));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn sin(operand: Expr) -> Expr {
        Expr::UnOp {
            op: UnOp::Sin,
            operand: Box::new(operand),
        }
    }

    /// `cos(a)` (f32).
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::cos(Expr::f32(0.0));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn cos(operand: Expr) -> Expr {
        Expr::UnOp {
            op: UnOp::Cos,
            operand: Box::new(operand),
        }
    }

    /// `abs(a)` (f32).
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::abs(Expr::f32(-1.0));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn abs(operand: Expr) -> Expr {
        Expr::UnOp {
            op: UnOp::Abs,
            operand: Box::new(operand),
        }
    }

    /// `sqrt(a)` (f32).
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::sqrt(Expr::f32(4.0));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn sqrt(operand: Expr) -> Expr {
        Expr::UnOp {
            op: UnOp::Sqrt,
            operand: Box::new(operand),
        }
    }

    /// `inverseSqrt(a)` (f32).
    #[must_use]
    #[inline(always)]
    pub fn inverse_sqrt(operand: Expr) -> Expr {
        Expr::UnOp {
            op: UnOp::InverseSqrt,
            operand: Box::new(operand),
        }
    }
}
