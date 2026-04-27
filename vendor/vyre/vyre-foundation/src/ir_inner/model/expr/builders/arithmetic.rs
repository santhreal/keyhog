use crate::ir_inner::model::expr::Expr;
use crate::ir_inner::model::types::{BinOp, UnOp};

impl Expr {
    /// `a + b`
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::add(Expr::u32(1), Expr::u32(2));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn add(left: Expr, right: Expr) -> Expr {
        Expr::BinOp {
            op: BinOp::Add,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// `a - b`
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::sub(Expr::u32(2), Expr::u32(1));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn sub(left: Expr, right: Expr) -> Expr {
        Expr::BinOp {
            op: BinOp::Sub,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// `a * b`
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::mul(Expr::u32(2), Expr::u32(3));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn mul(left: Expr, right: Expr) -> Expr {
        Expr::BinOp {
            op: BinOp::Mul,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// `a / b` (division, zero divisor returns 0)
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::div(Expr::u32(10), Expr::u32(2));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn div(left: Expr, right: Expr) -> Expr {
        Expr::BinOp {
            op: BinOp::Div,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// `a % b` (remainder, zero divisor returns 0)
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::rem(Expr::u32(10), Expr::u32(3));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn rem(left: Expr, right: Expr) -> Expr {
        Expr::BinOp {
            op: BinOp::Mod,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// Twos complement negation.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::negate(Expr::i32(1));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn negate(operand: Expr) -> Expr {
        Expr::UnOp {
            op: UnOp::Negate,
            operand: Box::new(operand),
        }
    }

    /// `abs_diff(a, b)` — unsigned absolute difference.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::abs_diff(Expr::u32(3), Expr::u32(5));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn abs_diff(left: Expr, right: Expr) -> Expr {
        Expr::BinOp {
            op: BinOp::AbsDiff,
            left: Box::new(left),
            right: Box::new(right),
        }
    }
    #[must_use]
    #[inline]
    /// Construct a wrapping addition node.
    pub fn wrapping_add(self, other: impl Into<Expr>) -> Self {
        Self::BinOp {
            op: BinOp::WrappingAdd,
            left: Box::new(self),
            right: Box::new(other.into()),
        }
    }

    #[must_use]
    #[inline]
    /// Construct a wrapping subtraction node.
    pub fn wrapping_sub(self, other: impl Into<Expr>) -> Self {
        Self::BinOp {
            op: BinOp::WrappingSub,
            left: Box::new(self),
            right: Box::new(other.into()),
        }
    }
}
