use crate::ir_inner::model::expr::Expr;
use crate::ir_inner::model::types::{BinOp, UnOp};

impl Expr {
    /// `a ^ b`
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::bitxor(Expr::u32(0b1010), Expr::u32(0b1100));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn bitxor(left: Expr, right: Expr) -> Expr {
        Expr::BinOp {
            op: BinOp::BitXor,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// `a & b`
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::bitand(Expr::u32(0b1010), Expr::u32(0b1100));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn bitand(left: Expr, right: Expr) -> Expr {
        Expr::BinOp {
            op: BinOp::BitAnd,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// `a | b`
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::bitor(Expr::u32(0b1010), Expr::u32(0b1100));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn bitor(left: Expr, right: Expr) -> Expr {
        Expr::BinOp {
            op: BinOp::BitOr,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// `~a` (bitwise NOT)
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::bitnot(Expr::u32(0));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn bitnot(operand: Expr) -> Expr {
        Expr::UnOp {
            op: UnOp::BitNot,
            operand: Box::new(operand),
        }
    }

    /// `a << b`
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::shl(Expr::u32(1), Expr::u32(2));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn shl(left: Expr, right: Expr) -> Expr {
        Expr::BinOp {
            op: BinOp::Shl,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// `a >> b`
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::shr(Expr::u32(4), Expr::u32(1));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn shr(left: Expr, right: Expr) -> Expr {
        Expr::BinOp {
            op: BinOp::Shr,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// Reverse all 32 bits.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::reverse_bits(Expr::u32(1));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn reverse_bits(operand: Expr) -> Expr {
        Expr::UnOp {
            op: UnOp::ReverseBits,
            operand: Box::new(operand),
        }
    }

    /// `popcount(a)`
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::popcount(Expr::u32(0b1011));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn popcount(operand: Expr) -> Expr {
        Expr::UnOp {
            op: UnOp::Popcount,
            operand: Box::new(operand),
        }
    }

    /// `countLeadingZeros(a)`
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::clz(Expr::u32(1));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn clz(operand: Expr) -> Expr {
        Expr::UnOp {
            op: UnOp::Clz,
            operand: Box::new(operand),
        }
    }

    /// `countTrailingZeros(a)`
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Expr;
    /// let _ = Expr::ctz(Expr::u32(1));
    /// ```
    #[must_use]
    #[inline(always)]
    pub fn ctz(operand: Expr) -> Expr {
        Expr::UnOp {
            op: UnOp::Ctz,
            operand: Box::new(operand),
        }
    }
}
