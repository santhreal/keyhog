use super::ops::{binary, unary};
use crate::ir_inner::model::expr::Expr;
use crate::ir_inner::model::types::{BinOp, UnOp};

macro_rules! binary_builders {
    ($($(#[$meta:meta])* $name:ident => $op:expr;)*) => {
        $(
            $(#[$meta])*
            #[must_use]
            #[inline]
            pub fn $name(left: Expr, right: Expr) -> Expr {
                binary($op, left, right)
            }
        )*
    };
}

macro_rules! unary_builders {
    ($($(#[$meta:meta])* $name:ident => $op:expr;)*) => {
        $(
            $(#[$meta])*
            #[must_use]
            #[inline]
            pub fn $name(operand: Expr) -> Expr {
                unary($op, operand)
            }
        )*
    };
}

impl Expr {
    binary_builders! {
        /// `a + b`.
        add => BinOp::Add;
        /// `a - b`.
        sub => BinOp::Sub;
        /// `a * b`.
        mul => BinOp::Mul;
        /// `a / b`; zero divisors evaluate to the total-reference value.
        div => BinOp::Div;
        /// Upper 32 bits of `a * b` for unsigned widening multiply.
        mulhi => BinOp::MulHigh;
        /// `a % b`; zero divisors evaluate to the total-reference value.
        rem => BinOp::Mod;
        /// Unsigned absolute difference.
        abs_diff => BinOp::AbsDiff;
        /// Bitwise XOR.
        bitxor => BinOp::BitXor;
        /// Bitwise AND.
        bitand => BinOp::BitAnd;
        /// Bitwise OR.
        bitor => BinOp::BitOr;
        /// Shift left.
        shl => BinOp::Shl;
        /// Shift right.
        shr => BinOp::Shr;
        /// Equality comparison.
        eq => BinOp::Eq;
        /// Strict less-than comparison.
        lt => BinOp::Lt;
        /// Inequality comparison.
        ne => BinOp::Ne;
        /// Strict greater-than comparison.
        gt => BinOp::Gt;
        /// Less-than-or-equal comparison.
        le => BinOp::Le;
        /// Greater-than-or-equal comparison.
        ge => BinOp::Ge;
        /// Logical AND.
        and => BinOp::And;
        /// Logical OR.
        or => BinOp::Or;
        /// `min(a, b)`.
        min => BinOp::Min;
        /// `max(a, b)`.
        max => BinOp::Max;
    }

    unary_builders! {
        /// Twos-complement negation.
        negate => UnOp::Negate;
        /// Bitwise NOT.
        bitnot => UnOp::BitNot;
        /// Reverse the bit order.
        reverse_bits => UnOp::ReverseBits;
        /// Count one bits.
        popcount => UnOp::Popcount;
        /// Count leading zero bits.
        clz => UnOp::Clz;
        /// Count trailing zero bits.
        ctz => UnOp::Ctz;
        /// Logical NOT.
        not => UnOp::LogicalNot;
        /// Sine.
        sin => UnOp::Sin;
        /// Cosine.
        cos => UnOp::Cos;
        /// Absolute value.
        abs => UnOp::Abs;
        /// Square root.
        sqrt => UnOp::Sqrt;
        /// Inverse square root.
        inverse_sqrt => UnOp::InverseSqrt;
        /// Reciprocal.
        reciprocal => UnOp::Reciprocal;
        /// Floor.
        floor => UnOp::Floor;
        /// Ceiling.
        ceil => UnOp::Ceil;
        /// Round to nearest.
        round => UnOp::Round;
        /// Truncate toward zero.
        trunc => UnOp::Trunc;
        /// Sign extraction.
        sign => UnOp::Sign;
        /// `isNan(a)`.
        is_nan => UnOp::IsNan;
        /// `isInf(a)`.
        is_inf => UnOp::IsInf;
        /// `isFinite(a)`.
        is_finite => UnOp::IsFinite;
    }

    /// `saturating_sub(a, b)` for unsigned operands; clamps to zero when
    /// `b > a` instead of underflowing.
    ///
    /// Compiles to `a - min(a, b)` so static WGSL evaluation never observes a
    /// literal underflow in an unguarded subtraction.
    #[must_use]
    #[inline]
    pub fn saturating_sub(left: Expr, right: Expr) -> Expr {
        binary(BinOp::Sub, left.clone(), binary(BinOp::Min, left, right))
    }

    /// Construct a wrapping addition node.
    #[must_use]
    #[inline]
    pub fn wrapping_add(self, other: impl Into<Expr>) -> Self {
        binary(BinOp::WrappingAdd, self, other.into())
    }

    /// Construct a wrapping subtraction node.
    #[must_use]
    #[inline]
    pub fn wrapping_sub(self, other: impl Into<Expr>) -> Self {
        binary(BinOp::WrappingSub, self, other.into())
    }
}
