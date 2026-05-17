//! Shared algebraic rewrite legality rules.
//!
//! This module is the single source of truth for algebraic decisions that apply
//! at more than one IR level. `vyre-foundation` Program passes and `vyre-lower`
//! KernelDescriptor rewrites adapt their local value representation into these
//! small rule inputs instead of independently re-encoding what `x + 0`, `x * 1`,
//! or division by a power of two means.

use crate::ir::BinOp;

/// Literal scalar value normalized across Program IR and KernelDescriptor IR.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ScalarLiteral {
    /// Unsigned 32-bit integer.
    U32(u32),
    /// Signed 32-bit integer.
    I32(i32),
    /// 32-bit float.
    F32(f32),
    /// Boolean.
    Bool(bool),
}

impl ScalarLiteral {
    /// Return true for numeric zero. Bool is deliberately excluded.
    #[must_use]
    pub fn is_numeric_zero(self) -> bool {
        match self {
            Self::U32(0) | Self::I32(0) => true,
            Self::F32(value) => value == 0.0,
            _ => false,
        }
    }

    /// Return true for *integer* zero only (u32 0 or i32 0).
    ///
    /// Float 0.0 is deliberately excluded because `NaN * 0.0 = NaN`
    /// and `Inf * 0.0 = NaN`; the `x * 0 → 0` absorber is only sound
    /// for integers.
    #[must_use]
    pub fn is_integer_zero(self) -> bool {
        matches!(self, Self::U32(0) | Self::I32(0))
    }

    /// Return true for numeric one. Bool is deliberately excluded.
    #[must_use]
    pub fn is_numeric_one(self) -> bool {
        match self {
            Self::U32(1) | Self::I32(1) => true,
            Self::F32(value) => value == 1.0,
            _ => false,
        }
    }

    /// Return true for integer all-ones bit patterns.
    #[must_use]
    pub fn is_bit_all_ones(self) -> bool {
        matches!(self, Self::U32(u32::MAX) | Self::I32(-1))
    }

    /// Return true for bool true.
    #[must_use]
    pub fn is_true(self) -> bool {
        matches!(self, Self::Bool(true))
    }

    /// Return true for bool false.
    #[must_use]
    pub fn is_false(self) -> bool {
        matches!(self, Self::Bool(false))
    }
}

/// Which original operand a substitution-only identity rewrite keeps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityReplacement {
    /// Replace the operation result with the left operand.
    Left,
    /// Replace the operation result with the right operand.
    Right,
}

/// Decide a substitution-only binary identity/absorber rewrite.
///
/// Returns which existing operand should replace the BinOp result. This function
/// never asks callers to synthesize a new literal, so it is safe for descriptor
/// passes that only rewrite result-id references.
#[must_use]
pub fn binop_identity_replacement(
    op: BinOp,
    lhs_same_as_rhs: bool,
    lhs_lit: Option<ScalarLiteral>,
    rhs_lit: Option<ScalarLiteral>,
) -> Option<IdentityReplacement> {
    if lhs_same_as_rhs {
        match op {
            BinOp::BitAnd | BinOp::BitOr | BinOp::And | BinOp::Or | BinOp::Min | BinOp::Max => {
                return Some(IdentityReplacement::Left);
            }
            _ => {}
        }
    }

    let lhs_is_zero = lhs_lit
        .map(ScalarLiteral::is_numeric_zero)
        .unwrap_or(false);
    let rhs_is_zero = rhs_lit
        .map(ScalarLiteral::is_numeric_zero)
        .unwrap_or(false);
    let lhs_is_one = lhs_lit
        .map(ScalarLiteral::is_numeric_one)
        .unwrap_or(false);
    let rhs_is_one = rhs_lit
        .map(ScalarLiteral::is_numeric_one)
        .unwrap_or(false);
    let lhs_is_all_ones = lhs_lit
        .map(ScalarLiteral::is_bit_all_ones)
        .unwrap_or(false);
    let rhs_is_all_ones = rhs_lit
        .map(ScalarLiteral::is_bit_all_ones)
        .unwrap_or(false);
    let lhs_is_true = lhs_lit.map(ScalarLiteral::is_true).unwrap_or(false);
    let rhs_is_true = rhs_lit.map(ScalarLiteral::is_true).unwrap_or(false);
    let lhs_is_false = lhs_lit.map(ScalarLiteral::is_false).unwrap_or(false);
    let rhs_is_false = rhs_lit.map(ScalarLiteral::is_false).unwrap_or(false);

    match op {
        BinOp::And => {
            if rhs_is_true {
                return Some(IdentityReplacement::Left);
            }
            if lhs_is_true {
                return Some(IdentityReplacement::Right);
            }
            if rhs_is_false {
                return Some(IdentityReplacement::Right);
            }
            if lhs_is_false {
                return Some(IdentityReplacement::Left);
            }
        }
        BinOp::Or => {
            if rhs_is_false {
                return Some(IdentityReplacement::Left);
            }
            if lhs_is_false {
                return Some(IdentityReplacement::Right);
            }
            if rhs_is_true {
                return Some(IdentityReplacement::Right);
            }
            if lhs_is_true {
                return Some(IdentityReplacement::Left);
            }
        }
        BinOp::BitAnd => {
            if rhs_is_all_ones {
                return Some(IdentityReplacement::Left);
            }
            if lhs_is_all_ones {
                return Some(IdentityReplacement::Right);
            }
        }
        BinOp::BitOr => {
            if rhs_is_all_ones {
                return Some(IdentityReplacement::Right);
            }
            if lhs_is_all_ones {
                return Some(IdentityReplacement::Left);
            }
        }
        _ => {}
    }

    let right_identity_when_zero = matches!(
        op,
        BinOp::Add
            | BinOp::Sub
            | BinOp::WrappingAdd
            | BinOp::WrappingSub
            | BinOp::SaturatingAdd
            | BinOp::SaturatingSub
            | BinOp::BitOr
            | BinOp::BitXor
            | BinOp::Shl
            | BinOp::Shr
            | BinOp::RotateLeft
            | BinOp::RotateRight
    );
    let right_identity_when_one = matches!(op, BinOp::Mul | BinOp::Div | BinOp::SaturatingMul);
    if (right_identity_when_zero && rhs_is_zero) || (right_identity_when_one && rhs_is_one) {
        return Some(IdentityReplacement::Left);
    }

    let left_identity_when_zero = matches!(
        op,
        BinOp::Add | BinOp::WrappingAdd | BinOp::SaturatingAdd | BinOp::BitOr | BinOp::BitXor
    );
    let left_identity_when_one = matches!(op, BinOp::Mul | BinOp::SaturatingMul);
    if (left_identity_when_zero && lhs_is_zero) || (left_identity_when_one && lhs_is_one) {
        return Some(IdentityReplacement::Right);
    }

    // Mul/SaturatingMul absorber is restricted to *integer* zero because
    // float 0.0 × NaN = NaN, not 0.0 — folding would change semantics.
    // BitAnd is fine with any zero (bitwise, type-safe).
    let lhs_is_int_zero = lhs_lit
        .map(ScalarLiteral::is_integer_zero)
        .unwrap_or(false);
    let rhs_is_int_zero = rhs_lit
        .map(ScalarLiteral::is_integer_zero)
        .unwrap_or(false);
    let absorbs_mul_to_zero = matches!(op, BinOp::Mul | BinOp::SaturatingMul);
    if absorbs_mul_to_zero {
        if rhs_is_int_zero {
            return Some(IdentityReplacement::Right);
        }
        if lhs_is_int_zero {
            return Some(IdentityReplacement::Left);
        }
    }
    if matches!(op, BinOp::BitAnd) {
        if rhs_is_zero {
            return Some(IdentityReplacement::Right);
        }
        if lhs_is_zero {
            return Some(IdentityReplacement::Left);
        }
    }

    None
}

/// Return `log2(value)` when `value` is a strength-reducible power of two.
#[must_use]
pub fn strength_reduce_power_of_two_shift(value: u32) -> Option<u32> {
    if value >= 2 && value.is_power_of_two() {
        Some(value.trailing_zeros())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_rules_cover_bool_and_integer_absorbers() {
        assert_eq!(
            binop_identity_replacement(BinOp::And, false, None, Some(ScalarLiteral::Bool(true))),
            Some(IdentityReplacement::Left)
        );
        assert_eq!(
            binop_identity_replacement(BinOp::Or, false, Some(ScalarLiteral::Bool(true)), None),
            Some(IdentityReplacement::Left)
        );
        assert_eq!(
            binop_identity_replacement(BinOp::BitAnd, false, None, Some(ScalarLiteral::U32(u32::MAX))),
            Some(IdentityReplacement::Left)
        );
        assert_eq!(
            binop_identity_replacement(BinOp::Mul, false, None, Some(ScalarLiteral::U32(0))),
            Some(IdentityReplacement::Right)
        );
    }

    #[test]
    fn strength_reduce_power_of_two_excludes_one_and_zero() {
        assert_eq!(strength_reduce_power_of_two_shift(0), None);
        assert_eq!(strength_reduce_power_of_two_shift(1), None);
        assert_eq!(strength_reduce_power_of_two_shift(8), Some(3));
    }
}
