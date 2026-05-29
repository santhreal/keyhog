//! Integration contracts for optimizer algebraic rule helpers.

use vyre_foundation::ir::BinOp;
use vyre_foundation::optimizer::algebraic_rules::{
    binop_identity_replacement, strength_reduce_power_of_two_shift, IdentityReplacement,
    ScalarLiteral,
};

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
        binop_identity_replacement(
            BinOp::BitAnd,
            false,
            None,
            Some(ScalarLiteral::U32(u32::MAX)),
        ),
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
