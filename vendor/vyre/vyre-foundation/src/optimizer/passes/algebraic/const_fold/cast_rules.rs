// Cast folding rules.
//
// Fold a Cast expression when the inner value is a compile-time literal.

use crate::ir::eval::fold_cast_literal;
use crate::ir::Expr;

/// Fold a Cast expression when the inner value is a compile-time literal.
pub(super) fn fold_cast(target: &crate::ir::DataType, value: &Expr) -> Option<Expr> {
    if let Some(folded) = fold_cast_literal(target, value) {
        return Some(folded);
    }
    match value {
        Expr::Cast { value: inner, .. } => Some(Expr::Cast {
            target: target.clone(),
            value: inner.clone(),
        }),
        _ => None,
    }
}
