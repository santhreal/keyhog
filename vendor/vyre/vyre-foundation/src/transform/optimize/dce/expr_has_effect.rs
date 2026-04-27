use crate::ir::Expr;

#[inline]
pub(crate) fn expr_has_effect(expr: &Expr) -> bool {
    let mut stack = vec![expr];
    while let Some(expr) = stack.pop() {
        match expr {
            Expr::Atomic { .. } | Expr::Call { .. } => return true,
            Expr::Load { index, .. }
            | Expr::UnOp { operand: index, .. }
            | Expr::Cast { value: index, .. } => stack.push(index),
            Expr::BinOp { left, right, .. } => {
                stack.push(left);
                stack.push(right);
            }
            Expr::Fma { a, b, c } => {
                stack.push(a);
                stack.push(b);
                stack.push(c);
            }
            Expr::Select {
                cond,
                true_val,
                false_val,
            } => {
                stack.push(cond);
                stack.push(true_val);
                stack.push(false_val);
            }
            Expr::LitU32(_)
            | Expr::LitI32(_)
            | Expr::LitF32(_)
            | Expr::LitBool(_)
            | Expr::Var(_)
            | Expr::BufLen { .. }
            | Expr::InvocationId { .. }
            | Expr::WorkgroupId { .. }
            | Expr::LocalId { .. }
            | Expr::SubgroupLocalId
            | Expr::SubgroupSize => {}
            &Expr::SubgroupBallot { .. }
            | &Expr::SubgroupShuffle { .. }
            | &Expr::SubgroupAdd { .. } => {}
            Expr::Opaque(extension) => {
                if !extension.cse_safe() {
                    return true;
                }
            }
        }
    }
    false
}
