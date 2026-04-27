use crate::ir::Expr;
use im::HashSet;

#[inline]
pub(crate) fn collect_expr_refs(expr: &Expr, refs: &mut HashSet<String>) {
    let mut stack = vec![expr];
    while let Some(expr) = stack.pop() {
        match expr {
            Expr::Var(name) => {
                refs.insert(name.to_string());
            }
            Expr::Load { index, .. } | Expr::UnOp { operand: index, .. } => {
                stack.push(index);
            }
            Expr::BinOp { left, right, .. } => {
                stack.push(left);
                stack.push(right);
            }
            Expr::Call { args, .. } => {
                stack.extend(args);
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
            Expr::Cast { value, .. } => stack.push(value),
            Expr::Fma { a, b, c } => {
                stack.push(a);
                stack.push(b);
                stack.push(c);
            }
            Expr::Atomic {
                index,
                expected,
                value,
                ..
            } => {
                stack.push(index);
                if let Some(expected) = expected {
                    stack.push(expected);
                }
                stack.push(value);
            }
            Expr::LitU32(_)
            | Expr::LitI32(_)
            | Expr::LitF32(_)
            | Expr::LitBool(_)
            | Expr::BufLen { .. }
            | Expr::InvocationId { .. }
            | Expr::WorkgroupId { .. }
            | Expr::LocalId { .. }
            | Expr::SubgroupLocalId
            | Expr::SubgroupSize
            | Expr::SubgroupBallot { .. }
            | Expr::SubgroupShuffle { .. }
            | Expr::SubgroupAdd { .. } => {}
            Expr::Opaque(_) => {}
        }
    }
}
