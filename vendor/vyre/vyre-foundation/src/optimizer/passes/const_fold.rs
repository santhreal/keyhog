use crate::ir::{Expr, Program};
use crate::optimizer::rewrite::{literal_binop, literal_unop, rewrite_program};
use crate::optimizer::{fingerprint_program, vyre_pass, PassAnalysis, PassResult};

/// Fold compile-time-known literal expressions.
#[derive(Debug, Default)]
#[vyre_pass(name = "const_fold", requires = [], invalidates = ["value_numbering"])]
pub struct ConstFold;

impl ConstFold {
    /// Decide whether this pass should run.
    #[must_use]
    #[inline]
    pub fn analyze(_program: &Program) -> PassAnalysis {
        PassAnalysis::RUN
    }

    /// Fold literal-only expressions.
    ///
    /// AUDIT_2026-04-24 F-CF-01 (closed): `rewrite_program` already
    /// preserves `non_composable_with_self` via `with_rewritten_entry`
    /// (see builder.rs line ~134). Leaving this comment so future
    /// audits see the invariant is intentional and traced to the
    /// constructor, not a one-off per-pass call.
    #[must_use]
    pub fn transform(program: Program) -> PassResult {
        let (program, changed) = rewrite_program(program, fold_expr);
        PassResult { program, changed }
    }

    /// Fingerprint this pass's visible input.
    #[must_use]
    #[inline]
    pub fn fingerprint(program: &Program) -> u64 {
        fingerprint_program(program)
    }
}

fn fold_expr(expr: &Expr) -> Option<Expr> {
    match expr {
        Expr::BinOp { op, left, right } => literal_binop(*op, left, right),
        Expr::UnOp { op, operand } => literal_unop(op.clone(), operand),
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => match cond.as_ref() {
            Expr::LitBool(true) => Some(true_val.as_ref().clone()),
            Expr::LitBool(false) => Some(false_val.as_ref().clone()),
            Expr::LitU32(value) => {
                if *value == 0 {
                    Some(false_val.as_ref().clone())
                } else {
                    Some(true_val.as_ref().clone())
                }
            }
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BufferDecl, DataType, Expr, Node};
    use crate::optimizer::{PassKind, PassScheduler};

    #[test]
    fn optimizer_const_fold_adds_literals() {
        let program = crate::transform::optimize::region_inline::run(Program::wrapped(
            vec![BufferDecl::read_write("out", 0, DataType::U32)],
            [1, 1, 1],
            vec![Node::store(
                "out",
                Expr::u32(0),
                Expr::add(Expr::u32(3), Expr::u32(4)),
            )],
        ));

        let optimized = PassScheduler::with_passes(vec![PassKind::ConstFold(ConstFold)])
            .run(program)
            .expect("Fix: const fold should converge");

        let body = crate::test_util::region_body(&optimized);
        assert!(matches!(
            &body[0],
            Node::Store {
                value: Expr::LitU32(7),
                ..
            }
        ));
    }

    #[test]
    fn optimizer_const_fold_is_idempotent() {
        let program = Program::wrapped(
            Vec::new(),
            [1, 1, 1],
            vec![Node::let_bind(
                "x",
                Expr::bitxor(Expr::u32(0b1010), Expr::u32(0b1100)),
            )],
        );

        let scheduler = PassScheduler::with_passes(vec![PassKind::ConstFold(ConstFold)]);
        let once = scheduler
            .run(program)
            .expect("Fix: first run should converge");
        let twice = scheduler
            .run(once.clone())
            .expect("Fix: second run should converge");
        assert_eq!(once, twice);
    }
}
