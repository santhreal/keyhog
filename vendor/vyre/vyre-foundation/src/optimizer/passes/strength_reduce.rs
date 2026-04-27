use crate::ir::{BinOp, Expr, Program};
use crate::optimizer::rewrite::rewrite_program;
use crate::optimizer::{fingerprint_program, vyre_pass, PassAnalysis, PassResult};

/// Replace multiplication by powers of two with shifts.
#[derive(Debug, Default)]
#[vyre_pass(
    name = "strength_reduce",
    requires = ["const_fold"],
    invalidates = ["value_numbering"]
)]
pub struct StrengthReduce;

impl StrengthReduce {
    /// Decide whether this pass should run.
    #[must_use]
    #[inline]
    pub fn analyze(_program: &Program) -> PassAnalysis {
        PassAnalysis::RUN
    }

    /// Rewrite multiply-by-power-of-two expressions into left shifts.
    ///
    /// AUDIT_2026-04-24 F-SR-01 (closed): `rewrite_program` already
    /// preserves `non_composable_with_self` via `with_rewritten_entry`
    /// (see builder.rs line ~134). No explicit call needed here.
    #[must_use]
    pub fn transform(program: Program) -> PassResult {
        let (program, changed) = rewrite_program(program, reduce_expr);
        PassResult { program, changed }
    }

    /// Fingerprint this pass's visible input.
    #[must_use]
    #[inline]
    pub fn fingerprint(program: &Program) -> u64 {
        fingerprint_program(program)
    }
}

fn reduce_expr(expr: &Expr) -> Option<Expr> {
    let Expr::BinOp { op, left, right } = expr else {
        return None;
    };
    match op {
        BinOp::Mul => {
            if let Some(shift) = power_of_two_shift(right) {
                return Some(Expr::shl(left.as_ref().clone(), Expr::u32(shift)));
            }
            if let Some(shift) = power_of_two_shift(left) {
                return Some(Expr::shl(right.as_ref().clone(), Expr::u32(shift)));
            }
            None
        }
        // VYRE_OPTIMIZER HIGH-02: unsigned Div-by-2^k -> Shr by k;
        // Mod-by-2^k -> BitAnd (2^k - 1). Only fires when the rhs
        // is a LitU32 power of two — LitI32 paths avoid signed
        // semantics mismatch (negative dividend + rounding
        // direction) entirely.
        BinOp::Div => {
            let Expr::LitU32(value) = right.as_ref() else {
                return None;
            };
            if !value.is_power_of_two() {
                return None;
            }
            Some(Expr::shr(
                left.as_ref().clone(),
                Expr::u32(value.trailing_zeros()),
            ))
        }
        BinOp::Mod => {
            let Expr::LitU32(value) = right.as_ref() else {
                return None;
            };
            if !value.is_power_of_two() {
                return None;
            }
            Some(Expr::bitand(left.as_ref().clone(), Expr::u32(value - 1)))
        }
        _ => None,
    }
}

fn power_of_two_shift(expr: &Expr) -> Option<u32> {
    match expr {
        Expr::LitU32(value) if value.is_power_of_two() => Some(value.trailing_zeros()),
        Expr::LitI32(value) if *value > 0 && (*value as u32).is_power_of_two() => {
            Some(value.trailing_zeros())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BufferDecl, DataType, Expr, Node};
    use crate::optimizer::passes::const_fold::ConstFold;
    use crate::optimizer::{PassKind, PassScheduler};

    #[test]
    fn optimizer_strength_reduce_multiplies_by_two() {
        let program = crate::transform::optimize::region_inline::run(Program::wrapped(
            vec![BufferDecl::read_write("out", 0, DataType::U32)],
            [1, 1, 1],
            vec![Node::store(
                "out",
                Expr::u32(0),
                Expr::mul(Expr::var("x"), Expr::u32(2)),
            )],
        ));

        let optimized = PassScheduler::with_passes(vec![
            PassKind::ConstFold(ConstFold),
            PassKind::StrengthReduce(StrengthReduce),
        ])
        .run(program)
        .expect("Fix: strength reduce should converge");

        let body = crate::test_util::region_body(&optimized);
        assert!(matches!(
            &body[0],
            Node::Store {
                value: Expr::BinOp {
                    op: BinOp::Shl,
                    right,
                    ..
                },
                ..
            } if matches!(right.as_ref(), Expr::LitU32(1))
        ));
    }

    #[test]
    fn optimizer_strength_reduce_leaves_non_power_of_two() {
        let program = Program::wrapped(
            Vec::new(),
            [1, 1, 1],
            vec![Node::let_bind(
                "x",
                Expr::mul(Expr::var("input"), Expr::u32(3)),
            )],
        );

        let optimized = PassScheduler::with_passes(vec![
            PassKind::ConstFold(ConstFold),
            PassKind::StrengthReduce(StrengthReduce),
        ])
        .run(program.clone())
        .expect("Fix: strength reduce should converge");
        assert_eq!(program, optimized);
    }
}
