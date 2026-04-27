use crate::ir_inner::model::expr::Expr;
use crate::ir_inner::model::program::BufferDecl;
use crate::ir_inner::model::types::{BinOp, DataType};
use crate::validate::{err, Binding, ValidationError};
use rustc_hash::FxHashMap;

#[inline]
pub(crate) fn validate_binop_operands(
    op: &BinOp,
    left: &Expr,
    right: &Expr,
    buffers: &FxHashMap<&str, &BufferDecl>,
    scope: &FxHashMap<String, Binding>,
    errors: &mut Vec<ValidationError>,
) {
    let left_ty = expr_type(left, buffers, scope);
    let right_ty = expr_type(right, buffers, scope);

    match op {
        // Arithmetic: U32, I32, and F32 are all valid in WGSL.
        // Bool is NOT — `(a && b) + 1` must be rejected at validation time.
        // Operand types must also match: `u32 + f32` is silently ambiguous
        // today and must be rejected (VAL-003).
        BinOp::Add
        | BinOp::Sub
        | BinOp::Mul
        | BinOp::Div
        | BinOp::SaturatingAdd
        | BinOp::SaturatingSub
        | BinOp::SaturatingMul
        | BinOp::Min
        | BinOp::Max
        | BinOp::AbsDiff => {
            if let (Some(l), Some(r)) = (&left_ty, &right_ty) {
                if matches!(l, DataType::U64 | DataType::I64)
                    || matches!(r, DataType::U64 | DataType::I64)
                {
                    errors.push(err(format!(
                        "binary operation `{op:?}` received left=`{l}`, right=`{r}`. 64-bit integer arithmetic is not yet validated across all backends. Fix: decompose into a U32 pair with explicit carry, or wait for the U64 emulation pass."
                    )));
                }

                if matches!(
                    op,
                    BinOp::SaturatingAdd | BinOp::SaturatingSub | BinOp::SaturatingMul
                ) && (l != &DataType::U32 || r != &DataType::U32)
                {
                    errors.push(err(
                        format!(
                            "Saturating arithmetic `{op:?}` received left=`{l}`, right=`{r}`; legal set is only U32 in the current lowering. Fix: cast both operands to U32, or clamp explicitly for I32/F32."
                        )
                            .to_string(),
                    ));
                }

                if matches!(op, BinOp::AbsDiff) && (l == &DataType::I32 || r == &DataType::I32) {
                    errors.push(err(
                        format!(
                            "AbsDiff has left=`{l}`, right=`{r}` and can overflow (i32::MIN - i32::MAX invokes WGSL signed-integer UB). Fix: cast operands to U32 before AbsDiff, or rewrite as an explicit branch."
                        )
                            .to_string(),
                    ));
                }
            }
            for (side, ty) in [("left", &left_ty), ("right", &right_ty)] {
                if let Some(ty) = ty {
                    if matches!(ty, DataType::Bool) {
                        errors.push(err(format!(
                            "binary operation `{op:?}` {side} operand has type `{ty}`, but numeric arithmetic expects one of `u32`, `i32`, or `f32`. Fix: cast the operand to U32 or I32 before arithmetic, or rewrite to avoid mixing logical and arithmetic operators."
                        )));
                    }
                }
            }
            // VAL-003: reject mixed numeric types. WGSL has no implicit
            // promotion; `a: u32 + b: f32` must be a cast at the call site,
            // not a silent validator pass.
            if let (Some(l), Some(r)) = (&left_ty, &right_ty) {
                let both_numeric = matches!(l, DataType::U32 | DataType::I32 | DataType::F32)
                    && matches!(r, DataType::U32 | DataType::I32 | DataType::F32);
                if both_numeric && l != r {
                    errors.push(err(format!(
                        "binary operation `{op:?}` operands have mismatched numeric types: left=`{l}`, right=`{r}` (legal set: U32, I32, F32). Fix: cast one operand so both sides share a type (WGSL has no implicit promotion)."
                    )));
                }
            }
        }
        // Modulo: WGSL lowers to `_vyre_safe_mod_u32`, so both sides must be u32.
        BinOp::Mod => {
            for (side, ty) in [("left", left_ty), ("right", right_ty)] {
                if let Some(ty) = ty {
                    if !matches!(ty, DataType::U32) {
                        errors.push(err(format!(
                            "binary operation `Mod` {side} operand must be `u32`, got `{ty}`. Legal set for Mod is only `u32`. Fix: cast the operand to U32 before modulo."
                        )));
                    }
                }
            }
        }
        // Bitwise: WGSL `&` / `|` / `^` require integer operands of the same type.
        BinOp::BitAnd | BinOp::BitOr | BinOp::BitXor => {
            if let (Some(l), Some(r)) = (&left_ty, &right_ty) {
                if !matches!(l, DataType::U32 | DataType::I32) {
                    errors.push(err(format!(
                        "binary operation `{op:?}` left operand has type `{l}`; legal integer set is `u32` or `i32`. Fix: cast the left operand to U32 or I32."
                    )));
                }
                if !matches!(r, DataType::U32 | DataType::I32) {
                    errors.push(err(format!(
                        "binary operation `{op:?}` right operand has type `{r}`; legal integer set is `u32` or `i32`. Fix: cast the right operand to U32 or I32."
                    )));
                }
                if l != r {
                    errors.push(err(format!(
                        "binary operation `{op:?}` operands have mismatched integer types: left=`{l}`, right=`{r}`. Integer operands must match and belong to `u32` or `i32`. Fix: cast both operands to the same integer type."
                    )));
                }
            }
        }
        // Shifts and rotates: WGSL masks the right operand with `& 31u`,
        // so both sides must be u32. Rotates share the same typing —
        // left is the bit-pattern, right is the rotation count in bits.
        BinOp::Shl | BinOp::Shr | BinOp::RotateLeft | BinOp::RotateRight => {
            for (side, ty) in [("left", left_ty), ("right", right_ty)] {
                if let Some(ty) = ty {
                    if !matches!(ty, DataType::U32) {
                        errors.push(err(format!(
                            "binary operation `{op:?}` {side} operand has type `{ty}`; shift/rotate operands must be `u32`. Fix: cast the operand to U32 before shifting/rotating."
                        )));
                    }
                }
            }
        }
        // Logical And/Or: WGSL lowers via `!= 0u`, so only u32 and bool are valid.
        BinOp::And | BinOp::Or => {
            for (side, ty) in [("left", left_ty), ("right", right_ty)] {
                if let Some(ty) = ty {
                    if !matches!(ty, DataType::U32 | DataType::Bool) {
                        errors.push(err(format!(
                            "binary operation `{op:?}` {side} operand has type `{ty}`; logical And/Or operands must be `u32` or `bool`. Fix: cast the operand to U32 or Bool."
                        )));
                    }
                }
            }
        }
        // Comparisons: WGSL requires both operands to have the same type.
        BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Gt | BinOp::Le | BinOp::Ge => {
            if let (Some(l), Some(r)) = (&left_ty, &right_ty) {
                if l != r {
                    errors.push(err(format!(
                        "binary comparison `{op:?}` operands have mismatched types: left=`{l}`, right=`{r}`. Comparisons require matching types. Fix: cast both operands to the same type before comparing."
                    )));
                }
            }
        }
        BinOp::Shuffle | BinOp::Ballot | BinOp::WaveReduce | BinOp::WaveBroadcast => {
            errors.push(err(format!(
                "binary operation `{op:?}` requires backend subgroup semantics (`supports_subgroup_ops() == true`) before foundation validation can guarantee safety. Fix: validate with ValidationOptions::with_backend(backend) where `backend.supports_subgroup_ops() == true`, or remove `{op:?}` before lowering."
            )));
        }
        // Opaque extension binops validate their own operands via
        // `ExprNode::validate_extension`; the foundation-level typechecker
        // imposes no operand-type constraints on them. Future non_exhaustive
        // variants land here without constraints until a dedicated arm is
        // added above.
        BinOp::Opaque(_) => {}
        _ => {}
    }
}

#[inline]
pub(crate) fn validate_unop_operand(
    op: &crate::ir_inner::model::types::UnOp,
    expr: &Expr,
    buffers: &FxHashMap<&str, &BufferDecl>,
    scope: &FxHashMap<String, Binding>,
    errors: &mut Vec<ValidationError>,
) {
    if let Some(ty) = expr_type(expr, buffers, scope) {
        match op {
            crate::ir_inner::model::types::UnOp::Negate => {
                if matches!(ty, DataType::I32) {
                    errors.push(err(format!(
                        "unary operation `Negate` operand has type `{ty}`, but legal unary Negate types are `u32`, `i32`, and `f32`. Fix: cast to U32 before Negate, or guard with Select(i32::MIN, 0, -x)."
                    )));
                } else if !matches!(ty, DataType::U32 | DataType::F32) {
                    errors.push(err(format!(
                        "unary operation `{op:?}` operand has type `{ty}`, but legal set is U32, I32, or F32. Fix: cast or rewrite the operand to U32/I32/F32."
                    )));
                }
            }
            crate::ir_inner::model::types::UnOp::LogicalNot => {
                if !matches!(ty, DataType::U32 | DataType::Bool) {
                    errors.push(err(format!(
                        "unary operation `LogicalNot` operand has type `{ty}`; legal set is `u32` or `bool`. Fix: cast or rewrite the operand to produce U32 or Bool."
                    )));
                }
            }
            crate::ir_inner::model::types::UnOp::BitNot
            | crate::ir_inner::model::types::UnOp::Popcount
            | crate::ir_inner::model::types::UnOp::Clz
            | crate::ir_inner::model::types::UnOp::Ctz
            | crate::ir_inner::model::types::UnOp::ReverseBits => {
                // VAL-004: U64 operands are valid for every bitwise-unary
                // op. The reference interpreter handles Value::U64 for
                // BitNot/Popcount/Clz/Ctz/ReverseBits and WGSL ≥ the 64-bit
                // extension emits the right intrinsics. Previously the
                // validator rejected U64 and forced an avoidable down-cast.
                if !matches!(ty, DataType::U32 | DataType::I32 | DataType::U64) {
                    errors.push(err(format!(
                        "unary operation `{op:?}` operand has type `{ty}`; legal integer set is `u32`, `i32`, or `u64`. Fix: cast or rewrite the operand to produce U32, I32, or U64."
                    )));
                }
            }
            crate::ir_inner::model::types::UnOp::Sin
            | crate::ir_inner::model::types::UnOp::Cos
            | crate::ir_inner::model::types::UnOp::Exp
            | crate::ir_inner::model::types::UnOp::Log
            | crate::ir_inner::model::types::UnOp::Log2
            | crate::ir_inner::model::types::UnOp::Exp2
            | crate::ir_inner::model::types::UnOp::Tan
            | crate::ir_inner::model::types::UnOp::Acos
            | crate::ir_inner::model::types::UnOp::Asin
            | crate::ir_inner::model::types::UnOp::Atan
            | crate::ir_inner::model::types::UnOp::Tanh
            | crate::ir_inner::model::types::UnOp::Sinh
            | crate::ir_inner::model::types::UnOp::Cosh
            | crate::ir_inner::model::types::UnOp::Abs
            | crate::ir_inner::model::types::UnOp::Sqrt
            | crate::ir_inner::model::types::UnOp::InverseSqrt
            | crate::ir_inner::model::types::UnOp::Floor
            | crate::ir_inner::model::types::UnOp::Ceil
            | crate::ir_inner::model::types::UnOp::Round
            | crate::ir_inner::model::types::UnOp::Trunc
            | crate::ir_inner::model::types::UnOp::Sign
            | crate::ir_inner::model::types::UnOp::IsNan
            | crate::ir_inner::model::types::UnOp::IsInf
            | crate::ir_inner::model::types::UnOp::IsFinite => {
                if ty != DataType::F32 {
                    errors.push(err(format!(
                        "unary operation `{op:?}` operand has type `{ty}`; legal set for math ops is `f32`. Fix: cast or rewrite the operand to produce F32."
                    )));
                }
            }
            _ => {
                errors.push(err(format!(
                    "unary operation `{op:?}` is not recognized. Fix: use a known UnOp variant from this enum (`Negate`, `LogicalNot`, `BitNot`, `Popcount`, `Clz`, `Ctz`, `ReverseBits`, `Sin`, `Cos`, `Exp`, `Log`, `Log2`, `Exp2`, `Tan`, `Acos`, `Asin`, `Atan`, `Tanh`, `Sinh`, `Cosh`, `Abs`, `Sqrt`, `InverseSqrt`, `Floor`, `Ceil`, `Round`, `Trunc`, `Sign`, `IsNan`, `IsInf`, `IsFinite`, `Unpack4Low`, `Unpack4High`, `Unpack8Low`, `Unpack8High`)."
                )));
            }
        }
    }
}

/// Infer the static type of an expression, if it can be determined from the IR.
#[inline]
pub(crate) fn expr_type(
    expr: &Expr,
    buffers: &FxHashMap<&str, &BufferDecl>,
    scope: &FxHashMap<String, Binding>,
) -> Option<DataType> {
    enum Frame<'a> {
        Enter(&'a Expr),
        Bin,
        Un,
        Select,
        Fma,
    }

    let mut frames = vec![Frame::Enter(expr)];
    let mut values: Vec<Option<DataType>> = Vec::new();
    while let Some(frame) = frames.pop() {
        match frame {
            Frame::Enter(expr) => match expr {
                Expr::LitU32(_) => values.push(Some(DataType::U32)),
                Expr::LitI32(_) => values.push(Some(DataType::I32)),
                Expr::LitF32(_) => values.push(Some(DataType::F32)),
                Expr::LitBool(_) => values.push(Some(DataType::Bool)),
                Expr::Var(name) => values.push(scope.get(name.as_str()).map(|b| b.ty.clone())),
                Expr::Load { buffer, .. } => {
                    values.push(buffers.get(buffer.as_str()).map(|b| b.element.clone()))
                }
                Expr::BufLen { .. }
                | Expr::InvocationId { .. }
                | Expr::WorkgroupId { .. }
                | Expr::LocalId { .. }
                | Expr::SubgroupLocalId
                | Expr::SubgroupSize
                | Expr::Atomic { .. } => values.push(Some(DataType::U32)),
                Expr::Call { .. } => values.push(None),
                Expr::Cast { target, .. } => values.push(Some(target.clone())),
                Expr::BinOp { op, left, right } => match op {
                    BinOp::Add
                    | BinOp::Sub
                    | BinOp::Mul
                    | BinOp::Div
                    | BinOp::SaturatingAdd
                    | BinOp::SaturatingSub
                    | BinOp::SaturatingMul
                    | BinOp::Min
                    | BinOp::Max => {
                        frames.push(Frame::Bin);
                        frames.push(Frame::Enter(right));
                        frames.push(Frame::Enter(left));
                    }
                    // Logical And/Or and all comparisons evaluate to Bool.
                    // The reference interpreter produces Value::Bool here, so
                    // the static type must match or programs like `(a && b) + 1`
                    // pass validation and then fail at interpreter time.
                    BinOp::And
                    | BinOp::Or
                    | BinOp::Eq
                    | BinOp::Ne
                    | BinOp::Lt
                    | BinOp::Gt
                    | BinOp::Le
                    | BinOp::Ge => values.push(Some(DataType::Bool)),
                    // Bitwise / mod / shifts are integer-typed. U32 is the safe
                    // default; the operand-checker already rejects non-integer
                    // operands.
                    _ => values.push(Some(DataType::U32)),
                },
                Expr::UnOp { op, operand } => match op {
                    crate::ir_inner::model::types::UnOp::Negate
                    | crate::ir_inner::model::types::UnOp::BitNot
                    | crate::ir_inner::model::types::UnOp::Popcount
                    | crate::ir_inner::model::types::UnOp::Clz
                    | crate::ir_inner::model::types::UnOp::Ctz
                    | crate::ir_inner::model::types::UnOp::ReverseBits => {
                        frames.push(Frame::Un);
                        frames.push(Frame::Enter(operand));
                    }
                    // GAP-4 fix: LogicalNot produces Bool, not U32. The Naga
                    // lowering emits `x == 0u` for integer operands which
                    // yields `bool`. The prior U32 typing allowed `!x + 1`
                    // to pass validation while lowering produced a type error.
                    crate::ir_inner::model::types::UnOp::LogicalNot => {
                        values.push(Some(DataType::Bool))
                    }
                    crate::ir_inner::model::types::UnOp::Sin
                    | crate::ir_inner::model::types::UnOp::Cos
                    | crate::ir_inner::model::types::UnOp::Exp
                    | crate::ir_inner::model::types::UnOp::Log
                    | crate::ir_inner::model::types::UnOp::Log2
                    | crate::ir_inner::model::types::UnOp::Exp2
                    | crate::ir_inner::model::types::UnOp::Tan
                    | crate::ir_inner::model::types::UnOp::Acos
                    | crate::ir_inner::model::types::UnOp::Asin
                    | crate::ir_inner::model::types::UnOp::Atan
                    | crate::ir_inner::model::types::UnOp::Tanh
                    | crate::ir_inner::model::types::UnOp::Sinh
                    | crate::ir_inner::model::types::UnOp::Cosh
                    | crate::ir_inner::model::types::UnOp::Abs
                    | crate::ir_inner::model::types::UnOp::Sqrt
                    | crate::ir_inner::model::types::UnOp::InverseSqrt
                    | crate::ir_inner::model::types::UnOp::Floor
                    | crate::ir_inner::model::types::UnOp::Ceil
                    | crate::ir_inner::model::types::UnOp::Round
                    | crate::ir_inner::model::types::UnOp::Trunc
                    | crate::ir_inner::model::types::UnOp::Sign => values.push(Some(DataType::F32)),
                    crate::ir_inner::model::types::UnOp::IsNan
                    | crate::ir_inner::model::types::UnOp::IsInf
                    | crate::ir_inner::model::types::UnOp::IsFinite => {
                        values.push(Some(DataType::Bool))
                    }
                    _ => values.push(None),
                },
                Expr::Select {
                    true_val,
                    false_val,
                    ..
                } => {
                    frames.push(Frame::Select);
                    frames.push(Frame::Enter(false_val));
                    frames.push(Frame::Enter(true_val));
                }
                Expr::Fma { a, b, c } => {
                    frames.push(Frame::Fma);
                    frames.push(Frame::Enter(c));
                    frames.push(Frame::Enter(b));
                    frames.push(Frame::Enter(a));
                }
                &Expr::SubgroupBallot { .. } => {
                    values.push(Some(crate::ir_inner::model::types::DataType::U32))
                }
                // GAP-3 fix: SubgroupShuffle/Add must push a value onto
                // the type-inference stack. The prior empty body desync'd
                // the stack when these expressions appeared inside compound
                // expressions (BinOp, Select, etc.). Both operations
                // produce the same type as their value operand — U32 is
                // the conservative default since the IR currently restricts
                // subgroup ops to integer types.
                &Expr::SubgroupShuffle { .. } | &Expr::SubgroupAdd { .. } => {
                    values.push(Some(DataType::U32))
                }

                Expr::Opaque(extension) => values.push(extension.result_type()),
            },
            Frame::Bin => {
                let r = values.pop().unwrap_or(None);
                let l = values.pop().unwrap_or(None);
                if l == r && l == Some(DataType::F32) {
                    values.push(Some(DataType::F32));
                } else {
                    values.push(Some(
                        l.as_ref()
                            .filter(|_| l == r)
                            .cloned()
                            .unwrap_or(DataType::U32),
                    ));
                }
            }
            Frame::Un => {
                let operand = values.pop().unwrap_or(None);
                values.push(operand);
            }
            Frame::Select => {
                let f = values.pop().unwrap_or(None);
                let t = values.pop().unwrap_or(None);
                values.push(if t == f { t } else { None });
            }
            Frame::Fma => {
                let tc = values.pop().unwrap_or(None);
                let tb = values.pop().unwrap_or(None);
                let ta = values.pop().unwrap_or(None);
                values.push(
                    if ta == Some(DataType::F32)
                        && tb == Some(DataType::F32)
                        && tc == Some(DataType::F32)
                    {
                        Some(DataType::F32)
                    } else {
                        None
                    },
                );
            }
        }
    }
    values.pop().flatten()
}

#[cfg(test)]
#[path = "typecheck_critical_test.rs"]
mod typecheck_critical_test;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir_inner::model::expr::Expr;

    fn empty_buffers() -> FxHashMap<&'static str, &'static BufferDecl> {
        FxHashMap::default()
    }
    fn empty_scope() -> FxHashMap<String, Binding> {
        FxHashMap::default()
    }

    fn bin(op: BinOp, l: Expr, r: Expr) -> Expr {
        Expr::BinOp {
            op,
            left: Box::new(l),
            right: Box::new(r),
        }
    }

    #[test]
    fn and_or_type_is_bool() {
        for op in [BinOp::And, BinOp::Or] {
            let e = bin(op, Expr::LitBool(true), Expr::LitBool(false));
            assert_eq!(
                expr_type(&e, &empty_buffers(), &empty_scope()),
                Some(DataType::Bool),
                "And/Or must type as Bool (reference interpreter produces Value::Bool)"
            );
        }
    }

    #[test]
    fn comparisons_type_is_bool() {
        for op in [
            BinOp::Eq,
            BinOp::Ne,
            BinOp::Lt,
            BinOp::Gt,
            BinOp::Le,
            BinOp::Ge,
        ] {
            let e = bin(op, Expr::LitU32(1), Expr::LitU32(2));
            assert_eq!(
                expr_type(&e, &empty_buffers(), &empty_scope()),
                Some(DataType::Bool),
                "comparison must type as Bool"
            );
        }
    }

    #[test]
    fn bitwise_type_is_integer() {
        let e = bin(BinOp::BitAnd, Expr::LitU32(1), Expr::LitU32(2));
        assert_eq!(
            expr_type(&e, &empty_buffers(), &empty_scope()),
            Some(DataType::U32)
        );
    }

    #[test]
    fn bool_plus_int_is_rejected() -> Result<(), String> {
        // Regression for REF-002: `(a && b) + 1` — previously accepted because
        // And was typed U32. Now And types as Bool, so arithmetic must reject.
        let and_expr = bin(BinOp::And, Expr::LitBool(true), Expr::LitBool(false));
        let add_expr = bin(BinOp::Add, and_expr, Expr::LitU32(1));
        let mut errors = Vec::new();
        if let Expr::BinOp { op, left, right } = &add_expr {
            validate_binop_operands(
                op,
                left,
                right,
                &empty_buffers(),
                &empty_scope(),
                &mut errors,
            );
        } else {
            return Err("expected BinOp".to_string());
        }
        assert!(
            !errors.is_empty(),
            "arithmetic on a Bool-typed operand must be rejected"
        );
        Ok(())
    }
}
