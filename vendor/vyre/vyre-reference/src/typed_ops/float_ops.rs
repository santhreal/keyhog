//! IEEE-754 `f32` operation semantics for the reference interpreter.

use vyre::ir::{BinOp, UnOp};
use vyre::Error;

use crate::value::Value;

pub(super) fn binop_f32(op: BinOp, left: f32, right: f32) -> Result<Value, vyre::Error> {
    let wrap = |v: f32| Value::Float(f64::from(v));
    match op {
        BinOp::Add => Ok(wrap(left + right)),
        BinOp::Sub => Ok(wrap(left - right)),
        BinOp::Mul => Ok(wrap(left * right)),
        BinOp::Div => Ok(wrap(left / right)),
        BinOp::Min => Ok(wrap(f32::min(left, right))),
        BinOp::Max => Ok(wrap(f32::max(left, right))),
        BinOp::Eq => Ok(Value::Bool(left == right)),
        BinOp::Ne => Ok(Value::Bool(left != right)),
        BinOp::Lt => Ok(Value::Bool(left < right)),
        BinOp::Gt => Ok(Value::Bool(left > right)),
        BinOp::Le => Ok(Value::Bool(left <= right)),
        BinOp::Ge => Ok(Value::Bool(left >= right)),
        _ => Err(Error::interp(format!(
            "binary op `{op:?}` is not defined for f32 operands. Fix: use arithmetic or comparison ops only for float primitives."
        ))),
    }
}

pub(super) fn unop_f32(op: UnOp, value: f32) -> Result<Value, vyre::Error> {
    let wrap = |v: f32| Value::Float(f64::from(v));
    match op {
        UnOp::Negate => Ok(wrap(-value)),
        UnOp::Abs => Ok(wrap(value.abs())),
        UnOp::Sqrt => Ok(wrap(value.sqrt())),
        UnOp::InverseSqrt => Ok(wrap(1.0 / value.sqrt())),
        UnOp::Sin => Ok(wrap(value.sin())),
        UnOp::Cos => Ok(wrap(value.cos())),
        UnOp::Floor => Ok(wrap(value.floor())),
        UnOp::Ceil => Ok(wrap(value.ceil())),
        UnOp::Round => Ok(wrap(value.round())),
        UnOp::Trunc => Ok(wrap(value.trunc())),
        UnOp::Sign => Ok(wrap(sign(value))),
        UnOp::IsNan => Ok(Value::Bool(value.is_nan())),
        UnOp::IsInf => Ok(Value::Bool(value.is_infinite())),
        UnOp::IsFinite => Ok(Value::Bool(value.is_finite())),
        // V7-CORR-005: softmax + attention emit Expr::UnOp { op: Exp, .. }
        // and need a reference eval path so CPU ref executes cleanly.
        UnOp::Exp => Ok(wrap(value.exp())),
        UnOp::Log => Ok(wrap(value.ln())),
        UnOp::Log2 => Ok(wrap(value.log2())),
        UnOp::Exp2 => Ok(wrap(value.exp2())),
        UnOp::Tan => Ok(wrap(value.tan())),
        UnOp::Acos => Ok(wrap(value.acos())),
        UnOp::Asin => Ok(wrap(value.asin())),
        UnOp::Atan => Ok(wrap(value.atan())),
        UnOp::Tanh => Ok(wrap(value.tanh())),
        UnOp::Sinh => Ok(wrap(value.sinh())),
        UnOp::Cosh => Ok(wrap(value.cosh())),
        _ => Err(Error::interp(format!(
            "unary op `{op:?}` is not defined for f32 operands. Fix: use numeric or IEEE-754 classification ops only for float primitives."
        ))),
    }
}

fn sign(value: f32) -> f32 {
    if value.is_nan() {
        f32::NAN
    } else if value > 0.0 {
        1.0
    } else if value < 0.0 {
        -1.0
    } else {
        0.0
    }
}
