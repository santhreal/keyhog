//! Variant-preserving primitive BinOp and UnOp dispatch.

use vyre::ir::{BinOp, UnOp};
use vyre::Error;

use crate::value::Value;

mod float_ops;

use float_ops::{binop_f32, unop_f32};

pub(super) fn eval_binop(op: BinOp, left: Value, right: Value) -> Result<Value, vyre::Error> {
    // Shared-arity ops that the int_bin_helpers macro does not generate:
    // Min, Max, AbsDiff. Handled before per-type dispatch so we do not
    // have to retrofit them into every macro invocation.
    if let (Value::U32(l), Value::U32(r)) = (&left, &right) {
        if let Some(v) = u32_shared_binop(&op, *l, *r) {
            return Ok(v);
        }
    }
    if let (Value::I32(l), Value::I32(r)) = (&left, &right) {
        if let Some(v) = i32_shared_binop(&op, *l, *r) {
            return Ok(v);
        }
    }
    if let (Value::U64(l), Value::U64(r)) = (&left, &right) {
        if let Some(v) = u64_shared_binop(&op, *l, *r) {
            return Ok(v);
        }
    }
    match (left, right) {
        (Value::U32(left), Value::U32(right)) => binop_u32(op, left, right),
        (Value::I32(left), Value::I32(right)) => binop_i32(op, left, right),
        (Value::U64(left), Value::U64(right)) => binop_u64(op, left, right),
        (Value::Bool(left), Value::Bool(right)) => binop_bool(op, left, right),
        (Value::Float(left), Value::Float(right)) => binop_f32(op, left as f32, right as f32),
        (left, right) => Err(Error::interp(format!(
            "binary op `{op:?}` received mismatched operands {left:?} and {right:?}. Fix: insert an explicit Cast so both operands have the same primitive type."
        ))),
    }
}

fn u32_shared_binop(op: &BinOp, left: u32, right: u32) -> Option<Value> {
    match op {
        BinOp::Min => Some(Value::U32(left.min(right))),
        BinOp::Max => Some(Value::U32(left.max(right))),
        BinOp::AbsDiff => Some(Value::U32(left.abs_diff(right))),
        // `right` is taken mod 32 (WGSL shift-mask semantics extend
        // naturally to rotates). `rotate_left(0)` / `rotate_right(0)`
        // are the identity and would otherwise produce UB on some
        // platforms via `x << 32`.
        BinOp::RotateLeft => Some(Value::U32(left.rotate_left(right & 31))),
        BinOp::RotateRight => Some(Value::U32(left.rotate_right(right & 31))),
        BinOp::WrappingAdd => Some(Value::U32(left.wrapping_add(right))),
        BinOp::WrappingSub => Some(Value::U32(left.wrapping_sub(right))),
        BinOp::SaturatingAdd => Some(Value::U32(left.saturating_add(right))),
        BinOp::SaturatingSub => Some(Value::U32(left.saturating_sub(right))),
        BinOp::SaturatingMul => Some(Value::U32(left.saturating_mul(right))),
        _ => None,
    }
}

fn i32_shared_binop(op: &BinOp, left: i32, right: i32) -> Option<Value> {
    match op {
        BinOp::Min => Some(Value::I32(left.min(right))),
        BinOp::Max => Some(Value::I32(left.max(right))),
        BinOp::AbsDiff => Some(Value::U32(left.abs_diff(right))),
        BinOp::WrappingAdd => Some(Value::I32(left.wrapping_add(right))),
        BinOp::WrappingSub => Some(Value::I32(left.wrapping_sub(right))),
        BinOp::SaturatingAdd => Some(Value::I32(left.saturating_add(right))),
        BinOp::SaturatingSub => Some(Value::I32(left.saturating_sub(right))),
        BinOp::SaturatingMul => Some(Value::I32(left.saturating_mul(right))),
        _ => None,
    }
}

fn u64_shared_binop(op: &BinOp, left: u64, right: u64) -> Option<Value> {
    match op {
        BinOp::Min => Some(Value::U64(left.min(right))),
        BinOp::Max => Some(Value::U64(left.max(right))),
        BinOp::AbsDiff => Some(Value::U64(left.abs_diff(right))),
        BinOp::WrappingAdd => Some(Value::U64(left.wrapping_add(right))),
        BinOp::WrappingSub => Some(Value::U64(left.wrapping_sub(right))),
        BinOp::SaturatingAdd => Some(Value::U64(left.saturating_add(right))),
        BinOp::SaturatingSub => Some(Value::U64(left.saturating_sub(right))),
        BinOp::SaturatingMul => Some(Value::U64(left.saturating_mul(right))),
        _ => None,
    }
}

pub(super) fn eval_unop(op: UnOp, operand: Value) -> Result<Value, vyre::Error> {
    match operand {
        Value::U32(value) => unop_u32(op, value),
        Value::I32(value) => unop_i32(op, value),
        Value::U64(value) => unop_u64(op, value),
        Value::Bool(value) => unop_bool(op, value),
        Value::Float(value) => unop_f32(op, value as f32),
        value => Err(Error::interp(format!(
            "unary op `{op:?}` received non-primitive operand {value:?}. Fix: load or cast to a scalar primitive before applying unary ops."
        ))),
    }
}

macro_rules! int_bin_helpers {
    (
        $ty:ty,
        $value:ident,
        $shift:expr,
        $div:expr,
        $rem:expr,
        $binop:ident,
        $add:ident,
        $sub:ident,
        $mul:ident,
        $div_fn:ident,
        $mod_fn:ident,
        $bit_and:ident,
        $bit_or:ident,
        $bit_xor:ident,
        $shl:ident,
        $shr:ident,
        $eq:ident,
        $ne:ident,
        $lt:ident,
        $gt:ident,
        $le:ident,
        $ge:ident,
        $and:ident,
        $or:ident
    ) => {
        fn $add(left: $ty, right: $ty) -> Value {
            Value::$value(left.wrapping_add(right))
        }

        fn $sub(left: $ty, right: $ty) -> Value {
            Value::$value(left.wrapping_sub(right))
        }

        fn $mul(left: $ty, right: $ty) -> Value {
            Value::$value(left.wrapping_mul(right))
        }

        fn $div_fn(left: $ty, right: $ty) -> Value {
            Value::$value($div(left, right))
        }

        fn $mod_fn(left: $ty, right: $ty) -> Value {
            Value::$value($rem(left, right))
        }

        fn $bit_and(left: $ty, right: $ty) -> Value {
            Value::$value(left & right)
        }

        fn $bit_or(left: $ty, right: $ty) -> Value {
            Value::$value(left | right)
        }

        fn $bit_xor(left: $ty, right: $ty) -> Value {
            Value::$value(left ^ right)
        }

        fn $shl(left: $ty, right: $ty) -> Value {
            Value::$value($shift(left, right, true))
        }

        fn $shr(left: $ty, right: $ty) -> Value {
            Value::$value($shift(left, right, false))
        }

        fn $eq(left: $ty, right: $ty) -> Value {
            Value::Bool(left == right)
        }

        fn $ne(left: $ty, right: $ty) -> Value {
            Value::Bool(left != right)
        }

        fn $lt(left: $ty, right: $ty) -> Value {
            Value::Bool(left < right)
        }

        fn $gt(left: $ty, right: $ty) -> Value {
            Value::Bool(left > right)
        }

        fn $le(left: $ty, right: $ty) -> Value {
            Value::Bool(left <= right)
        }

        fn $ge(left: $ty, right: $ty) -> Value {
            Value::Bool(left >= right)
        }

        fn $and(left: $ty, right: $ty) -> Value {
            Value::Bool(left != 0 && right != 0)
        }

        fn $or(left: $ty, right: $ty) -> Value {
            Value::Bool(left != 0 || right != 0)
        }

        fn $binop(op: BinOp, left: $ty, right: $ty) -> Result<Value, vyre::Error> {
            match op {
                BinOp::Add => Ok($add(left, right)),
                BinOp::Sub => Ok($sub(left, right)),
                BinOp::Mul => Ok($mul(left, right)),
                BinOp::Div => Ok($div_fn(left, right)),
                BinOp::Mod => Ok($mod_fn(left, right)),
                BinOp::BitAnd => Ok($bit_and(left, right)),
                BinOp::BitOr => Ok($bit_or(left, right)),
                BinOp::BitXor => Ok($bit_xor(left, right)),
                BinOp::Shl => Ok($shl(left, right)),
                BinOp::Shr => Ok($shr(left, right)),
                BinOp::Eq => Ok($eq(left, right)),
                BinOp::Ne => Ok($ne(left, right)),
                BinOp::Lt => Ok($lt(left, right)),
                BinOp::Gt => Ok($gt(left, right)),
                BinOp::Le => Ok($le(left, right)),
                BinOp::Ge => Ok($ge(left, right)),
                BinOp::And => Ok($and(left, right)),
                BinOp::Or => Ok($or(left, right)),
                _ => Err(Error::interp(format!(
                    "unsupported IR `unknown BinOp variant: {op:?}`. Fix: update vyre-reference for the new vyre::ir variant."
                ))),
            }
        }
    };
}

macro_rules! int_un_helpers {
    (
        $ty:ty,
        $value:ident,
        $zero:expr,
        $unop:ident,
        $negate:ident,
        $bit_not:ident,
        $logical_not:ident,
        $popcount:ident,
        $clz:ident,
        $ctz:ident,
        $reverse_bits:ident
    ) => {
        fn $negate(value: $ty) -> Value {
            Value::$value($zero.wrapping_sub(value))
        }

        fn $bit_not(value: $ty) -> Value {
            Value::$value(!value)
        }

        fn $logical_not(value: $ty) -> Value {
            Value::Bool(value == 0)
        }

        fn $popcount(value: $ty) -> Value {
            Value::$value(value.count_ones() as $ty)
        }

        fn $clz(value: $ty) -> Value {
            Value::$value(value.leading_zeros() as $ty)
        }

        fn $ctz(value: $ty) -> Value {
            Value::$value(value.trailing_zeros() as $ty)
        }

        fn $reverse_bits(value: $ty) -> Value {
            Value::$value(value.reverse_bits())
        }

        fn $unop(op: UnOp, value: $ty) -> Result<Value, vyre::Error> {
            match op {
                UnOp::Negate => Ok($negate(value)),
                UnOp::BitNot => Ok($bit_not(value)),
                UnOp::LogicalNot => Ok($logical_not(value)),
                UnOp::Popcount => Ok($popcount(value)),
                UnOp::Clz => Ok($clz(value)),
                UnOp::Ctz => Ok($ctz(value)),
                UnOp::ReverseBits => Ok($reverse_bits(value)),
                _ => Err(Error::interp(format!(
                    "unsupported IR `unknown UnOp variant: {op:?}`. Fix: update vyre-reference for the new vyre::ir variant."
                ))),
            }
        }
    };
}

fn div_u32(left: u32, right: u32) -> u32 {
    if right == 0 {
        0
    } else {
        left / right
    }
}

fn rem_u32(left: u32, right: u32) -> u32 {
    if right == 0 {
        0
    } else {
        left % right
    }
}

fn shift_u32(left: u32, right: u32, left_shift: bool) -> u32 {
    // WGSL spec: shift amount is taken modulo the bit width.
    let shift = right & 31;
    if left_shift {
        left << shift
    } else {
        left >> shift
    }
}

fn div_i32(left: i32, right: i32) -> i32 {
    if right == 0 {
        0
    } else {
        left.wrapping_div(right)
    }
}

fn rem_i32(left: i32, right: i32) -> i32 {
    if right == 0 {
        0
    } else {
        left.wrapping_rem(right)
    }
}

fn shift_i32(left: i32, right: i32, left_shift: bool) -> i32 {
    // WGSL spec: shift amount is taken modulo the bit width.
    let shift = (right as u32) & 31;
    if left_shift {
        left.wrapping_shl(shift)
    } else {
        left.wrapping_shr(shift)
    }
}

fn div_u64(left: u64, right: u64) -> u64 {
    if right == 0 {
        0
    } else {
        left / right
    }
}

fn rem_u64(left: u64, right: u64) -> u64 {
    if right == 0 {
        0
    } else {
        left % right
    }
}

fn shift_u64(left: u64, right: u64, left_shift: bool) -> u64 {
    // WGSL spec: shift amount is taken modulo the bit width.
    let shift = right & 63;
    if left_shift {
        left << shift
    } else {
        left >> shift
    }
}

int_bin_helpers!(
    u32,
    U32,
    shift_u32,
    div_u32,
    rem_u32,
    binop_u32,
    bin_add_u32,
    bin_sub_u32,
    bin_mul_u32,
    bin_div_u32,
    bin_mod_u32,
    bin_bit_and_u32,
    bin_bit_or_u32,
    bin_bit_xor_u32,
    bin_shl_u32,
    bin_shr_u32,
    bin_eq_u32,
    bin_ne_u32,
    bin_lt_u32,
    bin_gt_u32,
    bin_le_u32,
    bin_ge_u32,
    bin_and_u32,
    bin_or_u32
);
int_bin_helpers!(
    i32,
    I32,
    shift_i32,
    div_i32,
    rem_i32,
    binop_i32,
    bin_add_i32,
    bin_sub_i32,
    bin_mul_i32,
    bin_div_i32,
    bin_mod_i32,
    bin_bit_and_i32,
    bin_bit_or_i32,
    bin_bit_xor_i32,
    bin_shl_i32,
    bin_shr_i32,
    bin_eq_i32,
    bin_ne_i32,
    bin_lt_i32,
    bin_gt_i32,
    bin_le_i32,
    bin_ge_i32,
    bin_and_i32,
    bin_or_i32
);
int_bin_helpers!(
    u64,
    U64,
    shift_u64,
    div_u64,
    rem_u64,
    binop_u64,
    bin_add_u64,
    bin_sub_u64,
    bin_mul_u64,
    bin_div_u64,
    bin_mod_u64,
    bin_bit_and_u64,
    bin_bit_or_u64,
    bin_bit_xor_u64,
    bin_shl_u64,
    bin_shr_u64,
    bin_eq_u64,
    bin_ne_u64,
    bin_lt_u64,
    bin_gt_u64,
    bin_le_u64,
    bin_ge_u64,
    bin_and_u64,
    bin_or_u64
);

int_un_helpers!(
    u32,
    U32,
    0u32,
    unop_u32,
    un_negate_u32,
    un_bit_not_u32,
    un_logical_not_u32,
    un_popcount_u32,
    un_clz_u32,
    un_ctz_u32,
    un_reverse_bits_u32
);
int_un_helpers!(
    i32,
    I32,
    0i32,
    unop_i32,
    un_negate_i32,
    un_bit_not_i32,
    un_logical_not_i32,
    un_popcount_i32,
    un_clz_i32,
    un_ctz_i32,
    un_reverse_bits_i32
);
int_un_helpers!(
    u64,
    U64,
    0u64,
    unop_u64,
    un_negate_u64,
    un_bit_not_u64,
    un_logical_not_u64,
    un_popcount_u64,
    un_clz_u64,
    un_ctz_u64,
    un_reverse_bits_u64
);

fn binop_bool(op: BinOp, left: bool, right: bool) -> Result<Value, vyre::Error> {
    match op {
        BinOp::Eq => Ok(Value::Bool(left == right)),
        BinOp::Ne => Ok(Value::Bool(left != right)),
        BinOp::And => Ok(Value::Bool(left && right)),
        BinOp::Or => Ok(Value::Bool(left || right)),
        _ => Err(Error::interp(format!(
            "binary op `{op:?}` is not defined for bool operands. Fix: cast bools to u32 before numeric or bitwise operations."
        ))),
    }
}

fn unop_bool(op: UnOp, value: bool) -> Result<Value, vyre::Error> {
    match op {
        UnOp::LogicalNot => Ok(Value::Bool(!value)),
        _ => Err(Error::interp(format!(
            "unary op `{op:?}` is not defined for bool operands. Fix: cast bool to u32 before numeric or bitwise unary operations."
        ))),
    }
}
