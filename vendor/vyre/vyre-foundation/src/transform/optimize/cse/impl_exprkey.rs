use crate::ir::{BinOp, Expr, UnOp};
use crate::transform::optimize::cse::expr_key::{ExprId, ExprKey};
use crate::transform::optimize::cse::{is_commutative, CseCtx, TypeKey};
use smallvec::SmallVec;
use std::sync::Arc;

impl CseCtx {
    #[inline]
    pub(crate) fn intern_expr(&mut self, expr: &Expr) -> ExprId {
        let key = match expr {
            Expr::LitU32(value) => ExprKey::LitU32(*value),
            Expr::LitI32(value) => ExprKey::LitI32(*value),
            Expr::LitF32(value) => ExprKey::LitF32(value.to_bits()),
            Expr::LitBool(value) => ExprKey::LitBool(*value),
            Expr::Var(name) => ExprKey::Var(Arc::from(name.as_str())),
            Expr::Load { buffer, index } => {
                ExprKey::Load(Arc::from(buffer.as_str()), self.intern_expr(index))
            }
            Expr::BufLen { buffer } => ExprKey::BufLen(Arc::from(buffer.as_str())),
            Expr::InvocationId { axis } => ExprKey::InvocationId(*axis),
            Expr::WorkgroupId { axis } => ExprKey::WorkgroupId(*axis),
            Expr::LocalId { axis } => ExprKey::LocalId(*axis),
            Expr::BinOp { op, left, right } => {
                let mut l = self.intern_expr(left);
                let mut r = self.intern_expr(right);
                if is_commutative(op) && r < l {
                    std::mem::swap(&mut l, &mut r);
                }
                match op {
                    BinOp::Opaque(id) => ExprKey::BinOpOpaque(id.as_u32(), l, r),
                    _ => ExprKey::BinOp(bin_op_key(op), l, r),
                }
            }
            Expr::UnOp { op, operand } => {
                let operand_id = self.intern_expr(operand);
                match op {
                    UnOp::Opaque(id) => ExprKey::UnOpOpaque(id.as_u32(), operand_id),
                    _ => ExprKey::UnOp(un_op_key(op), operand_id),
                }
            }
            Expr::Call { op_id, args } => ExprKey::Call(
                Arc::from(op_id.as_str()),
                args.iter()
                    .map(|arg| self.intern_expr(arg))
                    .collect::<SmallVec<[ExprId; 4]>>(),
            ),
            Expr::Fma { a, b, c } => ExprKey::Fma(
                self.intern_expr(a),
                self.intern_expr(b),
                self.intern_expr(c),
            ),
            Expr::Select {
                cond,
                true_val,
                false_val,
            } => ExprKey::Select(
                self.intern_expr(cond),
                self.intern_expr(true_val),
                self.intern_expr(false_val),
            ),
            Expr::Cast { target, value } => {
                ExprKey::Cast(TypeKey::from(target), self.intern_expr(value))
            }
            Expr::Atomic { .. } => ExprKey::Atomic,
            &Expr::SubgroupBallot { .. }
            | &Expr::SubgroupShuffle { .. }
            | &Expr::SubgroupAdd { .. } => {
                let id = self.subgroup_counter;
                self.subgroup_counter = self.subgroup_counter.wrapping_add(1);
                ExprKey::Subgroup(id)
            }
            Expr::SubgroupLocalId => ExprKey::SubgroupLocalId,
            Expr::SubgroupSize => ExprKey::SubgroupSize,
            Expr::Opaque(extension) => ExprKey::Opaque(
                Arc::from(extension.extension_kind()),
                extension.stable_fingerprint(),
            ),
        };

        if let Some(&id) = self.deduplication.get(&key) {
            id
        } else {
            let id = ExprId(self.arena.len() as u32);
            self.arena.push(key.clone());
            self.deduplication.insert(key, id);
            id
        }
    }
}

#[inline]
fn bin_op_key(op: &BinOp) -> u8 {
    match op {
        BinOp::Add => 0,
        BinOp::Sub => 1,
        BinOp::Mul => 2,
        BinOp::Div => 3,
        BinOp::Mod => 4,
        BinOp::BitAnd => 5,
        BinOp::BitOr => 6,
        BinOp::BitXor => 7,
        BinOp::Shl => 8,
        BinOp::Shr => 9,
        BinOp::Eq => 10,
        BinOp::Ne => 11,
        BinOp::Lt => 12,
        BinOp::Gt => 13,
        BinOp::Le => 14,
        BinOp::Ge => 15,
        BinOp::And => 16,
        BinOp::Or => 17,
        BinOp::AbsDiff => 18,
        BinOp::Min => 19,
        BinOp::Max => 20,
        BinOp::SaturatingAdd => 21,
        BinOp::SaturatingSub => 22,
        BinOp::SaturatingMul => 23,
        BinOp::Shuffle => 24,
        BinOp::Ballot => 25,
        BinOp::WaveReduce => 26,
        BinOp::WaveBroadcast => 27,
        _ => 255,
    }
}

#[inline]
fn un_op_key(op: &UnOp) -> u8 {
    match op {
        UnOp::Negate => 0,
        UnOp::BitNot => 1,
        UnOp::LogicalNot => 2,
        UnOp::Popcount => 3,
        UnOp::Clz => 4,
        UnOp::Ctz => 5,
        UnOp::ReverseBits => 6,
        UnOp::Sin => 7,
        UnOp::Cos => 8,
        UnOp::Abs => 9,
        UnOp::Sqrt => 10,
        UnOp::InverseSqrt => 11,
        UnOp::Floor => 12,
        UnOp::Ceil => 13,
        UnOp::Round => 14,
        UnOp::Trunc => 15,
        UnOp::Sign => 16,
        UnOp::IsNan => 17,
        UnOp::IsInf => 18,
        UnOp::IsFinite => 19,
        UnOp::Exp => 20,
        UnOp::Log => 21,
        UnOp::Log2 => 22,
        UnOp::Exp2 => 23,
        UnOp::Tan => 24,
        UnOp::Acos => 25,
        UnOp::Asin => 26,
        UnOp::Atan => 27,
        UnOp::Tanh => 28,
        UnOp::Sinh => 29,
        UnOp::Cosh => 30,
        _ => 255,
    }
}
