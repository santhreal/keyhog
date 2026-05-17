use crate::ir::{BinOp, Expr, UnOp};
use crate::optimizer::passes::fusion_cse::cse::expr_key::{ExprId, ExprKey};
use crate::optimizer::passes::fusion_cse::cse::{is_commutative, CseCtx, TypeKey};
use smallvec::SmallVec;

impl CseCtx {
    #[inline]
    pub(crate) fn intern_expr(&mut self, expr: &Expr) -> ExprId {
        // Soundness (S19): pointer-keyed cache removed. See the
        // matching comment in `impl_csectx.rs::expr` — `Box<Expr>`
        // addresses are reused as Cow::Owned rewrites churn through
        // them, so caching by raw pointer returned stale ExprIds and
        // CSE merged semantically distinct expressions. The
        // `deduplication` map below still amortises intern cost
        // through structural key lookup.
        self.intern_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let key = match expr {
            Expr::LitU32(value) => ExprKey::LitU32(*value),
            Expr::LitI32(value) => ExprKey::LitI32(*value),
            Expr::LitF32(value) => ExprKey::LitF32(value.to_bits()),
            Expr::LitBool(value) => ExprKey::LitBool(*value),
            Expr::Var(name) => ExprKey::Var(name.clone()),
            Expr::Load { buffer, index } => ExprKey::Load(buffer.clone(), self.intern_expr(index)),
            Expr::BufLen { buffer } => ExprKey::BufLen(buffer.clone()),
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
                op_id.clone(),
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
            Expr::Opaque(extension) => {
                ExprKey::Opaque(extension.extension_kind(), extension.stable_fingerprint())
            }
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
    // Soundness: every concrete BinOp variant gets a distinct tag so
    // CSE never merges semantically distinct ops. The previous
    // `_ => 255` fallback collapsed WrappingSub / RotateLeft /
    // RotateRight / MulHigh onto a single tag — silent CSE soundness
    // gap waiting on an adversarial input. `BinOp::Opaque` is keyed
    // separately via `ExprKey::BinOpOpaque` (carries the extension u32
    // id) so the integer table below covers only built-in variants.
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
        BinOp::WrappingAdd => 28,
        BinOp::WrappingSub => 29,
        BinOp::RotateLeft => 30,
        BinOp::RotateRight => 31,
        BinOp::MulHigh => 32,
        // Opaque is handled via ExprKey::BinOpOpaque before this
        // function is called; reaching this arm is a soundness bug.
        BinOp::Opaque(_) => unreachable!(
            "bin_op_key called on BinOp::Opaque; route through ExprKey::BinOpOpaque instead"
        ),
        // Catch new BinOp variants explicitly. Adding a variant
        // without extending this table would silently reuse tag 255
        // and merge unrelated ops in CSE. Update the match the moment
        // a new variant lands.
        _ => panic!("bin_op_key missing an arm for BinOp variant `{op:?}` — assign a unique tag"),
    }
}

#[inline]
fn un_op_key(op: &UnOp) -> u8 {
    // Same soundness contract as bin_op_key: every concrete UnOp
    // variant gets a distinct tag. `UnOp::Opaque` is keyed separately
    // via `ExprKey::UnOpOpaque`, so the table covers only built-ins.
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
        UnOp::Reciprocal => 12,
        UnOp::Floor => 13,
        UnOp::Ceil => 14,
        UnOp::Round => 15,
        UnOp::Trunc => 16,
        UnOp::Sign => 17,
        UnOp::IsNan => 18,
        UnOp::IsInf => 19,
        UnOp::IsFinite => 20,
        UnOp::Exp => 21,
        UnOp::Log => 22,
        UnOp::Tan => 23,
        UnOp::Acos => 24,
        UnOp::Asin => 25,
        UnOp::Atan => 26,
        UnOp::Tanh => 27,
        UnOp::Sinh => 28,
        UnOp::Cosh => 29,
        UnOp::Opaque(_) => unreachable!(
            "un_op_key called on UnOp::Opaque; route through ExprKey::UnOpOpaque instead"
        ),
        _ => panic!("un_op_key missing an arm for UnOp variant `{op:?}` — assign a unique tag"),
    }
}
