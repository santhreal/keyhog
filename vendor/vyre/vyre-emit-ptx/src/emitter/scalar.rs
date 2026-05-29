use std::fmt::Write as _;

use vyre_foundation::ir::{BinOp, DataType, UnOp};

use super::format::ptx_binop_suffix;
use super::names::unop_name;
use super::BodyCtx;
use crate::reg::{PtxType, Reg};
use crate::EmitError;

impl BodyCtx<'_> {
    pub(super) fn canonicalize_f32(&mut self, value: Reg) -> Reg {
        if value.0 != PtxType::F32 {
            return value;
        }
        let bits = self.alloc(PtxType::U32);
        let abs_bits = self.alloc(PtxType::U32);
        let sign_bits = self.alloc(PtxType::U32);
        let subnormal_or_zero = self.alloc(PtxType::Bool);
        let nan = self.alloc(PtxType::Bool);
        let no_subnormal_bits = self.alloc(PtxType::U32);
        let canonical_bits = self.alloc(PtxType::U32);
        let out = self.alloc(PtxType::F32);
        let _ = writeln!(self.text, "    mov.b32    {bits}, {value};");
        let _ = writeln!(self.text, "    and.b32    {abs_bits}, {bits}, 0x7fffffff;");
        let _ = writeln!(self.text, "    and.b32    {sign_bits}, {bits}, 0x80000000;");
        let _ = writeln!(
            self.text,
            "    setp.lt.u32    {subnormal_or_zero}, {abs_bits}, 0x00800000;"
        );
        let _ = writeln!(
            self.text,
            "    setp.gt.u32    {nan}, {abs_bits}, 0x7f800000;"
        );
        let _ = writeln!(
            self.text,
            "    selp.u32    {no_subnormal_bits}, {sign_bits}, {bits}, {subnormal_or_zero};"
        );
        let _ = writeln!(
            self.text,
            "    selp.u32    {canonical_bits}, 0x7fc00000, {no_subnormal_bits}, {nan};"
        );
        let _ = writeln!(self.text, "    mov.b32    {out}, {canonical_bits};");
        out
    }

    pub(super) fn coerce_for_store(&mut self, value: Reg, elem_ty: PtxType) -> Reg {
        if value.0 != PtxType::Bool || elem_ty == PtxType::Bool {
            return value;
        }
        let out = self.alloc(PtxType::U32);
        let _ = writeln!(self.text, "    selp.u32    {out}, 1, 0, {value};");
        out
    }

    pub(super) fn pred_from_boolish(&mut self, value: Reg) -> Reg {
        if value.0 == PtxType::Bool {
            return value;
        }
        let pred = self.alloc(PtxType::Bool);
        let _ = writeln!(self.text, "    setp.ne.u32    {pred}, {value}, 0;");
        pred
    }

    pub(super) fn emit_binop(
        &mut self,
        op: BinOp,
        left: Reg,
        right: Reg,
    ) -> Result<(Reg, PtxType), EmitError> {
        let ty = left.0;
        if ty == PtxType::Bool && matches!(op, BinOp::Eq | BinOp::Ne) {
            let out = self.alloc(PtxType::Bool);
            let xor = self.alloc(PtxType::Bool);
            let _ = writeln!(self.text, "    xor.pred    {xor}, {left}, {right};");
            if matches!(op, BinOp::Eq) {
                let _ = writeln!(self.text, "    not.pred    {out}, {xor};");
            } else {
                let _ = writeln!(self.text, "    mov.pred    {out}, {xor};");
            }
            return Ok((out, PtxType::Bool));
        }
        if matches!(
            op,
            BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge
        ) {
            let out = self.alloc(PtxType::Bool);
            let cmp = match op {
                BinOp::Eq => "eq",
                BinOp::Ne if ty == PtxType::F32 => "neu",
                BinOp::Ne => "ne",
                BinOp::Lt => "lt",
                BinOp::Le => "le",
                BinOp::Gt => "gt",
                BinOp::Ge => "ge",
                other => {
                    return Err(EmitError::InvalidDescriptor(format!(
                        "comparison lowering received non-comparison operator {other:?}. \
                         Fix: route arithmetic operators through the arithmetic PTX lowering path."
                    )));
                }
            };
            let suffix = if ty == PtxType::F32 {
                "f32"
            } else if ty == PtxType::I32 {
                "s32"
            } else {
                "u32"
            };
            let _ = writeln!(
                self.text,
                "    setp.{cmp}.{suffix}    {out}, {left}, {right};"
            );
            return Ok((out, PtxType::Bool));
        }
        match op {
            BinOp::AbsDiff if ty == PtxType::U32 || ty == PtxType::Bool => {
                let left_ge_right = self.alloc(PtxType::Bool);
                let hi = self.alloc(PtxType::U32);
                let lo = self.alloc(PtxType::U32);
                let out = self.alloc(PtxType::U32);
                let _ = writeln!(
                    self.text,
                    "    setp.ge.u32    {left_ge_right}, {left}, {right};"
                );
                let _ = writeln!(
                    self.text,
                    "    selp.u32    {hi}, {left}, {right}, {left_ge_right};"
                );
                let _ = writeln!(
                    self.text,
                    "    selp.u32    {lo}, {right}, {left}, {left_ge_right};"
                );
                let _ = writeln!(self.text, "    sub.u32    {out}, {hi}, {lo};");
                Ok((out, PtxType::U32))
            }
            BinOp::RotateLeft | BinOp::RotateRight
                if ty == PtxType::U32 || ty == PtxType::I32 || ty == PtxType::Bool =>
            {
                let out = self.alloc(ty);
                let direction = if matches!(op, BinOp::RotateLeft) {
                    "l"
                } else {
                    "r"
                };
                let _ = writeln!(
                    self.text,
                    "    shf.{direction}.wrap.b32    {out}, {left}, {left}, {right};"
                );
                Ok((out, ty))
            }
            BinOp::Shl | BinOp::Shr if ty == PtxType::U32 || ty == PtxType::I32 => {
                let out = self.alloc(ty);
                let masked_shift = self.alloc(PtxType::U32);
                let mnemonic = if matches!(op, BinOp::Shl) {
                    "shl"
                } else {
                    "shr"
                };
                let suffix = ptx_binop_suffix(op, ty);
                let _ = writeln!(self.text, "    and.b32    {masked_shift}, {right}, 31;");
                let _ = writeln!(
                    self.text,
                    "    {mnemonic}.{suffix}    {out}, {left}, {masked_shift};"
                );
                Ok((out, ty))
            }
            BinOp::Div if ty == PtxType::U32 || ty == PtxType::Bool => {
                let out = self.emit_total_u32_div(left, right);
                Ok((out, PtxType::U32))
            }
            BinOp::Mod if ty == PtxType::U32 || ty == PtxType::Bool => {
                let out = self.emit_total_u32_mod(left, right);
                Ok((out, PtxType::U32))
            }
            BinOp::Div if ty == PtxType::I32 => {
                let out = self.emit_total_i32_div(left, right);
                Ok((out, PtxType::I32))
            }
            BinOp::Div if ty == PtxType::F32 => {
                let out = self.alloc(PtxType::F32);
                let _ = writeln!(self.text, "    div.rn.f32    {out}, {left}, {right};");
                Ok((self.canonicalize_f32(out), PtxType::F32))
            }
            BinOp::Mod if ty == PtxType::I32 => {
                let out = self.emit_total_i32_mod(left, right);
                Ok((out, PtxType::I32))
            }
            BinOp::SaturatingAdd if ty == PtxType::U32 || ty == PtxType::Bool => {
                let sum = self.alloc(PtxType::U32);
                let overflow = self.alloc(PtxType::Bool);
                let out = self.alloc(PtxType::U32);
                let _ = writeln!(self.text, "    add.u32    {sum}, {left}, {right};");
                let _ = writeln!(self.text, "    setp.lt.u32    {overflow}, {sum}, {left};");
                let _ = writeln!(
                    self.text,
                    "    selp.u32    {out}, 0xffffffff, {sum}, {overflow};"
                );
                Ok((out, PtxType::U32))
            }
            BinOp::SaturatingSub if ty == PtxType::U32 || ty == PtxType::Bool => {
                let underflow = self.alloc(PtxType::Bool);
                let diff = self.alloc(PtxType::U32);
                let out = self.alloc(PtxType::U32);
                let _ = writeln!(
                    self.text,
                    "    setp.lt.u32    {underflow}, {left}, {right};"
                );
                let _ = writeln!(self.text, "    sub.u32    {diff}, {left}, {right};");
                let _ = writeln!(self.text, "    selp.u32    {out}, 0, {diff}, {underflow};");
                Ok((out, PtxType::U32))
            }
            _ => {
                let out_ty = if matches!(op, BinOp::And | BinOp::Or) && ty == PtxType::Bool {
                    PtxType::Bool
                } else {
                    ty
                };
                let out = self.alloc(out_ty);
                let mnemonic = match op {
                    BinOp::Add | BinOp::WrappingAdd => "add",
                    BinOp::Sub | BinOp::WrappingSub => "sub",
                    BinOp::Mul => {
                        if ty == PtxType::F32 {
                            "mul"
                        } else {
                            "mul.lo"
                        }
                    }
                    BinOp::MulHigh => "mul.hi",
                    BinOp::BitAnd | BinOp::And => "and",
                    BinOp::BitOr | BinOp::Or => "or",
                    BinOp::BitXor => "xor",
                    BinOp::Shl => "shl",
                    BinOp::Shr => "shr",
                    BinOp::Min => "min",
                    BinOp::Max => "max",
                    other => {
                        return Err(EmitError::PtxConstructionFailed(format!(
                            "BinOp `{other:?}` has no PTX lowering. Fix: add descriptor PTX emission before enabling this op on CUDA."
                        )));
                    }
                };
                let suffix = ptx_binop_suffix(op, ty);
                let _ = writeln!(
                    self.text,
                    "    {mnemonic}.{suffix}    {out}, {left}, {right};"
                );
                Ok((self.canonicalize_f32(out), out_ty))
            }
        }
    }

    pub(super) fn emit_small_u32_const_mul(&mut self, value: Reg, constant: u32) -> Option<Reg> {
        if !matches!(value.0, PtxType::U32 | PtxType::Bool) {
            return None;
        }
        if constant == 0 {
            let out = self.alloc(PtxType::U32);
            let _ = writeln!(self.text, "    mov.u32    {out}, 0;");
            return Some(out);
        }
        if constant == 1 {
            return Some(value);
        }
        if constant.is_power_of_two() {
            let out = self.alloc(PtxType::U32);
            let shift = constant.trailing_zeros();
            let _ = writeln!(self.text, "    shl.b32    {out}, {value}, {shift};");
            return Some(out);
        }
        if constant.count_ones() > 4 {
            return None;
        }
        let mut acc = None;
        for shift in 0..u32::BITS {
            if (constant & (1u32 << shift)) == 0 {
                continue;
            }
            let term = if shift == 0 {
                value
            } else {
                let shifted = self.alloc(PtxType::U32);
                let _ = writeln!(self.text, "    shl.b32    {shifted}, {value}, {shift};");
                shifted
            };
            acc = Some(match acc {
                Some(prev) => {
                    let out = self.alloc(PtxType::U32);
                    let _ = writeln!(self.text, "    add.u32    {out}, {prev}, {term};");
                    out
                }
                None => term,
            });
        }
        acc
    }

    pub(super) fn emit_fast_u32_const_div(&mut self, value: Reg, divisor: u32) -> Option<Reg> {
        if !matches!(value.0, PtxType::U32 | PtxType::Bool) || divisor == 0 {
            return None;
        }
        if divisor == 1 {
            return Some(value);
        }
        if divisor.is_power_of_two() {
            let out = self.alloc(PtxType::U32);
            let shift = divisor.trailing_zeros();
            let _ = writeln!(self.text, "    shr.u32    {out}, {value}, {shift};");
            return Some(out);
        }
        if divisor == 3 {
            let magic = self.alloc(PtxType::U32);
            let high = self.alloc(PtxType::U32);
            let out = self.alloc(PtxType::U32);
            let _ = writeln!(self.text, "    mov.u32    {magic}, 0xaaaaaaab;");
            let _ = writeln!(self.text, "    mul.hi.u32    {high}, {value}, {magic};");
            let _ = writeln!(self.text, "    shr.u32    {out}, {high}, 1;");
            return Some(out);
        }
        None
    }

    fn emit_total_u32_div(&mut self, left: Reg, right: Reg) -> Reg {
        let out = self.alloc(PtxType::U32);
        let pred = self.alloc(PtxType::Bool);
        let done = self.alloc_label("u32_div_done");
        let _ = writeln!(self.text, "    mov.u32    {out}, 0xffffffff;");
        let _ = writeln!(self.text, "    setp.eq.u32    {pred}, {right}, 0;");
        let _ = writeln!(self.text, "    @{pred} bra {done};");
        let _ = writeln!(self.text, "    div.u32    {out}, {left}, {right};");
        let _ = writeln!(self.text, "{done}:");
        out
    }

    fn emit_total_u32_mod(&mut self, left: Reg, right: Reg) -> Reg {
        let out = self.alloc(PtxType::U32);
        let pred = self.alloc(PtxType::Bool);
        let done = self.alloc_label("u32_mod_done");
        let _ = writeln!(self.text, "    mov.u32    {out}, 0;");
        let _ = writeln!(self.text, "    setp.eq.u32    {pred}, {right}, 0;");
        let _ = writeln!(self.text, "    @{pred} bra {done};");
        let _ = writeln!(self.text, "    rem.u32    {out}, {left}, {right};");
        let _ = writeln!(self.text, "{done}:");
        out
    }

    fn emit_total_i32_div(&mut self, left: Reg, right: Reg) -> Reg {
        let out = self.alloc(PtxType::I32);
        let zero = self.alloc(PtxType::Bool);
        let min = self.alloc(PtxType::Bool);
        let neg_one = self.alloc(PtxType::Bool);
        let overflow = self.alloc(PtxType::Bool);
        let overflow_label = self.alloc_label("i32_div_min_overflow");
        let done = self.alloc_label("i32_div_done");
        let _ = writeln!(self.text, "    mov.s32    {out}, 0;");
        let _ = writeln!(self.text, "    setp.eq.s32    {zero}, {right}, 0;");
        let _ = writeln!(self.text, "    @{zero} bra {done};");
        let _ = writeln!(self.text, "    setp.eq.u32    {min}, {left}, 0x80000000;");
        let _ = writeln!(
            self.text,
            "    setp.eq.u32    {neg_one}, {right}, 0xffffffff;"
        );
        let _ = writeln!(self.text, "    and.pred    {overflow}, {min}, {neg_one};");
        let _ = writeln!(self.text, "    @{overflow} bra {overflow_label};");
        let _ = writeln!(self.text, "    div.s32    {out}, {left}, {right};");
        let _ = writeln!(self.text, "    bra {done};");
        let _ = writeln!(self.text, "{overflow_label}:");
        let _ = writeln!(self.text, "    mov.u32    {out}, 0x80000000;");
        let _ = writeln!(self.text, "{done}:");
        out
    }

    fn emit_total_i32_mod(&mut self, left: Reg, right: Reg) -> Reg {
        let out = self.alloc(PtxType::I32);
        let zero = self.alloc(PtxType::Bool);
        let min = self.alloc(PtxType::Bool);
        let neg_one = self.alloc(PtxType::Bool);
        let overflow = self.alloc(PtxType::Bool);
        let done = self.alloc_label("i32_mod_done");
        let _ = writeln!(self.text, "    mov.s32    {out}, 0;");
        let _ = writeln!(self.text, "    setp.eq.s32    {zero}, {right}, 0;");
        let _ = writeln!(self.text, "    @{zero} bra {done};");
        let _ = writeln!(self.text, "    setp.eq.u32    {min}, {left}, 0x80000000;");
        let _ = writeln!(
            self.text,
            "    setp.eq.u32    {neg_one}, {right}, 0xffffffff;"
        );
        let _ = writeln!(self.text, "    and.pred    {overflow}, {min}, {neg_one};");
        let _ = writeln!(self.text, "    @{overflow} bra {done};");
        let _ = writeln!(self.text, "    rem.s32    {out}, {left}, {right};");
        let _ = writeln!(self.text, "{done}:");
        out
    }

    pub(super) fn emit_unop(&mut self, op: &UnOp, operand: Reg) -> Result<Reg, EmitError> {
        let out = match (op, operand.0) {
            (UnOp::Negate, PtxType::F32) => {
                let out = self.alloc(PtxType::F32);
                let _ = writeln!(self.text, "    neg.f32    {out}, {operand};");
                out
            }
            (UnOp::Negate, _) => {
                let out = self.alloc(PtxType::I32);
                let _ = writeln!(self.text, "    neg.s32    {out}, {operand};");
                out
            }
            (UnOp::BitNot, _) => {
                let out = self.alloc(PtxType::U32);
                let _ = writeln!(self.text, "    not.b32    {out}, {operand};");
                out
            }
            (UnOp::LogicalNot, _) => {
                let out = self.alloc(PtxType::Bool);
                if operand.0 == PtxType::Bool {
                    let _ = writeln!(self.text, "    not.pred    {out}, {operand};");
                } else {
                    let _ = writeln!(self.text, "    setp.eq.u32    {out}, {operand}, 0;");
                }
                out
            }
            (UnOp::Abs, PtxType::F32) => {
                let out = self.alloc(PtxType::F32);
                let _ = writeln!(self.text, "    abs.f32    {out}, {operand};");
                out
            }
            (UnOp::Abs, _) => {
                let out = self.alloc(PtxType::I32);
                let _ = writeln!(self.text, "    abs.s32    {out}, {operand};");
                out
            }
            (UnOp::Sqrt, PtxType::F32) => {
                let out = self.alloc(PtxType::F32);
                let _ = writeln!(self.text, "    sqrt.rn.f32    {out}, {operand};");
                out
            }
            (UnOp::InverseSqrt, PtxType::F32) => {
                let out = self.alloc(PtxType::F32);
                if self.options.ulp_budget.is_some_and(|budget| budget > 0) {
                    let _ = writeln!(self.text, "    rsqrt.approx.f32    {out}, {operand};");
                } else {
                    let _ = writeln!(self.text, "    sqrt.rn.f32    {out}, {operand};");
                    let _ = writeln!(self.text, "    rcp.rn.f32    {out}, {out};");
                }
                out
            }
            (UnOp::Reciprocal, PtxType::F32) => {
                let out = self.alloc(PtxType::F32);
                if self.options.ulp_budget.is_some_and(|budget| budget > 0) {
                    let _ = writeln!(self.text, "    rcp.approx.f32    {out}, {operand};");

                } else {
                    let _ = writeln!(self.text, "    rcp.rn.f32    {out}, {operand};");
                }
                out
            }
            (UnOp::Tanh, PtxType::F32) => {
                if !self.options.ulp_budget.is_some_and(|budget| budget > 0) {
                    return Err(EmitError::PtxConstructionFailed(
                        "CUDA PTX `tanh` lowering requires approximate transcendental instructions, but ulp_budget is not positive. Fix: set an explicit ULP budget for this dispatch or route to strict lowering.".into(),
                    ));
                }
                let out = self.alloc(PtxType::F32);
                let _ = writeln!(self.text, "    tanh.approx.f32    {out}, {operand};");
                out
            }
            (UnOp::Exp, PtxType::F32)
            | (UnOp::Log, PtxType::F32)
            | (UnOp::Exp2, PtxType::F32)
            | (UnOp::Log2, PtxType::F32)
            | (UnOp::Sin, PtxType::F32)
            | (UnOp::Cos, PtxType::F32) => {
                if !self.options.ulp_budget.is_some_and(|budget| budget > 0) {
                    return Err(EmitError::PtxConstructionFailed(format!(
                        "CUDA PTX `{op:?}` lowering requires approximate transcendental instructions, but ulp_budget is not positive. Fix: set an explicit ULP budget for this dispatch or route to strict lowering."
                    )));
                }
                let out = self.alloc(PtxType::F32);
                match op {
                    UnOp::Exp => {
                        let tmp = self.alloc(PtxType::F32);
                        let _ = writeln!(self.text, "    mul.f32    {tmp}, {operand}, 0f3FB8AA3B;");
                        let _ = writeln!(self.text, "    ex2.approx.f32    {out}, {tmp};");
                    }
                    UnOp::Log => {
                        let tmp = self.alloc(PtxType::F32);
                        let _ = writeln!(self.text, "    lg2.approx.f32    {tmp}, {operand};");
                        let _ = writeln!(self.text, "    mul.f32    {out}, {tmp}, 0f3F317218;");
                    }
                    UnOp::Exp2 => {
                        let _ = writeln!(self.text, "    ex2.approx.f32    {out}, {operand};");
                    }
                    UnOp::Log2 => {
                        let _ = writeln!(self.text, "    lg2.approx.f32    {out}, {operand};");
                    }
                    UnOp::Sin => {
                        let _ = writeln!(self.text, "    sin.approx.f32    {out}, {operand};");
                    }
                    UnOp::Cos => {
                        let _ = writeln!(self.text, "    cos.approx.f32    {out}, {operand};");
                    }
                    _ => {}
                }
                out
            }
            (UnOp::Floor, PtxType::F32) => {
                let out = self.alloc(PtxType::F32);
                let _ = writeln!(self.text, "    cvt.rmi.f32.f32    {out}, {operand};");
                out
            }
            (UnOp::Ceil, PtxType::F32) => {
                let out = self.alloc(PtxType::F32);
                let _ = writeln!(self.text, "    cvt.rpi.f32.f32    {out}, {operand};");
                out
            }
            (UnOp::Round, PtxType::F32) => {
                let out = self.alloc(PtxType::F32);
                let _ = writeln!(self.text, "    cvt.rni.f32.f32    {out}, {operand};");
                out
            }
            (UnOp::Trunc, PtxType::F32) => {
                let out = self.alloc(PtxType::F32);
                let _ = writeln!(self.text, "    cvt.rzi.f32.f32    {out}, {operand};");
                out
            }
            (UnOp::Popcount, _) => {
                let out = self.alloc(PtxType::U32);
                let _ = writeln!(self.text, "    popc.b32    {out}, {operand};");
                out
            }
            (UnOp::Clz, _) => {
                let out = self.alloc(PtxType::U32);
                let _ = writeln!(self.text, "    clz.b32    {out}, {operand};");
                out
            }
            (UnOp::Ctz, _) => {
                let reversed = self.alloc(PtxType::U32);
                let out = self.alloc(PtxType::U32);
                let _ = writeln!(self.text, "    brev.b32    {reversed}, {operand};");
                let _ = writeln!(self.text, "    clz.b32    {out}, {reversed};");
                out
            }
            (UnOp::ReverseBits, _) => {
                let out = self.alloc(PtxType::U32);
                let _ = writeln!(self.text, "    brev.b32    {out}, {operand};");
                out
            }
            (UnOp::IsNan, PtxType::F32) => {
                let out = self.alloc(PtxType::Bool);
                let _ = writeln!(
                    self.text,
                    "    setp.nan.f32    {out}, {operand}, {operand};"
                );
                out
            }
            (UnOp::IsInf, PtxType::F32) => {
                let bits = self.alloc(PtxType::U32);
                let abs = self.alloc(PtxType::U32);
                let out = self.alloc(PtxType::Bool);
                let _ = writeln!(self.text, "    mov.b32    {bits}, {operand};");
                let _ = writeln!(self.text, "    and.b32    {abs}, {bits}, 0x7fffffff;");
                let _ = writeln!(self.text, "    setp.eq.u32    {out}, {abs}, 0x7f800000;");
                out
            }
            (UnOp::IsFinite, PtxType::F32) => {
                let bits = self.alloc(PtxType::U32);
                let abs = self.alloc(PtxType::U32);
                let out = self.alloc(PtxType::Bool);
                let _ = writeln!(self.text, "    mov.b32    {bits}, {operand};");
                let _ = writeln!(self.text, "    and.b32    {abs}, {bits}, 0x7fffffff;");
                let _ = writeln!(self.text, "    setp.lt.u32    {out}, {abs}, 0x7f800000;");
                out
            }
            other => {
                return Err(EmitError::PtxConstructionFailed(format!(
                    "UnOp `{}` on {:?} has no PTX lowering. Fix: add descriptor PTX emission before enabling this op on CUDA.",
                    unop_name(other.0),
                    other.1
                )));
            }
        };
        Ok(self.canonicalize_f32(out))
    }

    pub(super) fn emit_cast(&mut self, src: Reg, target: &DataType) -> Result<Reg, EmitError> {
        let dst_ty = PtxType::from_dtype(target)?;
        if src.0 == dst_ty {
            return Ok(src);
        }
        let dst = self.alloc(dst_ty);
        match (src.0, dst_ty) {
            (PtxType::U32, PtxType::F32) => {
                let _ = writeln!(self.text, "    cvt.rn.f32.u32    {dst}, {src};");
            }
            (PtxType::I32, PtxType::F32) => {
                let _ = writeln!(self.text, "    cvt.rn.f32.s32    {dst}, {src};");
            }
            (PtxType::Bool, PtxType::F32) => {
                let word = self.alloc(PtxType::U32);
                let _ = writeln!(self.text, "    selp.u32    {word}, 1, 0, {src};");
                let _ = writeln!(self.text, "    cvt.rn.f32.u32    {dst}, {word};");
            }
            (PtxType::F32, PtxType::U32) => {
                let _ = writeln!(self.text, "    cvt.rzi.u32.f32    {dst}, {src};");
            }
            (PtxType::F32, PtxType::I32) => {
                let _ = writeln!(self.text, "    cvt.rzi.s32.f32    {dst}, {src};");
            }
            (PtxType::Bool, PtxType::U32) => {
                let _ = writeln!(self.text, "    selp.u32    {dst}, 1, 0, {src};");
            }
            (PtxType::Bool, PtxType::I32) => {
                let _ = writeln!(self.text, "    selp.u32    {dst}, 1, 0, {src};");
            }
            (PtxType::U32 | PtxType::I32, PtxType::Bool) => {
                let _ = writeln!(self.text, "    setp.ne.u32    {dst}, {src}, 0;");
            }
            (PtxType::F32, PtxType::Bool) => {
                let _ = writeln!(self.text, "    setp.neu.f32    {dst}, {src}, 0f00000000;");
            }
            (PtxType::U32, PtxType::I32) | (PtxType::I32, PtxType::U32) => {
                let _ = writeln!(self.text, "    mov.b32    {dst}, {src};");
            }
            _ => {
                return Err(EmitError::PtxConstructionFailed(format!(
                    "unsupported PTX cast from {:?} to {:?}. Fix: validate casts before CUDA emission.",
                    src.0, dst_ty
                )));
            }
        }
        Ok(dst)
    }

    pub(super) fn subgroup_lane_mask(&self) -> u32 {
        self.options.subgroup_size.saturating_sub(1)
    }

    pub(super) fn emit_subgroup_add(&mut self, value: Reg) -> Reg {
        let result = self.alloc(value.0);
        let mask = self.alloc(PtxType::U32);
        let _ = writeln!(self.text, "    activemask.b32    {mask};");
        let ptx_type = value.0.ptx_type_str();
        let _ = writeln!(
            self.text,
            "    redux.sync.add.{ptx_type}    {result}, {value}, {mask};"
        );
        result
    }
}

