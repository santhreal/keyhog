use super::{
    extension_ops::{emit_registered_atomic_op, emit_registered_bin_op, emit_registered_un_op},
    utils::*,
    FunctionBuilder, LoweringError, WgpuEmitExpr,
};
use naga::Span;
use naga::{
    BinaryOperator, CollectiveOperation, Expression, GatherMode, Literal, MathFunction, ScalarKind,
    Statement, SubgroupOperation, UnaryOperator, VectorSize,
};
use std::borrow::Cow;
use vyre_foundation::ir::{AtomicOp, BinOp, DataType, Expr, UnOp};
#[doc = " Recursively fold constant sub-expressions so the emitted WGSL never"]
#[doc = " contains a constant-evaluable integer overflow."]
#[doc = ""]
#[doc = " WGSL's shader-creation rules reject overflow in constant expressions,"]
#[doc = " even though runtime wraparound is well-defined. By folding literals on"]
#[doc = " the CPU we emit a single literal that matches the GPU runtime result."]
fn fold_expr(expr: &Expr) -> Option<Cow<'_, Expr>> {
    match expr {
        Expr::BinOp { op, left, right } => {
            let folded_left = fold_expr(left);
            let folded_right = fold_expr(right);
            let left = folded_left.as_deref().unwrap_or(left.as_ref());
            let right = folded_right.as_deref().unwrap_or(right.as_ref());
            fold_binary_literal(op, left, right).map(Cow::Owned)
        }
        Expr::Fma { a, b, c } => {
            let folded_a = fold_expr(a);
            let folded_b = fold_expr(b);
            let folded_c = fold_expr(c);
            let a = folded_a.as_deref().unwrap_or(a.as_ref());
            let b = folded_b.as_deref().unwrap_or(b.as_ref());
            let c = folded_c.as_deref().unwrap_or(c.as_ref());
            match (a, b, c) {
                (Expr::LitF32(a), Expr::LitF32(b), Expr::LitF32(c)) => {
                    Some(Cow::Owned(Expr::LitF32(a.mul_add(*b, *c))))
                }
                _ => None,
            }
        }
        Expr::UnOp { op, operand } => {
            let folded_operand = fold_expr(operand);
            let operand = folded_operand.as_deref().unwrap_or(operand.as_ref());
            fold_unary_literal(op, operand).map(Cow::Owned)
        }
        Expr::Cast { target, value } => {
            let folded_value = fold_expr(value);
            let value = folded_value.as_deref().unwrap_or(value.as_ref());
            fold_cast_literal(target, value).map(Cow::Owned)
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            let folded_cond = fold_expr(cond);
            let cond = folded_cond.as_deref().unwrap_or(cond.as_ref());
            match cond {
                Expr::LitBool(true) | Expr::LitU32(1..=u32::MAX) => {
                    Some(Cow::Borrowed(true_val.as_ref()))
                }
                Expr::LitBool(false) | Expr::LitU32(0) => Some(Cow::Borrowed(false_val.as_ref())),
                _ => None,
            }
        }
        _ => None,
    }
}
impl FunctionBuilder<'_> {
    pub(crate) fn emit_bool_expr(
        &mut self,
        expr: &Expr,
    ) -> Result<naga::Handle<Expression>, LoweringError> {
        let value = self.emit_expr(expr)?;
        self.emit_bool_from_handle(value, &expr_type(expr, self)?)
    }
    fn emit_bool_from_handle(
        &mut self,
        value: naga::Handle<Expression>,
        ty: &DataType,
    ) -> Result<naga::Handle<Expression>, LoweringError> {
        match ty {
            DataType::Bool => Ok(value),
            DataType::I8 | DataType::I16 | DataType::I32 => {
                let zero = self.append_expr(Expression::Literal(Literal::I32(0)));
                Ok(self.append_expr(Expression::Binary {
                    op: BinaryOperator::NotEqual,
                    left: value,
                    right: zero,
                }))
            }
            DataType::U8 | DataType::U16 | DataType::U32 => {
                let zero = self.append_expr(Expression::Literal(Literal::U32(0)));
                Ok(self.append_expr(Expression::Binary {
                    op: BinaryOperator::NotEqual,
                    left: value,
                    right: zero,
                }))
            }
            DataType::F32 => {
                let zero = self.append_expr(Expression::Literal(Literal::F32(0.0)));
                Ok(self.append_expr(Expression::Binary {
                    op: BinaryOperator::NotEqual,
                    left: value,
                    right: zero,
                }))
            }
            other => Err(LoweringError::invalid(format!(
                "cannot coerce `{other:?}` to bool in WGSL lowering. \
                 Fix: supported source types are Bool, I8/16/32, U8/16/32, F32 — \
                 cast `{other:?}` to one of these before the predicate site."
            ))),
        }
    }
    fn emit_subgroup_ballot_expr(
        &mut self,
        predicate: &Expr,
    ) -> Result<naga::Handle<Expression>, LoweringError> {
        let predicate = self.emit_bool_expr(predicate)?;
        let result = self
            .function
            .expressions
            .append(Expression::SubgroupBallotResult, Span::UNDEFINED);
        self.function.body.push(
            Statement::SubgroupBallot {
                result,
                predicate: Some(predicate),
            },
            Span::UNDEFINED,
        );
        Ok(self.append_expr(Expression::AccessIndex {
            base: result,
            index: 0,
        }))
    }
    fn emit_subgroup_gather_expr(
        &mut self,
        mode: GatherMode,
        value: &Expr,
    ) -> Result<naga::Handle<Expression>, LoweringError> {
        let ty = self.module.scalar_type(expr_type(value, self)?)?;
        let argument = self.emit_expr(value)?;
        let result = self
            .function
            .expressions
            .append(Expression::SubgroupOperationResult { ty }, Span::UNDEFINED);
        self.function.body.push(
            Statement::SubgroupGather {
                mode,
                argument,
                result,
            },
            Span::UNDEFINED,
        );
        Ok(result)
    }
    fn emit_subgroup_collective_expr(
        &mut self,
        op: SubgroupOperation,
        collective_op: CollectiveOperation,
        value: &Expr,
    ) -> Result<naga::Handle<Expression>, LoweringError> {
        let ty = self.module.scalar_type(expr_type(value, self)?)?;
        let argument = self.emit_expr(value)?;
        let result = self
            .function
            .expressions
            .append(Expression::SubgroupOperationResult { ty }, Span::UNDEFINED);
        self.function.body.push(
            Statement::SubgroupCollectiveOperation {
                op,
                collective_op,
                argument,
                result,
            },
            Span::UNDEFINED,
        );
        Ok(result)
    }
    fn emit_scalar_cast(
        &mut self,
        expr: naga::Handle<Expression>,
        source: &DataType,
        kind: ScalarKind,
        convert: Option<u8>,
    ) -> Result<naga::Handle<Expression>, LoweringError> {
        let casted = if matches!(source, DataType::Bool) && !matches!(kind, ScalarKind::Bool) {
            let one = self.append_expr(Expression::Literal(Literal::U32(1)));
            let zero = self.append_expr(Expression::Literal(Literal::U32(0)));
            self.append_expr(Expression::Select {
                condition: expr,
                accept: one,
                reject: zero,
            })
        } else {
            expr
        };
        Ok(self.append_expr(Expression::As {
            expr: casted,
            kind,
            convert,
        }))
    }
    fn emit_narrow_uint_cast(
        &mut self,
        expr: naga::Handle<Expression>,
        source: &DataType,
        bits: u32,
    ) -> Result<naga::Handle<Expression>, LoweringError> {
        let wide = self.emit_scalar_cast(expr, source, ScalarKind::Uint, Some(4))?;
        let mask = self.append_expr(Expression::Literal(Literal::U32((1u32 << bits) - 1)));
        Ok(self.append_expr(Expression::Binary {
            op: BinaryOperator::And,
            left: wide,
            right: mask,
        }))
    }
    fn emit_narrow_sint_cast(
        &mut self,
        expr: naga::Handle<Expression>,
        source: &DataType,
        bits: u32,
    ) -> Result<naga::Handle<Expression>, LoweringError> {
        let unsigned = self.emit_narrow_uint_cast(expr, source, bits)?;
        let as_signed = self.append_expr(Expression::As {
            expr: unsigned,
            kind: ScalarKind::Sint,
            convert: Some(4),
        });
        let sign_bit = self.append_expr(Expression::Literal(Literal::I32(1 << (bits - 1))));
        let toggled = self.append_expr(Expression::Binary {
            op: BinaryOperator::ExclusiveOr,
            left: as_signed,
            right: sign_bit,
        });
        Ok(self.append_expr(Expression::Binary {
            op: BinaryOperator::Subtract,
            left: toggled,
            right: sign_bit,
        }))
    }
    fn emit_u64_cast(
        &mut self,
        expr: naga::Handle<Expression>,
        source: &DataType,
    ) -> Result<naga::Handle<Expression>, LoweringError> {
        let vec2_ty = self.module.types.vec2_u32_ty;
        let zero = self.append_expr(Expression::Literal(Literal::U32(0)));

        match source {
            DataType::U64 | DataType::Vec2U32 => Ok(expr),
            DataType::Vec4U32 => Ok(self.append_expr(Expression::Swizzle {
                size: VectorSize::Bi,
                vector: expr,
                pattern: [
                    naga::SwizzleComponent::X,
                    naga::SwizzleComponent::Y,
                    naga::SwizzleComponent::X,
                    naga::SwizzleComponent::Y,
                ],
            })),
            DataType::Bool | DataType::U8 | DataType::U16 | DataType::U32 => {
                let low = self.emit_scalar_cast(expr, source, ScalarKind::Uint, Some(4))?;
                Ok(self.append_expr(Expression::Compose {
                    ty: vec2_ty,
                    components: vec![low, zero],
                }))
            }
            DataType::I8 | DataType::I16 | DataType::I32 => {
                let signed = self.emit_scalar_cast(expr, source, ScalarKind::Sint, Some(4))?;
                let signed_zero = self.append_expr(Expression::Literal(Literal::I32(0)));
                let negative = self.append_expr(Expression::Binary {
                    op: BinaryOperator::Less,
                    left: signed,
                    right: signed_zero,
                });
                let all_ones = self.append_expr(Expression::Literal(Literal::U32(u32::MAX)));
                let high = self.append_expr(Expression::Select {
                    condition: negative,
                    accept: all_ones,
                    reject: zero,
                });
                let low = self.append_expr(Expression::As {
                    expr: signed,
                    kind: ScalarKind::Uint,
                    convert: Some(4),
                });
                Ok(self.append_expr(Expression::Compose {
                    ty: vec2_ty,
                    components: vec![low, high],
                }))
            }
            other => Err(LoweringError::invalid(format!(
                "cannot cast `{other:?}` to U64 in wgpu lowering. Fix: cast through Bool, I8/I16/I32, U8/U16/U32, Vec2U32, or Vec4U32 before the U64 boundary."
            ))),
        }
    }
    fn atomic_scalar_type(&self, buffer: &str) -> Result<DataType, LoweringError> {
        self.module
            .buffers
            .get(buffer)
            .map(|binding| binding.decl.element.clone())
            .ok_or_else(|| {
                LoweringError::invalid(format!(
                    "unknown atomic buffer `{buffer}`. Fix: declare it before lowering atomic ops."
                ))
            })
    }
    fn atomic_result_type(
        &self,
        op: &AtomicOp,
        scalar_ty: &DataType,
    ) -> Result<naga::Handle<naga::Type>, LoweringError> {
        Ok(match op {
            AtomicOp::CompareExchange | AtomicOp::CompareExchangeWeak => match scalar_ty {
                DataType::U32 => self.module.types.atomic_compare_exchange_u32_ty,
                DataType::I32 => self.module.types.atomic_compare_exchange_i32_ty,
                other => {
                    return Err(LoweringError::invalid(format!(
                        "atomic compare-exchange on `{other:?}` is invalid. Fix: declare the target buffer as u32 or i32."
                    )));
                }
            },
            _ => match scalar_ty {
                DataType::U32 => self.module.types.u32_ty,
                DataType::I32 => self.module.types.i32_ty,
                other => {
                    return Err(LoweringError::invalid(format!(
                        "atomic op on `{other:?}` is invalid. Fix: declare the target buffer as u32 or i32."
                    )));
                }
            },
        })
    }
    fn emit_atomic_expr(
        &mut self,
        op: &AtomicOp,
        buffer: &str,
        index: &Expr,
        expected: Option<&Expr>,
        value: &Expr,
    ) -> Result<naga::Handle<Expression>, LoweringError> {
        let pointer = self.emit_buffer_pointer(buffer, index)?;
        let scalar_ty = self.atomic_scalar_type(buffer)?;
        let value_handle = self.emit_expr(value)?;
        let naga_op = match op {
            AtomicOp::Add => naga::AtomicFunction::Add,
            AtomicOp::And => naga::AtomicFunction::And,
            AtomicOp::Or => naga::AtomicFunction::InclusiveOr,
            AtomicOp::Xor => naga::AtomicFunction::ExclusiveOr,
            AtomicOp::Min => naga::AtomicFunction::Min,
            AtomicOp::Max | AtomicOp::LruUpdate => naga::AtomicFunction::Max,
            AtomicOp::Exchange => naga::AtomicFunction::Exchange { compare: None },
            AtomicOp::CompareExchange | AtomicOp::CompareExchangeWeak => {
                let expected_expr = expected . ok_or_else (| | { LoweringError :: invalid ("atomic compare-exchange requires an expected value. Fix: provide `expected` for this atomic op." ,) }) ? ;
                let cmp = self.emit_expr(expected_expr)?;
                naga::AtomicFunction::Exchange { compare: Some(cmp) }
            }
            AtomicOp::FetchNand => {
                return Err(LoweringError::invalid(
                    "atomic FetchNand has no Naga/WGSL analog in the current lowering. Fix: lower it through a compare-exchange retry sequence before backend emission.",
                ));
            }
            AtomicOp::Opaque(id) => {
                return emit_registered_atomic_op(*id, self, buffer, index, expected, value);
            }
            _ => return Err(LoweringError::unsupported_op(op)),
        };
        let result = self.function.expressions.append(
            Expression::AtomicResult {
                ty: self.atomic_result_type(op, &scalar_ty)?,
                comparison: matches!(
                    op,
                    AtomicOp::CompareExchange | AtomicOp::CompareExchangeWeak
                ),
            },
            Span::UNDEFINED,
        );
        self.function.body.push(
            Statement::Atomic {
                pointer,
                fun: naga_op,
                value: value_handle,
                result: Some(result),
            },
            Span::UNDEFINED,
        );
        if matches!(
            op,
            AtomicOp::CompareExchange | AtomicOp::CompareExchangeWeak
        ) {
            return Ok(self.append_expr(Expression::AccessIndex {
                base: result,
                index: 0,
            }));
        }
        Ok(result)
    }
    pub(crate) fn emit_expr(
        &mut self,
        expr: &Expr,
    ) -> Result<naga::Handle<Expression>, LoweringError> {
        if let Some(folded) = fold_expr(expr) {
            return self.emit_expr(folded.as_ref());
        }
        let handle = match expr {
            Expr::LitU32(value) => self.append_expr(Expression::Literal(Literal::U32(*value))),
            Expr::LitI32(value) => self.append_expr(Expression::Literal(Literal::I32(*value))),
            Expr::LitF32(value) => self.append_expr(Expression::Literal(Literal::F32(*value))),
            Expr::LitBool(value) => self.append_expr(Expression::Literal(Literal::Bool(*value))),
            Expr::Var(name) => {
                let local = self.locals.get(name.as_str()).copied().ok_or_else(|| {
                    LoweringError::invalid(format!(
                        "unknown local `{name}`. Fix: bind the variable before reading it."
                    ))
                })?;
                let pointer = self.append_expr(Expression::LocalVariable(local));
                self.append_expr(Expression::Load { pointer })
            }
            Expr::InvocationId { axis } => self.emit_builtin_axis(self.gid_arg, *axis)?,
            Expr::WorkgroupId { axis } => self.emit_builtin_axis(self.wgid_arg, *axis)?,
            Expr::LocalId { axis } => self.emit_builtin_axis(self.lid_arg, *axis)?,

            Expr::SubgroupLocalId => {
                let arg = self.sgid_arg.ok_or_else(|| {
                    LoweringError::unsupported_op(
                        "SubgroupLocalId is only supported when subgroup-ops are enabled.",
                    )
                })?;
                self.append_expr(naga::Expression::FunctionArgument(arg))
            }
            Expr::SubgroupSize => {
                let arg = self.sgsize_arg.ok_or_else(|| {
                    LoweringError::unsupported_op(
                        "SubgroupSize is only supported when subgroup-ops are enabled.",
                    )
                })?;
                self.append_expr(naga::Expression::FunctionArgument(arg))
            }

            Expr::Load { buffer, index } => {
                let pointer = self.emit_buffer_pointer(buffer.as_str(), index)?;
                let loaded = self.append_expr(Expression::Load { pointer });
                let buffer_decl = &self
                    .module
                    .buffers
                    .get(buffer.as_str())
                    .ok_or_else(|| {
                        LoweringError::invalid(format!(
                            "unknown buffer `{buffer}`. Fix: declare it before lowering the load."
                        ))
                    })?
                    .decl;
                if matches!(buffer_decl.element, DataType::Bool) {
                    self.emit_bool_from_handle(loaded, &DataType::U32)?
                } else {
                    loaded
                }
            }
            Expr::BufLen { buffer } => {
                let binding = self.module.buffers.get(buffer.as_str()).ok_or_else(|| {
                    LoweringError::invalid(format!(
                        "unknown buffer `{buffer}`. Fix: declare it before lowering `buf_len`."
                    ))
                })?;
                if matches!(
                    binding.decl.kind,
                    vyre_foundation::ir::MemoryKind::Global
                        | vyre_foundation::ir::MemoryKind::Readonly
                ) {
                    let global = self.buffer_global(buffer.as_str())?;
                    let pointer = self.append_expr(Expression::GlobalVariable(global));
                    self.append_expr(Expression::ArrayLength(pointer))
                } else {
                    self.append_expr(Expression::Literal(Literal::U32(binding.decl.count.max(1))))
                }
            }
            Expr::BinOp { op, left, right } => self.emit_binop(op, left, right)?,
            Expr::UnOp { op, operand } => self.emit_unary(op, operand)?,
            Expr::Select {
                cond,
                true_val,
                false_val,
            } => {
                let condition = self.emit_expr(cond)?;
                let accept = self.emit_expr(true_val)?;
                let reject = self.emit_expr(false_val)?;
                self.append_expr(Expression::Select {
                    condition,
                    accept,
                    reject,
                })
            }
            Expr::Cast { target, value } => {
                let expr = self.emit_expr(value)?;
                let source_ty = expr_type(value, self)?;
                match target {
                    DataType::Bool => self.emit_bool_from_handle(expr, &source_ty)?,
                    DataType::U8 => self.emit_narrow_uint_cast(expr, &source_ty, 8)?,
                    DataType::U16 => self.emit_narrow_uint_cast(expr, &source_ty, 16)?,
                    DataType::U32 => {
                        self.emit_scalar_cast(expr, &source_ty, ScalarKind::Uint, Some(4))?
                    }
                    DataType::I8 => self.emit_narrow_sint_cast(expr, &source_ty, 8)?,
                    DataType::I16 => self.emit_narrow_sint_cast(expr, &source_ty, 16)?,
                    DataType::I32 => {
                        self.emit_scalar_cast(expr, &source_ty, ScalarKind::Sint, Some(4))?
                    }
                    DataType::F32 => {
                        self.emit_scalar_cast(expr, &source_ty, ScalarKind::Float, Some(4))?
                    }
                    DataType::Vec2U32 => match source_ty {
                        DataType::Vec2U32 => expr,
                        DataType::Vec4U32 => self.append_expr(Expression::Swizzle {
                            size: VectorSize::Bi,
                            vector: expr,
                            pattern: [
                                naga::SwizzleComponent::X,
                                naga::SwizzleComponent::Y,
                                naga::SwizzleComponent::X,
                                naga::SwizzleComponent::Y,
                            ],
                        }),
                        _ => {
                            let scalar =
                                self.emit_scalar_cast(expr, &source_ty, ScalarKind::Uint, Some(4))?;
                            self.append_expr(Expression::Splat {
                                size: VectorSize::Bi,
                                value: scalar,
                            })
                        }
                    },
                    DataType::Vec4U32 => match source_ty {
                        DataType::Vec4U32 => expr,
                        _ => {
                            let scalar =
                                self.emit_scalar_cast(expr, &source_ty, ScalarKind::Uint, Some(4))?;
                            self.append_expr(Expression::Splat {
                                size: VectorSize::Quad,
                                value: scalar,
                            })
                        }
                    },
                    DataType::U64 => self.emit_u64_cast(expr, &source_ty)?,
                    other => {
                        return Err(LoweringError::unsupported_type(other));
                    }
                }
            }
            Expr::Fma { a, b, c } => {
                let a_ty = expr_type(a, self)?;
                let b_ty = expr_type(b, self)?;
                let c_ty = expr_type(c, self)?;
                if !(matches!(a_ty, DataType::F32)
                    && matches!(b_ty, DataType::F32)
                    && matches!(c_ty, DataType::F32))
                {
                    return Err(LoweringError::invalid(format!(
                        "Fma requires three f32 operands, got ({a_ty:?}, {b_ty:?}, {c_ty:?}). Fix: cast all Fma operands to F32 before lowering."
                    )));
                }
                let arg = self.emit_expr(a)?;
                let arg1 = Some(self.emit_expr(b)?);
                let arg2 = Some(self.emit_expr(c)?);
                self.append_expr(Expression::Math {
                    fun: MathFunction::Fma,
                    arg,
                    arg1,
                    arg2,
                    arg3: None,
                })
            }
            Expr::Call { op_id, .. } => {
                return Err(LoweringError::invalid(format!(
                    "un-inlined call `{op_id}` reached wgpu lowering. Fix: register and inline the callee before Naga emission."
                )));
            }
            Expr::Atomic {
                op,
                buffer,
                index,
                expected,
                value,
            } => {
                return self.emit_atomic_expr(
                    op,
                    buffer.as_str(),
                    index,
                    expected.as_deref(),
                    value,
                );
            }
            Expr::SubgroupBallot { cond } => return self.emit_subgroup_ballot_expr(cond),
            Expr::SubgroupShuffle { value, lane } => {
                let lane_handle = self.emit_expr(lane)?;
                return self.emit_subgroup_gather_expr(GatherMode::Shuffle(lane_handle), value);
            }
            Expr::SubgroupAdd { value } => {
                return self.emit_subgroup_collective_expr(
                    SubgroupOperation::Add,
                    CollectiveOperation::Reduce,
                    value,
                );
            }
            Expr::Opaque(ext) => {
                if let Some(wgpu_ext) = ext.as_any().downcast_ref::<&dyn WgpuEmitExpr>() {
                    return wgpu_ext.wgpu_emit_expr(self);
                }
                // Wide-literal opaque extensions (vyre.literal.{i64,u64,f64})
                // ship in vyre-foundation/src/ir_inner/model/expr/builders/wide_literals.rs.
                // vyre-foundation can't impl the pub(crate) WgpuEmitExpr trait
                // here, so the driver recognises them by extension_kind +
                // 8-byte wire_payload and emits the closest naga literal.
                //
                // naga's Literal in this vyre revision is {Bool, U32, I32,
                // F32, F64, AbstractInt, AbstractFloat} — no native u64/i64.
                // For values that fit the narrow type we emit Literal::U32 /
                // I32 / F64; values that exceed the narrow range are a
                // legitimate WGSL incompatibility and we error fast with the
                // exceeded value, instead of silently truncating.
                let kind = ext.extension_kind();
                if kind == "vyre.literal.u64"
                    || kind == "vyre.literal.i64"
                    || kind == "vyre.literal.f64"
                {
                    let payload = ext.wire_payload();
                    if payload.len() != 8 {
                        return Err(LoweringError::invalid(format!(
                            "wide-literal opaque `{kind}` carries {} payload bytes, expected 8. Fix: encode literals via Expr::u64 / Expr::i64 / Expr::f64 which serialize to little-endian 8-byte payloads.",
                            payload.len()
                        )));
                    }
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&payload);
                    let lit = match kind {
                        "vyre.literal.u64" => {
                            let value = u64::from_le_bytes(bytes);
                            let narrow: u32 = value.try_into().map_err(|_| {
                                LoweringError::invalid(format!(
                                    "u64 literal {value} exceeds u32::MAX. Fix: WGSL has no native u64; either narrow the literal at construction time or split into a vec2<u32> via dedicated builder."
                                ))
                            })?;
                            Literal::U32(narrow)
                        }
                        "vyre.literal.i64" => {
                            let value = i64::from_le_bytes(bytes);
                            let narrow: i32 = value.try_into().map_err(|_| {
                                LoweringError::invalid(format!(
                                    "i64 literal {value} outside i32 range. Fix: WGSL has no native i64; narrow at construction time or split into a vec2<i32>."
                                ))
                            })?;
                            Literal::I32(narrow)
                        }
                        "vyre.literal.f64" => {
                            let value = f64::from_le_bytes(bytes);
                            // naga::Literal::F64 exists; emit it directly.
                            // wgpu adapter must report shader-f64 capability
                            // for this to compile through; the driver caps
                            // probe surfaces that as a clear error already.
                            Literal::F64(value)
                        }
                        _ => unreachable!("kind matched above"),
                    };
                    return Ok(self.append_expr(Expression::Literal(lit)));
                }
                return Err(LoweringError::invalid(format!(
                    "unsupported opaque expression `{}` in wgpu lowering. Fix: implement WgpuEmitExpr for this extension.",
                    kind
                )));
            }
            _ => {
                return Err(LoweringError::invalid(
                    "unsupported future expression variant in wgpu lowering. Fix: add a concrete Naga emission path before this IR variant reaches the backend.",
                ));
            }
        };
        Ok(handle)
    }
    fn emit_unary(
        &mut self,
        op: &UnOp,
        operand: &Expr,
    ) -> Result<naga::Handle<Expression>, LoweringError> {
        let operand_ty = expr_type(operand, self)?;
        let expr = self.emit_expr(operand)?;
        Ok(match op {
            UnOp::Negate => {
                if matches!(operand_ty, DataType::Bool) {
                    return Err(LoweringError::invalid(
                        "UnOp::Negate on Bool is invalid. Fix: cast to a signed scalar first.",
                    ));
                }
                if matches!(operand_ty, DataType::U32) {
                    let as_signed = self.append_expr(Expression::As {
                        expr,
                        kind: ScalarKind::Sint,
                        convert: Some(4),
                    });
                    let negated = self.append_expr(Expression::Unary {
                        op: UnaryOperator::Negate,
                        expr: as_signed,
                    });
                    self.append_expr(Expression::As {
                        expr: negated,
                        kind: ScalarKind::Uint,
                        convert: Some(4),
                    })
                } else {
                    self.append_expr(Expression::Unary {
                        op: UnaryOperator::Negate,
                        expr,
                    })
                }
            }
            UnOp::BitNot => self.append_expr(Expression::Unary {
                op: UnaryOperator::BitwiseNot,
                expr,
            }),
            UnOp::LogicalNot => match operand_ty {
                DataType::Bool => self.append_expr(Expression::Unary {
                    op: UnaryOperator::LogicalNot,
                    expr,
                }),
                DataType::U32 => {
                    let zero = self.append_expr(Expression::Literal(Literal::U32(0)));
                    self.append_expr(Expression::Binary {
                        op: BinaryOperator::Equal,
                        left: expr,
                        right: zero,
                    })
                }
                DataType::I32 => {
                    let zero = self.append_expr(Expression::Literal(Literal::I32(0)));
                    self.append_expr(Expression::Binary {
                        op: BinaryOperator::Equal,
                        left: expr,
                        right: zero,
                    })
                }
                other => {
                    return Err(LoweringError::unsupported_type(&other));
                }
            },
            UnOp::Abs => self.append_expr(Expression::Math {
                fun: MathFunction::Abs,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::Sqrt => self.append_expr(Expression::Math {
                fun: MathFunction::Sqrt,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::InverseSqrt => self.append_expr(Expression::Math {
                fun: MathFunction::InverseSqrt,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::Floor => self.append_expr(Expression::Math {
                fun: MathFunction::Floor,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::Ceil => self.append_expr(Expression::Math {
                fun: MathFunction::Ceil,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::Round => self.append_expr(Expression::Math {
                fun: MathFunction::Round,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::Trunc => self.append_expr(Expression::Math {
                fun: MathFunction::Trunc,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::Sign => self.append_expr(Expression::Math {
                fun: MathFunction::Sign,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::Cos => self.append_expr(Expression::Math {
                fun: MathFunction::Cos,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::Sin => self.append_expr(Expression::Math {
                fun: MathFunction::Sin,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::Popcount => self.append_expr(Expression::Math {
                fun: MathFunction::CountOneBits,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::Clz => {
                if matches!(operand_ty, DataType::U32) {
                    let zero = self.append_expr(Expression::Literal(Literal::U32(0)));
                    let is_zero = self.append_expr(Expression::Binary {
                        op: BinaryOperator::Equal,
                        left: expr,
                        right: zero,
                    });
                    let first = self.append_expr(Expression::Math {
                        fun: MathFunction::FirstLeadingBit,
                        arg: expr,
                        arg1: None,
                        arg2: None,
                        arg3: None,
                    });
                    let thirty_one = self.append_expr(Expression::Literal(Literal::U32(31)));
                    let thirty_two = self.append_expr(Expression::Literal(Literal::U32(32)));
                    let count = self.append_expr(Expression::Binary {
                        op: BinaryOperator::Subtract,
                        left: thirty_one,
                        right: first,
                    });
                    self.append_expr(Expression::Select {
                        condition: is_zero,
                        accept: thirty_two,
                        reject: count,
                    })
                } else {
                    self.append_expr(Expression::Math {
                        fun: MathFunction::CountLeadingZeros,
                        arg: expr,
                        arg1: None,
                        arg2: None,
                        arg3: None,
                    })
                }
            }
            UnOp::Ctz => self.append_expr(Expression::Math {
                fun: MathFunction::CountTrailingZeros,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::ReverseBits => self.append_expr(Expression::Math {
                fun: MathFunction::ReverseBits,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::IsNan => self.append_expr(Expression::Relational {
                fun: naga::RelationalFunction::IsNan,
                argument: expr,
            }),
            UnOp::IsInf => self.append_expr(Expression::Relational {
                fun: naga::RelationalFunction::IsInf,
                argument: expr,
            }),
            UnOp::IsFinite => {
                let is_nan = self.append_expr(Expression::Relational {
                    fun: naga::RelationalFunction::IsNan,
                    argument: expr,
                });
                let is_inf = self.append_expr(Expression::Relational {
                    fun: naga::RelationalFunction::IsInf,
                    argument: expr,
                });
                let either = self.append_expr(Expression::Binary {
                    op: BinaryOperator::LogicalOr,
                    left: is_nan,
                    right: is_inf,
                });
                self.append_expr(Expression::Unary {
                    op: UnaryOperator::LogicalNot,
                    expr: either,
                })
            }
            UnOp::Exp => self.append_expr(Expression::Math {
                fun: MathFunction::Exp,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::Log => self.append_expr(Expression::Math {
                fun: MathFunction::Log,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::Exp2 => self.append_expr(Expression::Math {
                fun: MathFunction::Exp2,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::Log2 => self.append_expr(Expression::Math {
                fun: MathFunction::Log2,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::Tan => self.append_expr(Expression::Math {
                fun: MathFunction::Tan,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::Acos => self.append_expr(Expression::Math {
                fun: MathFunction::Acos,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::Asin => self.append_expr(Expression::Math {
                fun: MathFunction::Asin,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::Atan => self.append_expr(Expression::Math {
                fun: MathFunction::Atan,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::Unpack4Low => {
                if !matches!(operand_ty, DataType::U32) {
                    return Err(LoweringError::invalid(
                        "UnOp::Unpack4Low requires u32 input. Fix: cast or assemble the packed byte into u32 before unpacking.",
                    ));
                }
                let mask = self.append_expr(Expression::Literal(Literal::U32(0x0F)));
                self.append_expr(Expression::Binary {
                    op: BinaryOperator::And,
                    left: expr,
                    right: mask,
                })
            }
            UnOp::Unpack4High => {
                if !matches!(operand_ty, DataType::U32) {
                    return Err(LoweringError::invalid(
                        "UnOp::Unpack4High requires u32 input. Fix: cast or assemble the packed byte into u32 before unpacking.",
                    ));
                }
                let shift = self.append_expr(Expression::Literal(Literal::U32(4)));
                let shifted = self.append_expr(Expression::Binary {
                    op: BinaryOperator::ShiftRight,
                    left: expr,
                    right: shift,
                });
                let mask = self.append_expr(Expression::Literal(Literal::U32(0x0F)));
                self.append_expr(Expression::Binary {
                    op: BinaryOperator::And,
                    left: shifted,
                    right: mask,
                })
            }
            UnOp::Unpack8Low => {
                if !matches!(operand_ty, DataType::U32) {
                    return Err(LoweringError::invalid(
                        "UnOp::Unpack8Low requires u32 input. Fix: cast or assemble the packed byte into u32 before unpacking.",
                    ));
                }
                let mask = self.append_expr(Expression::Literal(Literal::U32(0xFF)));
                self.append_expr(Expression::Binary {
                    op: BinaryOperator::And,
                    left: expr,
                    right: mask,
                })
            }
            UnOp::Unpack8High => {
                if !matches!(operand_ty, DataType::U32) {
                    return Err(LoweringError::invalid(
                        "UnOp::Unpack8High requires u32 input. Fix: cast or assemble the packed byte into u32 before unpacking.",
                    ));
                }
                let shift = self.append_expr(Expression::Literal(Literal::U32(24)));
                let shifted = self.append_expr(Expression::Binary {
                    op: BinaryOperator::ShiftRight,
                    left: expr,
                    right: shift,
                });
                let mask = self.append_expr(Expression::Literal(Literal::U32(0xFF)));
                self.append_expr(Expression::Binary {
                    op: BinaryOperator::And,
                    left: shifted,
                    right: mask,
                })
            }
            UnOp::Opaque(op) => emit_registered_un_op(*op, self, operand)?,
            UnOp::Tanh => self.append_expr(Expression::Math {
                fun: MathFunction::Tanh,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::Sinh => self.append_expr(Expression::Math {
                fun: MathFunction::Sinh,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            UnOp::Cosh => self.append_expr(Expression::Math {
                fun: MathFunction::Cosh,
                arg: expr,
                arg1: None,
                arg2: None,
                arg3: None,
            }),
            other => {
                return Err(LoweringError::unsupported_op(other));
            }
        })
    }
    #[doc = " Emit a binary op, expanding `AbsDiff`, `Min`, `Max` (no direct naga"]
    #[doc = " equivalent) into the proper `Math` variants."]
    fn emit_binop(
        &mut self,
        op: &BinOp,
        left_expr: &Expr,
        right_expr: &Expr,
    ) -> Result<naga::Handle<Expression>, LoweringError> {
        if let Some(folded) = fold_binary_literal(op, left_expr, right_expr) {
            return self.emit_expr(&folded);
        }
        if matches!(
            op,
            BinOp::Shuffle | BinOp::Ballot | BinOp::WaveReduce | BinOp::WaveBroadcast
        ) {
            return match op {
                BinOp::Shuffle => {
                    let lane = self.emit_expr(right_expr)?;
                    self.emit_subgroup_gather_expr(GatherMode::Shuffle(lane), left_expr)
                }
                BinOp::Ballot => self.emit_subgroup_ballot_expr(left_expr),
                BinOp::WaveReduce => self.emit_subgroup_collective_expr(
                    SubgroupOperation::Add,
                    CollectiveOperation::Reduce,
                    left_expr,
                ),
                BinOp::WaveBroadcast => {
                    let lane = self.emit_expr(right_expr)?;
                    self.emit_subgroup_gather_expr(GatherMode::Broadcast(lane), left_expr)
                }
                other => return Err(LoweringError::unsupported_op(other)),
            };
        }
        if let BinOp::Opaque(op) = op {
            return emit_registered_bin_op(*op, self, left_expr, right_expr);
        }
        let left_ty = expr_type(left_expr, self)?;
        let right_ty = expr_type(right_expr, self)?;
        if matches!(left_ty, DataType::U64 | DataType::I64)
            || matches!(right_ty, DataType::U64 | DataType::I64)
        {
            let u64_arith_banned = !matches!(
                op,
                BinOp::BitAnd | BinOp::BitOr | BinOp::BitXor | BinOp::Eq | BinOp::Ne
            );
            if u64_arith_banned {
                return Err(LoweringError::invalid(format!(
                    "BinOp `{op:?}` on a 64-bit integer operand is unsound on the wgpu backend. \
                     Fix: the vec2<u32> emulation pass that propagates carry across U64/I64 \
                     arithmetic has not shipped, so componentwise vector arithmetic would \
                     silently produce incorrect numeric results. Rework the calculation in \
                     U32/I32 pieces, or route through the SPIR-V backend once it gains native \
                     64-bit integer arithmetic. Only bitwise and equality binops are correct \
                     under the current vec2<u32> backing representation."
                )));
            }
        }
        let left = self.emit_expr(left_expr)?;
        let right = self.emit_expr(right_expr)?;
        match op {
            BinOp::Min => Ok(self.append_expr(Expression::Math {
                fun: MathFunction::Min,
                arg: left,
                arg1: Some(right),
                arg2: None,
                arg3: None,
            })),
            BinOp::Max => Ok(self.append_expr(Expression::Math {
                fun: MathFunction::Max,
                arg: left,
                arg1: Some(right),
                arg2: None,
                arg3: None,
            })),
            BinOp::RotateLeft | BinOp::RotateRight => {
                let bits_ty = expr_type(left_expr, self)?;
                let width_bits = rotate_width_bits(&bits_ty)?;
                let bits = self.append_expr(Expression::Literal(Literal::U32(width_bits)));
                let (primary_op, complement_op) = if matches!(op, BinOp::RotateLeft) {
                    (BinaryOperator::ShiftLeft, BinaryOperator::ShiftRight)
                } else {
                    (BinaryOperator::ShiftRight, BinaryOperator::ShiftLeft)
                };
                let mask = self.append_expr(Expression::Literal(Literal::U32(width_bits - 1)));
                let masked_right = self.append_expr(Expression::Binary {
                    op: BinaryOperator::And,
                    left: right,
                    right: mask,
                });
                let complement = self.append_expr(Expression::Binary {
                    op: BinaryOperator::Subtract,
                    left: bits,
                    right: masked_right,
                });
                let primary = self.append_expr(Expression::Binary {
                    op: primary_op,
                    left,
                    right: masked_right,
                });
                let secondary = self.append_expr(Expression::Binary {
                    op: complement_op,
                    left,
                    right: complement,
                });
                Ok(self.append_expr(Expression::Binary {
                    op: BinaryOperator::InclusiveOr,
                    left: primary,
                    right: secondary,
                }))
            }
            BinOp::AbsDiff => {
                let max = self.append_expr(Expression::Math {
                    fun: MathFunction::Max,
                    arg: left,
                    arg1: Some(right),
                    arg2: None,
                    arg3: None,
                });
                let min = self.append_expr(Expression::Math {
                    fun: MathFunction::Min,
                    arg: left,
                    arg1: Some(right),
                    arg2: None,
                    arg3: None,
                });
                Ok(self.append_expr(Expression::Binary {
                    op: BinaryOperator::Subtract,
                    left: max,
                    right: min,
                }))
            }
            BinOp::SaturatingAdd => {
                let u32_max = self.append_expr(Expression::Literal(Literal::U32(u32::MAX)));
                let headroom = self.append_expr(Expression::Binary {
                    op: BinaryOperator::Subtract,
                    left: u32_max,
                    right,
                });
                let clamped_left = self.append_expr(Expression::Math {
                    fun: MathFunction::Min,
                    arg: left,
                    arg1: Some(headroom),
                    arg2: None,
                    arg3: None,
                });
                Ok(self.append_expr(Expression::Binary {
                    op: BinaryOperator::Add,
                    left: clamped_left,
                    right,
                }))
            }
            BinOp::SaturatingSub => {
                let clamped = self.append_expr(Expression::Math {
                    fun: MathFunction::Max,
                    arg: left,
                    arg1: Some(right),
                    arg2: None,
                    arg3: None,
                });
                Ok(self.append_expr(Expression::Binary {
                    op: BinaryOperator::Subtract,
                    left: clamped,
                    right,
                }))
            }
            BinOp::SaturatingMul => {
                let u32_max = self.append_expr(Expression::Literal(Literal::U32(u32::MAX)));
                let zero = self.append_expr(Expression::Literal(Literal::U32(0)));
                let b_is_zero = self.append_expr(Expression::Binary {
                    op: BinaryOperator::Equal,
                    left: right,
                    right: zero,
                });
                let one = self.append_expr(Expression::Literal(Literal::U32(1)));
                let safe_divisor = self.append_expr(Expression::Math {
                    fun: MathFunction::Max,
                    arg: right,
                    arg1: Some(one),
                    arg2: None,
                    arg3: None,
                });
                let threshold = self.append_expr(Expression::Binary {
                    op: BinaryOperator::Divide,
                    left: u32_max,
                    right: safe_divisor,
                });
                let would_overflow = self.append_expr(Expression::Binary {
                    op: BinaryOperator::Greater,
                    left,
                    right: threshold,
                });
                let product = self.append_expr(Expression::Binary {
                    op: BinaryOperator::Multiply,
                    left,
                    right,
                });
                let overflow_select = self.append_expr(Expression::Select {
                    condition: would_overflow,
                    accept: u32_max,
                    reject: product,
                });
                Ok(self.append_expr(Expression::Select {
                    condition: b_is_zero,
                    accept: zero,
                    reject: overflow_select,
                }))
            }
            other => {
                let naga_op = binary_operator(*other)?;
                Ok(self.append_expr(Expression::Binary {
                    op: naga_op,
                    left,
                    right,
                }))
            }
        }
    }
}
fn rotate_width_bits(value_ty: &DataType) -> Result<u32, LoweringError> {
    Ok(match value_ty {
        DataType::U32 | DataType::I32 => 32,
        DataType::U64 | DataType::I64 => {
            return Err(LoweringError::invalid(
                "RotateLeft/RotateRight on U64/I64 is not supported in this lowering path. \
                 Fix: decompose into a U32 pair and rotate each half explicitly, or wait for \
                 the U64 emulation pass.",
            ));
        }
        DataType::U16 | DataType::I16 => 16,
        DataType::U8 | DataType::I8 => 8,
        DataType::Bool => 1,
        DataType::Vec2U32 | DataType::Vec4U32 => {
            return Err(LoweringError::invalid(
                "RotateLeft/RotateRight are scalar-only ops in this lowering path.",
            ));
        }
        _ => {
            return Err(LoweringError::invalid(format!(
                "rotate width is undefined for `{value_ty:?}`; fix by lowering rotate through a supported integer scalar type."
            )));
        }
    })
}
#[doc = " Fold a binary operation on two literal expressions."]
#[doc = ""]
#[doc = " Returns `Some(folded_expr)` when both operands are integer literals of the"]
#[doc = " same type, so the result can be computed on the CPU. This prevents WGSL"]
#[doc = " shader-creation errors where the WGSL constant evaluator rejects overflow"]
#[doc = " in expressions like `2418658927u + 2250928233u` (runtime wrap is valid,"]
#[doc = " but constant-eval overflow is a validation error)."]
fn fold_binary_literal(op: &BinOp, left: &Expr, right: &Expr) -> Option<Expr> {
    match (left, right) {
        (Expr::LitU32(a), Expr::LitU32(b)) => match op {
            BinOp::Add | BinOp::WrappingAdd => Some(Expr::LitU32(a.wrapping_add(*b))),
            BinOp::Sub | BinOp::WrappingSub => Some(Expr::LitU32(a.wrapping_sub(*b))),
            BinOp::Mul => Some(Expr::LitU32(a.wrapping_mul(*b))),
            BinOp::Div => a.checked_div(*b).map(Expr::LitU32),
            BinOp::Mod => a.checked_rem(*b).map(Expr::LitU32),
            BinOp::BitAnd => Some(Expr::LitU32(a & b)),
            BinOp::BitOr => Some(Expr::LitU32(a | b)),
            BinOp::BitXor => Some(Expr::LitU32(a ^ b)),
            BinOp::Shl => Some(Expr::LitU32(a.wrapping_shl(*b % 32))),
            BinOp::Shr => Some(Expr::LitU32(a.wrapping_shr(*b % 32))),
            BinOp::Eq => Some(Expr::LitBool(a == b)),
            BinOp::Ne => Some(Expr::LitBool(a != b)),
            BinOp::Lt => Some(Expr::LitBool(a < b)),
            BinOp::Gt => Some(Expr::LitBool(a > b)),
            BinOp::Le => Some(Expr::LitBool(a <= b)),
            BinOp::Ge => Some(Expr::LitBool(a >= b)),
            BinOp::Min => Some(Expr::LitU32(core::cmp::min(*a, *b))),
            BinOp::Max => Some(Expr::LitU32(core::cmp::max(*a, *b))),
            BinOp::AbsDiff => Some(Expr::LitU32(a.abs_diff(*b))),
            BinOp::SaturatingAdd => Some(Expr::LitU32(a.saturating_add(*b))),
            BinOp::SaturatingSub => Some(Expr::LitU32(a.saturating_sub(*b))),
            BinOp::SaturatingMul => Some(Expr::LitU32(a.saturating_mul(*b))),
            BinOp::RotateLeft => Some(Expr::LitU32(a.rotate_left(*b % 32))),
            BinOp::RotateRight => Some(Expr::LitU32(a.rotate_right(*b % 32))),
            _ => None,
        },
        (Expr::LitI32(a), Expr::LitI32(b)) => match op {
            BinOp::Add => Some(Expr::LitI32(a.wrapping_add(*b))),
            BinOp::Sub => Some(Expr::LitI32(a.wrapping_sub(*b))),
            BinOp::Mul => Some(Expr::LitI32(a.wrapping_mul(*b))),
            BinOp::Div => a.checked_div(*b).map(Expr::LitI32),
            BinOp::Mod => a.checked_rem(*b).map(Expr::LitI32),
            BinOp::BitAnd => Some(Expr::LitI32(a & b)),
            BinOp::BitOr => Some(Expr::LitI32(a | b)),
            BinOp::BitXor => Some(Expr::LitI32(a ^ b)),
            BinOp::Shl => {
                if *b < 0 {
                    None
                } else {
                    Some(Expr::LitI32(a.wrapping_shl((*b as u32) % 32)))
                }
            }
            BinOp::Shr => {
                if *b < 0 {
                    None
                } else {
                    Some(Expr::LitI32(a.wrapping_shr((*b as u32) % 32)))
                }
            }
            BinOp::Eq => Some(Expr::LitBool(a == b)),
            BinOp::Ne => Some(Expr::LitBool(a != b)),
            BinOp::Lt => Some(Expr::LitBool(a < b)),
            BinOp::Gt => Some(Expr::LitBool(a > b)),
            BinOp::Le => Some(Expr::LitBool(a <= b)),
            BinOp::Ge => Some(Expr::LitBool(a >= b)),
            BinOp::Min => Some(Expr::LitI32(core::cmp::min(*a, *b))),
            BinOp::Max => Some(Expr::LitI32(core::cmp::max(*a, *b))),
            BinOp::AbsDiff => None,
            BinOp::SaturatingAdd => Some(Expr::LitI32(a.saturating_add(*b))),
            BinOp::SaturatingSub => Some(Expr::LitI32(a.saturating_sub(*b))),
            BinOp::SaturatingMul => Some(Expr::LitI32(a.saturating_mul(*b))),
            BinOp::RotateLeft => Some(Expr::LitI32(a.rotate_left((*b as u32) % 32))),
            BinOp::RotateRight => Some(Expr::LitI32(a.rotate_right((*b as u32) % 32))),
            _ => None,
        },
        (Expr::LitBool(a), Expr::LitBool(b)) => match op {
            BinOp::And => Some(Expr::LitBool(*a && *b)),
            BinOp::Or => Some(Expr::LitBool(*a || *b)),
            BinOp::Eq => Some(Expr::LitBool(a == b)),
            BinOp::Ne => Some(Expr::LitBool(a != b)),
            _ => None,
        },
        _ => None,
    }
}
#[doc = " Fold a unary operation on a literal expression."]
fn fold_unary_literal(op: &UnOp, operand: &Expr) -> Option<Expr> {
    match operand {
        Expr::LitU32(v) => match op {
            UnOp::Negate => Some(Expr::LitU32(v.wrapping_neg())),
            UnOp::BitNot => Some(Expr::LitU32(!v)),
            UnOp::LogicalNot => Some(Expr::LitBool(*v == 0)),
            UnOp::Popcount => Some(Expr::LitU32(v.count_ones())),
            UnOp::Clz => Some(Expr::LitU32(v.leading_zeros())),
            UnOp::Ctz => Some(Expr::LitU32(v.trailing_zeros())),
            UnOp::ReverseBits => Some(Expr::LitU32(v.reverse_bits())),
            UnOp::Abs => Some(Expr::LitU32(*v)),
            UnOp::Sign => Some(Expr::LitF32(if *v == 0 { 0.0 } else { 1.0 })),
            UnOp::Sqrt => Some(Expr::LitF32((*v as f32).sqrt())),
            UnOp::InverseSqrt => Some(Expr::LitF32(1.0 / (*v as f32).sqrt())),
            UnOp::Exp => Some(Expr::LitF32((*v as f32).exp())),
            UnOp::Exp2 => Some(Expr::LitF32((*v as f32).exp2())),
            UnOp::Log => Some(Expr::LitF32((*v as f32).ln())),
            UnOp::Log2 => Some(Expr::LitF32((*v as f32).log2())),
            UnOp::Sin => Some(Expr::LitF32((*v as f32).sin())),
            UnOp::Cos => Some(Expr::LitF32((*v as f32).cos())),
            UnOp::Tan => Some(Expr::LitF32((*v as f32).tan())),
            UnOp::Asin => Some(Expr::LitF32((*v as f32).asin())),
            UnOp::Acos => Some(Expr::LitF32((*v as f32).acos())),
            UnOp::Atan => Some(Expr::LitF32((*v as f32).atan())),
            UnOp::Sinh => Some(Expr::LitF32((*v as f32).sinh())),
            UnOp::Cosh => Some(Expr::LitF32((*v as f32).cosh())),
            UnOp::Tanh => Some(Expr::LitF32((*v as f32).tanh())),
            UnOp::Floor | UnOp::Ceil | UnOp::Round | UnOp::Trunc => Some(Expr::LitF32(*v as f32)),
            UnOp::IsNan => Some(Expr::LitBool(false)),
            UnOp::IsInf => Some(Expr::LitBool(false)),
            UnOp::IsFinite => Some(Expr::LitBool(true)),
            UnOp::Unpack4Low => Some(Expr::LitU32(v & 0x0F)),
            UnOp::Unpack4High => Some(Expr::LitU32((v >> 4) & 0x0F)),
            UnOp::Unpack8Low => Some(Expr::LitU32(v & 0xFF)),
            UnOp::Unpack8High => Some(Expr::LitU32((v >> 24) & 0xFF)),
            _ => None,
        },
        Expr::LitI32(v) => match op {
            UnOp::Negate => Some(Expr::LitI32(v.wrapping_neg())),
            UnOp::BitNot => Some(Expr::LitI32(!v)),
            UnOp::LogicalNot => Some(Expr::LitBool(*v == 0)),
            UnOp::Popcount => Some(Expr::LitI32(v.count_ones() as i32)),
            UnOp::Clz => Some(Expr::LitI32(v.leading_zeros() as i32)),
            UnOp::Ctz => Some(Expr::LitI32(v.trailing_zeros() as i32)),
            UnOp::ReverseBits => Some(Expr::LitI32(v.reverse_bits())),
            UnOp::Abs => Some(Expr::LitI32(v.wrapping_abs())),
            UnOp::Sign => Some(Expr::LitF32(if *v == 0 { 0.0 } else { v.signum() as f32 })),
            UnOp::Sqrt => Some(Expr::LitF32((*v as f32).sqrt())),
            UnOp::InverseSqrt => Some(Expr::LitF32(1.0 / (*v as f32).sqrt())),
            UnOp::Exp => Some(Expr::LitF32((*v as f32).exp())),
            UnOp::Exp2 => Some(Expr::LitF32((*v as f32).exp2())),
            UnOp::Log => Some(Expr::LitF32((*v as f32).ln())),
            UnOp::Log2 => Some(Expr::LitF32((*v as f32).log2())),
            UnOp::Sin => Some(Expr::LitF32((*v as f32).sin())),
            UnOp::Cos => Some(Expr::LitF32((*v as f32).cos())),
            UnOp::Tan => Some(Expr::LitF32((*v as f32).tan())),
            UnOp::Asin => Some(Expr::LitF32((*v as f32).asin())),
            UnOp::Acos => Some(Expr::LitF32((*v as f32).acos())),
            UnOp::Atan => Some(Expr::LitF32((*v as f32).atan())),
            UnOp::Sinh => Some(Expr::LitF32((*v as f32).sinh())),
            UnOp::Cosh => Some(Expr::LitF32((*v as f32).cosh())),
            UnOp::Tanh => Some(Expr::LitF32((*v as f32).tanh())),
            UnOp::Floor | UnOp::Ceil | UnOp::Round | UnOp::Trunc => Some(Expr::LitF32(*v as f32)),
            UnOp::IsNan => Some(Expr::LitBool(false)),
            UnOp::IsInf => Some(Expr::LitBool(false)),
            UnOp::IsFinite => Some(Expr::LitBool(true)),
            _ => None,
        },
        Expr::LitBool(v) => match op {
            UnOp::LogicalNot => Some(Expr::LitBool(!v)),
            UnOp::BitNot => Some(Expr::LitBool(!v)),
            UnOp::IsNan => Some(Expr::LitBool(false)),
            UnOp::IsInf => Some(Expr::LitBool(false)),
            UnOp::IsFinite => Some(Expr::LitBool(true)),
            _ => None,
        },
        Expr::LitF32(v) => match op {
            UnOp::Negate => Some(Expr::LitF32(-v)),
            UnOp::Sqrt => Some(Expr::LitF32(v.sqrt())),
            UnOp::InverseSqrt => Some(Expr::LitF32(1.0 / v.sqrt())),
            UnOp::Exp => Some(Expr::LitF32(v.exp())),
            UnOp::Exp2 => Some(Expr::LitF32(v.exp2())),
            UnOp::Log => Some(Expr::LitF32(v.ln())),
            UnOp::Log2 => Some(Expr::LitF32(v.log2())),
            UnOp::Sin => Some(Expr::LitF32(v.sin())),
            UnOp::Cos => Some(Expr::LitF32(v.cos())),
            UnOp::Tan => Some(Expr::LitF32(v.tan())),
            UnOp::Asin => Some(Expr::LitF32(v.asin())),
            UnOp::Acos => Some(Expr::LitF32(v.acos())),
            UnOp::Atan => Some(Expr::LitF32(v.atan())),
            UnOp::Sinh => Some(Expr::LitF32(v.sinh())),
            UnOp::Cosh => Some(Expr::LitF32(v.cosh())),
            UnOp::Tanh => Some(Expr::LitF32(v.tanh())),
            UnOp::Ceil => Some(Expr::LitF32(v.ceil())),
            UnOp::Floor => Some(Expr::LitF32(v.floor())),
            UnOp::Round => Some(Expr::LitF32(v.round())),
            UnOp::Trunc => Some(Expr::LitF32(v.trunc())),
            UnOp::Abs => Some(Expr::LitF32(v.abs())),
            UnOp::Sign => Some(Expr::LitF32(if *v == 0.0 { 0.0 } else { v.signum() })),
            UnOp::IsNan => Some(Expr::LitBool(v.is_nan())),
            UnOp::IsInf => Some(Expr::LitBool(v.is_infinite())),
            UnOp::IsFinite => Some(Expr::LitBool(v.is_finite())),
            _ => None,
        },
        _ => None,
    }
}
#[doc = " Fold a cast on a literal expression."]
fn fold_cast_literal(target: &DataType, value: &Expr) -> Option<Expr> {
    match (target, value) {
        (DataType::U32, Expr::LitU32(v)) => Some(Expr::LitU32(*v)),
        (DataType::U32, Expr::LitI32(v)) => Some(Expr::LitU32(*v as u32)),
        (DataType::U32, Expr::LitF32(v)) => Some(Expr::LitU32(*v as u32)),
        (DataType::U32, Expr::LitBool(v)) => Some(Expr::LitU32(if *v { 1 } else { 0 })),
        (DataType::I32, Expr::LitU32(v)) => Some(Expr::LitI32(*v as i32)),
        (DataType::I32, Expr::LitI32(v)) => Some(Expr::LitI32(*v)),
        (DataType::I32, Expr::LitF32(v)) => Some(Expr::LitI32(*v as i32)),
        (DataType::I32, Expr::LitBool(v)) => Some(Expr::LitI32(if *v { 1 } else { 0 })),
        (DataType::F32, Expr::LitU32(v)) => Some(Expr::LitF32(*v as f32)),
        (DataType::F32, Expr::LitI32(v)) => Some(Expr::LitF32(*v as f32)),
        (DataType::F32, Expr::LitF32(v)) => Some(Expr::LitF32(*v)),
        (DataType::F32, Expr::LitBool(v)) => Some(Expr::LitF32(if *v { 1.0 } else { 0.0 })),
        (DataType::Bool, Expr::LitU32(v)) => Some(Expr::LitBool(*v != 0)),
        (DataType::Bool, Expr::LitI32(v)) => Some(Expr::LitBool(*v != 0)),
        (DataType::Bool, Expr::LitF32(v)) => Some(Expr::LitBool(*v != 0.0)),
        (DataType::Bool, Expr::LitBool(v)) => Some(Expr::LitBool(*v)),
        _ => None,
    }
}
#[cfg(test)]
mod tests {
    use super::{rotate_width_bits, DataType};
    #[test]
    fn rotate_width_bits_accepts_u32_and_rejects_u64() {
        assert_eq!(
            rotate_width_bits(&DataType::U32).expect("U32 width must be known."),
            32
        );
        assert!(rotate_width_bits(&DataType::U64).is_err());
        assert!(rotate_width_bits(&DataType::I64).is_err());
    }
}
